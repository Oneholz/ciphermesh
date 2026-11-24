/**
 * CipherMesh Serverless P2P Transport (WebRTC DataChannels via Trystero / Nostr)
 * Includes: Signed peer handshake, Token-Bucket Rate Limiter, Replay Protection, Outbox Auto-Flush
 */

import {
  createSignedHello,
  verifySignedHello,
  verifyPacketSignature,
  decryptVerifiedPacket,
  createSignedControlPacket
} from './crypto.js';
import {
  getContact,
  getOutboxForRecipient,
  removeOutboxItem,
  hasSeenMessageId,
  markMessageIdSeen
} from './db.js';

const TRYSTERO_ESM_URL = 'https://esm.run/trystero';
const APP_ID = 'ciphermesh.local.p2p.v1';
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const RATE_LIMIT_CAPACITY = 25;
const RATE_LIMIT_REFILL_PER_SEC = 6;

class PeerRateLimiter {
  constructor(capacity = RATE_LIMIT_CAPACITY, refillPerSec = RATE_LIMIT_REFILL_PER_SEC) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.buckets = new Map();
  }

  allow(peerId) {
    const now = Date.now();
    let bucket = this.buckets.get(peerId);
    if (!bucket) {
      bucket = { tokens: this.capacity, lastRefill: now };
      this.buckets.set(peerId, bucket);
    }
    const elapsedSec = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedSec * this.refillPerSec);
    bucket.lastRefill = now;

    if (bucket.tokens < 1) {
      return false;
    }
    bucket.tokens -= 1;
    return true;
  }

  remove(peerId) {
    this.buckets.delete(peerId);
  }
}

export class P2PNetwork {
  constructor(callbacks) {
    this.callbacks = callbacks;
    this.room = null;
    this.sendHello = null;
    this.sendPacket = null;
    this.identity = null;
    this.peerToUser = new Map();
    this.userToPeers = new Map();
    this.memorySeenIds = new Set();
    this.rateLimiter = new PeerRateLimiter();
    this.connected = false;
  }

  async connect({ roomId, signalingPassword, identity }) {
    await this.disconnect();
    this.identity = identity;

    let trystero;
    try {
      trystero = await import(TRYSTERO_ESM_URL);
    } catch {
      this.connected = false;
      this.callbacks.onStatusChange(false, 'Офлайн (нет доступа к релеям)');
      return false;
    }

    const { joinRoom } = trystero;
    this.room = joinRoom(
      {
        appId: APP_ID,
        password: signalingPassword,
        trickleIce: true
      },
      roomId
    );

    const [sendHello, getHello] = this.room.makeAction('cm_hello');
    const [sendPacket, getPacket] = this.room.makeAction('cm_pkt');
    this.sendHello = sendHello;
    this.sendPacket = sendPacket;

    this.room.onPeerJoin(async (peerId) => {
      try {
        const hello = await createSignedHello({
          userId: this.identity.fingerprint,
          ecdhPubJwk: this.identity.ecdhPubJwk,
          ecdsaPubJwk: this.identity.ecdsaPubJwk,
          myEcdsaPrivateKey: this.identity.ecdsaPrivateKey
        });
        this.sendHello(hello, peerId);
      } catch {
        // ignore transient peer disconnect during handshake
      }
    });

    this.room.onPeerLeave((peerId) => {
      this.rateLimiter.remove(peerId);
      const userId = this.peerToUser.get(peerId);
      this.peerToUser.delete(peerId);
      if (userId) {
        const set = this.userToPeers.get(userId);
        if (set) {
          set.delete(peerId);
          if (set.size === 0) {
            this.userToPeers.delete(userId);
            this.callbacks.onPeerPresence(userId, false);
          }
        }
      }
      this.emitNetworkCount();
    });

    getHello(async (hello, peerId) => {
      if (!this.rateLimiter.allow(peerId)) return;
      const valid = await verifySignedHello(hello);
      if (!valid) return;
      if (hello.userId === this.identity.fingerprint) return;

      this.peerToUser.set(peerId, hello.userId);
      if (!this.userToPeers.has(hello.userId)) {
        this.userToPeers.set(hello.userId, new Set());
      }
      this.userToPeers.get(hello.userId).add(peerId);

      this.callbacks.onPeerPresence(hello.userId, true);
      this.emitNetworkCount();
      await this.flushOutboxForUser(hello.userId);
    });

    getPacket(async (packet, peerId) => {
      if (!this.rateLimiter.allow(peerId)) return;
      await this.handleIncomingPacket(packet, peerId);
    });

    this.connected = true;
    this.emitNetworkCount();
    return true;
  }

  emitNetworkCount() {
    if (!this.connected) {
      this.callbacks.onStatusChange(false, 'Офлайн');
      return;
    }
    const onlineCount = this.userToPeers.size;
    const label = onlineCount > 0 ? `P2P активен · пиров: ${onlineCount}` : 'P2P готов · поиск пиров';
    this.callbacks.onStatusChange(true, label);
  }

  isUserOnline(userId) {
    const peers = this.userToPeers.get(userId);
    return Boolean(peers && peers.size > 0);
  }

  async sendToUser(userId, packet) {
    if (!this.sendPacket) return false;
    const peers = this.userToPeers.get(userId);
    if (!peers || peers.size === 0) return false;

    let sentAny = false;
    for (const peerId of peers) {
      try {
        await this.sendPacket(packet, peerId);
        sentAny = true;
      } catch {
        // peer channel may have closed; keep queued in outbox until ACK arrives
      }
    }
    return sentAny;
  }

  async flushOutboxForUser(userId) {
    if (!this.isUserOnline(userId)) return;
    const queued = await getOutboxForRecipient(userId);
    for (const item of queued) {
      await this.sendToUser(userId, item.envelope);
    }
  }

  async handleIncomingPacket(packet, peerId) {
    if (!packet || typeof packet !== 'object' || typeof packet.msg_id !== 'string') return;
    if (packet.recipient_id !== this.identity.fingerprint) return;

    // Anti-replay timestamp & duplicate ID check
    if (typeof packet.timestamp !== 'number' || packet.timestamp > Date.now() + MAX_FUTURE_SKEW_MS) {
      return;
    }
    if (this.memorySeenIds.has(packet.msg_id)) return;
    if (await hasSeenMessageId(packet.msg_id)) {
      this.memorySeenIds.add(packet.msg_id);
      return;
    }

    // Bind sender_id to authenticated contact
    const boundUserId = this.peerToUser.get(peerId);
    if (boundUserId && boundUserId !== packet.sender_id) return;

    const contact = await getContact(packet.sender_id);
    if (!contact) return;

    // Verify ECDSA signature BEFORE decrypting or modifying local state
    const signatureOk = await verifyPacketSignature(packet, contact.ecdsaPubJwk);
    if (!signatureOk) return;

    this.memorySeenIds.add(packet.msg_id);
    await markMessageIdSeen(packet.msg_id);

    if (packet.type === 'msg') {
      try {
        const decrypted = await decryptVerifiedPacket({
          packet,
          myEcdhPrivateKey: this.identity.ecdhPrivateKey,
          peerEcdhPubJwk: contact.ecdhPubJwk
        });

        if (!decrypted || typeof decrypted.text !== 'string') return;

        await this.callbacks.onIncomingMessage({
          msgId: packet.msg_id,
          senderId: contact.id,
          text: decrypted.text.slice(0, 4000),
          timestamp: packet.timestamp
        });

        // Send signed delivery ACK back to sender
        const ack = await createSignedControlPacket({
          type: 'ack',
          senderId: this.identity.fingerprint,
          recipientId: contact.id,
          refId: packet.msg_id,
          myEcdsaPrivateKey: this.identity.ecdsaPrivateKey
        });
        await this.sendToUser(contact.id, ack);
      } catch {
        // Decryption failed (corrupted or mismatched key)
      }
      return;
    }

    if (packet.type === 'ack' && typeof packet.ref_id === 'string') {
      await removeOutboxItem(packet.ref_id);
      await this.callbacks.onDeliveryAck(contact.id, packet.ref_id);
      return;
    }

    if (packet.type === 'wipe_chat') {
      await this.callbacks.onRemoteWipeChat(contact.id);
      const ack = await createSignedControlPacket({
        type: 'ack',
        senderId: this.identity.fingerprint,
        recipientId: contact.id,
        refId: packet.msg_id,
        myEcdsaPrivateKey: this.identity.ecdsaPrivateKey
      });
      await this.sendToUser(contact.id, ack);
    }
  }

  async disconnect() {
    if (this.room) {
      try {
        await this.room.leave();
      } catch {
        // ignore leave error
      }
    }
    this.room = null;
    this.sendHello = null;
    this.sendPacket = null;
    this.peerToUser.clear();
    this.userToPeers.clear();
    this.memorySeenIds.clear();
    this.connected = false;
  }
}
