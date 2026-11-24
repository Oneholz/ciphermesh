/**
 * CipherMesh Serverless P2P Transport (WebRTC DataChannels via Trystero 0.27+ / Nostr)
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
const HELLO_RESYNC_MS = 10000;

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

function extractPeerId(arg) {
  if (typeof arg === 'string') return arg;
  if (arg && typeof arg === 'object') {
    return arg.peerId || arg.userId || '';
  }
  return '';
}

function wrapAction(actionOrTuple) {
  if (Array.isArray(actionOrTuple)) {
    const [sendFn, receiveFn] = actionOrTuple;
    return {
      send: (data, targetPeerId) => (targetPeerId ? sendFn(data, targetPeerId) : sendFn(data)),
      onMessage: (cb) => receiveFn((data, peerId) => cb(data, extractPeerId(peerId)))
    };
  }
  return {
    send: (data, targetPeerId) =>
      targetPeerId ? actionOrTuple.send(data, { target: targetPeerId }) : actionOrTuple.send(data),
    onMessage: (cb) => {
      if (typeof actionOrTuple.onMessage === 'function') {
        return actionOrTuple.onMessage((data, ctx) => cb(data, extractPeerId(ctx)));
      }
      actionOrTuple.onMessage = (data, ctx) => cb(data, extractPeerId(ctx));
      return () => {};
    }
  };
}

export class P2PNetwork {
  constructor(callbacks) {
    this.callbacks = callbacks;
    this.room = null;
    this.helloAction = null;
    this.pktAction = null;
    this.identity = null;
    this.peerToUser = new Map();
    this.userToPeers = new Map();
    this.rawPeers = new Set();
    this.memorySeenIds = new Set();
    this.rateLimiter = new PeerRateLimiter();
    this.connected = false;
    this.syncTimer = null;
    this.unsubscribers = [];
  }

  async sendSignedHelloTo(peerId = null) {
    if (!this.helloAction || !this.identity) return;
    try {
      const hello = await createSignedHello({
        userId: this.identity.fingerprint,
        ecdhPubJwk: this.identity.ecdhPubJwk,
        ecdsaPubJwk: this.identity.ecdsaPubJwk,
        myEcdsaPrivateKey: this.identity.ecdsaPrivateKey
      });
      await this.helloAction.send(hello, peerId || undefined);
    } catch {
      // ignore transient peer disconnect during handshake
    }
  }

  async connect({ roomId, signalingPassword, identity }) {
    await this.disconnect();
    this.identity = identity;

    let trystero;
    try {
      trystero = await import(TRYSTERO_ESM_URL);
    } catch {
      this.connected = false;
      this.callbacks.onStatusChange(false, 'Офлайн (нет доступа к Trystero CDN)');
      return false;
    }

    try {
      const { joinRoom } = trystero;
      this.room = joinRoom(
        {
          appId: APP_ID,
          password: signalingPassword,
          trickleIce: true
        },
        roomId
      );

      this.helloAction = wrapAction(this.room.makeAction('cm_hello'));
      this.pktAction = wrapAction(this.room.makeAction('cm_pkt'));

      const unsubHello = this.helloAction.onMessage(async (hello, peerId) => {
        if (!peerId || !this.rateLimiter.allow(peerId)) return;
        const valid = await verifySignedHello(hello);
        if (!valid) return;
        if (hello.userId === this.identity.fingerprint) return;

        const isNewBinding = this.peerToUser.get(peerId) !== hello.userId;
        this.peerToUser.set(peerId, hello.userId);
        if (!this.userToPeers.has(hello.userId)) {
          this.userToPeers.set(hello.userId, new Set());
        }
        this.userToPeers.get(hello.userId).add(peerId);

        if (isNewBinding) {
          this.callbacks.onPeerPresence(hello.userId, true);
          this.emitNetworkCount();
          await this.sendSignedHelloTo(peerId);
        }
        await this.flushOutboxForUser(hello.userId);
      });
      if (typeof unsubHello === 'function') this.unsubscribers.push(unsubHello);

      const unsubPkt = this.pktAction.onMessage(async (packet, peerId) => {
        if (!peerId || !this.rateLimiter.allow(peerId)) return;
        await this.handleIncomingPacket(packet, peerId);
      });
      if (typeof unsubPkt === 'function') this.unsubscribers.push(unsubPkt);

      const handlePeerJoin = async (info) => {
        const peerId = extractPeerId(info);
        if (!peerId) return;
        this.rawPeers.add(peerId);
        this.emitNetworkCount();
        await this.sendSignedHelloTo(peerId);
      };

      const handlePeerLeave = (info) => {
        const peerId = extractPeerId(info);
        if (!peerId) return;
        this.rawPeers.delete(peerId);
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
      };

      if (typeof this.room.onPeerJoin === 'function') {
        const u1 = this.room.onPeerJoin(handlePeerJoin);
        if (typeof u1 === 'function') this.unsubscribers.push(u1);
      } else {
        this.room.onPeerJoin = handlePeerJoin;
      }

      if (typeof this.room.onPeerLeave === 'function') {
        const u2 = this.room.onPeerLeave(handlePeerLeave);
        if (typeof u2 === 'function') this.unsubscribers.push(u2);
      } else {
        this.room.onPeerLeave = handlePeerLeave;
      }

      if (typeof this.room.onError === 'function') {
        const u3 = this.room.onError(() => {
          this.emitNetworkCount();
        });
        if (typeof u3 === 'function') this.unsubscribers.push(u3);
      }

      // Replay already connected peers if any
      if (typeof this.room.getPeers === 'function') {
        const existing = Object.keys(this.room.getPeers() || {});
        for (const peerId of existing) {
          handlePeerJoin(peerId);
        }
      }

      // Periodic handshake & outbox resync for reliability across NAT/mobile reconnects
      this.syncTimer = setInterval(async () => {
        if (!this.connected) return;
        if (this.rawPeers.size > 0) {
          await this.sendSignedHelloTo(null);
        }
        for (const userId of this.userToPeers.keys()) {
          await this.flushOutboxForUser(userId);
        }
      }, HELLO_RESYNC_MS);

      this.connected = true;
      this.emitNetworkCount();
      return true;
    } catch {
      this.connected = false;
      this.callbacks.onStatusChange(false, 'Ошибка P2P-инициализации');
      return false;
    }
  }

  emitNetworkCount() {
    if (!this.connected) {
      this.callbacks.onStatusChange(false, 'Офлайн');
      return;
    }
    const verifiedCount = this.userToPeers.size;
    const rawCount = this.rawPeers.size;
    if (verifiedCount > 0) {
      this.callbacks.onStatusChange(true, `P2P активен · контактов: ${verifiedCount}`);
    } else if (rawCount > 0) {
      this.callbacks.onStatusChange(true, `P2P рукопожатие · пиров: ${rawCount}`);
    } else {
      this.callbacks.onStatusChange(true, 'P2P готов · поиск пиров');
    }
  }

  isUserOnline(userId) {
    const peers = this.userToPeers.get(userId);
    return Boolean(peers && peers.size > 0);
  }

  async sendToUser(userId, packet) {
    if (!this.pktAction) return false;
    const peers = this.userToPeers.get(userId);
    if (!peers || peers.size === 0) return false;

    let sentAny = false;
    for (const peerId of peers) {
      try {
        await this.pktAction.send(packet, peerId);
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
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
    for (const unsub of this.unsubscribers) {
      try {
        unsub();
      } catch {
        // ignore unsubscribe error
      }
    }
    this.unsubscribers = [];
    if (this.room) {
      try {
        await this.room.leave();
      } catch {
        // ignore leave error
      }
    }
    this.room = null;
    this.helloAction = null;
    this.pktAction = null;
    this.peerToUser.clear();
    this.userToPeers.clear();
    this.rawPeers.clear();
    this.memorySeenIds.clear();
    this.connected = false;
  }
}
