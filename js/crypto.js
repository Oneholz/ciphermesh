/**
 * CipherMesh Web Crypto API Module (Zero-Knowledge E2EE)
 * Algorithms: ECDH (P-256), ECDSA (P-256 / SHA-256), PBKDF2 (SHA-256, 150000 iter), AES-256-GCM
 */

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

export const PBKDF2_ITERATIONS = 150000;
export const AES_IV_BYTES = 12;
export const SALT_BYTES = 16;

export function bytesToBase64Url(bytes) {
  let binary = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let hex = '';
  for (let i = 0; i < arr.length; i++) {
    hex += arr[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export async function sha256Hex(input) {
  const data = typeof input === 'string' ? TEXT_ENCODER.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

export async function computeFingerprint(ecdhPubJwk, ecdsaPubJwk) {
  const canonical = JSON.stringify({
    dh: { crv: ecdhPubJwk.crv, kty: ecdhPubJwk.kty, x: ecdhPubJwk.x, y: ecdhPubJwk.y },
    ds: { crv: ecdsaPubJwk.crv, kty: ecdsaPubJwk.kty, x: ecdsaPubJwk.x, y: ecdsaPubJwk.y }
  });
  const fullHash = await sha256Hex(canonical);
  return fullHash.slice(0, 32);
}

export async function deriveRoomCredentials(roomSecret) {
  const normalized = roomSecret.trim();
  const roomId = (await sha256Hex(`ciphermesh:room:v1:${normalized}`)).slice(0, 40);
  const signalingPassword = await sha256Hex(`ciphermesh:signal:v1:${normalized}`);
  return { roomId, signalingPassword };
}

export async function generateIdentityKeys() {
  const ecdhPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const ecdsaPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const [ecdhPubJwk, ecdhPrivJwk, ecdsaPubJwk, ecdsaPrivJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', ecdhPair.publicKey),
    crypto.subtle.exportKey('jwk', ecdhPair.privateKey),
    crypto.subtle.exportKey('jwk', ecdsaPair.publicKey),
    crypto.subtle.exportKey('jwk', ecdsaPair.privateKey)
  ]);

  const fingerprint = await computeFingerprint(ecdhPubJwk, ecdsaPubJwk);

  return {
    fingerprint,
    ecdhPrivateKey: ecdhPair.privateKey,
    ecdsaPrivateKey: ecdsaPair.privateKey,
    ecdhPubJwk,
    ecdsaPubJwk,
    ecdhPrivJwk,
    ecdsaPrivJwk
  };
}

export async function importPrivateIdentity(ecdhPrivJwk, ecdsaPrivJwk) {
  const [ecdhPrivateKey, ecdsaPrivateKey] = await Promise.all([
    crypto.subtle.importKey(
      'jwk',
      ecdhPrivJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey', 'deriveBits']
    ),
    crypto.subtle.importKey(
      'jwk',
      ecdsaPrivJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    )
  ]);
  return { ecdhPrivateKey, ecdsaPrivateKey };
}

export async function derivePasswordKey(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    TEXT_ENCODER.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptWithPassword(dataObj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_BYTES));
  const key = await derivePasswordKey(password, salt);
  const encoded = TEXT_ENCODER.encode(JSON.stringify(dataObj));

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64Url(salt),
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(cipherBuffer))
  };
}

export async function decryptWithPassword(encryptedBlob, password) {
  if (!encryptedBlob || !encryptedBlob.salt || !encryptedBlob.iv || !encryptedBlob.ciphertext) {
    throw new Error('INVALID_VAULT_FORMAT');
  }
  const salt = base64UrlToBytes(encryptedBlob.salt);
  const iv = base64UrlToBytes(encryptedBlob.iv);
  const ciphertext = base64UrlToBytes(encryptedBlob.ciphertext);
  const key = await derivePasswordKey(password, salt);

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return JSON.parse(TEXT_DECODER.decode(plainBuffer));
}

export async function deriveSharedAesKey(myEcdhPrivateKey, peerEcdhPubJwk) {
  const peerPublicKey = await crypto.subtle.importKey(
    'jwk',
    peerEcdhPubJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPublicKey },
    myEcdhPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function buildCanonicalEnvelope(packet) {
  return JSON.stringify({
    v: packet.v,
    type: packet.type,
    msg_id: packet.msg_id,
    sender_id: packet.sender_id,
    recipient_id: packet.recipient_id,
    timestamp: packet.timestamp,
    iv: packet.iv || '',
    ciphertext: packet.ciphertext || '',
    ref_id: packet.ref_id || ''
  });
}

export async function signData(text, myEcdsaPrivateKey) {
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    myEcdsaPrivateKey,
    TEXT_ENCODER.encode(text)
  );
  return bytesToBase64Url(new Uint8Array(sigBuf));
}

export async function verifyDataSignature(text, signatureB64, peerEcdsaPubJwk) {
  try {
    const peerVerifyKey = await crypto.subtle.importKey(
      'jwk',
      peerEcdsaPubJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const sigBytes = base64UrlToBytes(signatureB64);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      peerVerifyKey,
      sigBytes,
      TEXT_ENCODER.encode(text)
    );
  } catch {
    return false;
  }
}

export async function encryptAndSignPacket({
  type,
  plaintextObj,
  myEcdhPrivateKey,
  myEcdsaPrivateKey,
  peerEcdhPubJwk,
  senderId,
  recipientId
}) {
  const sharedKey = await deriveSharedAesKey(myEcdhPrivateKey, peerEcdhPubJwk);
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_BYTES));
  const encoded = TEXT_ENCODER.encode(JSON.stringify(plaintextObj));

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    encoded
  );

  const packet = {
    v: 1,
    type,
    msg_id: crypto.randomUUID(),
    sender_id: senderId,
    recipient_id: recipientId,
    timestamp: Date.now(),
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(cipherBuffer)),
    ref_id: ''
  };

  packet.signature = await signData(buildCanonicalEnvelope(packet), myEcdsaPrivateKey);
  return packet;
}

export async function createSignedControlPacket({
  type,
  senderId,
  recipientId,
  refId = '',
  myEcdsaPrivateKey
}) {
  const packet = {
    v: 1,
    type,
    msg_id: crypto.randomUUID(),
    sender_id: senderId,
    recipient_id: recipientId,
    timestamp: Date.now(),
    iv: '',
    ciphertext: '',
    ref_id: refId
  };

  packet.signature = await signData(buildCanonicalEnvelope(packet), myEcdsaPrivateKey);
  return packet;
}

export async function verifyPacketSignature(packet, peerEcdsaPubJwk) {
  if (!packet || typeof packet.signature !== 'string') return false;
  return verifyDataSignature(buildCanonicalEnvelope(packet), packet.signature, peerEcdsaPubJwk);
}

export async function decryptVerifiedPacket({ packet, myEcdhPrivateKey, peerEcdhPubJwk }) {
  const sharedKey = await deriveSharedAesKey(myEcdhPrivateKey, peerEcdhPubJwk);
  const iv = base64UrlToBytes(packet.iv);
  const ciphertext = base64UrlToBytes(packet.ciphertext);
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    ciphertext
  );
  return JSON.parse(TEXT_DECODER.decode(plainBuf));
}

export async function createSignedHello({ userId, ecdhPubJwk, ecdsaPubJwk, myEcdsaPrivateKey }) {
  const nonce = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(12)));
  const timestamp = Date.now();
  const payload = { userId, nonce, timestamp };
  const signature = await signData(JSON.stringify(payload), myEcdsaPrivateKey);
  return {
    ...payload,
    dh: { x: ecdhPubJwk.x, y: ecdhPubJwk.y },
    ds: { x: ecdsaPubJwk.x, y: ecdsaPubJwk.y },
    signature
  };
}

export async function verifySignedHello(hello) {
  if (!hello || !hello.userId || !hello.dh || !hello.ds || !hello.signature) return false;
  if (typeof hello.timestamp !== 'number' || Math.abs(Date.now() - hello.timestamp) > 300000) {
    return false;
  }
  const ecdhPubJwk = { kty: 'EC', crv: 'P-256', x: hello.dh.x, y: hello.dh.y, ext: true };
  const ecdsaPubJwk = { kty: 'EC', crv: 'P-256', x: hello.ds.x, y: hello.ds.y, ext: true };
  const expectedId = await computeFingerprint(ecdhPubJwk, ecdsaPubJwk);
  if (expectedId !== hello.userId) return false;
  const payload = { userId: hello.userId, nonce: hello.nonce, timestamp: hello.timestamp };
  return verifyDataSignature(JSON.stringify(payload), hello.signature, ecdsaPubJwk);
}

export function buildInvitePayload({ name, ecdhPubJwk, ecdsaPubJwk }) {
  const compact = {
    v: 1,
    n: name.slice(0, 32),
    dx: ecdhPubJwk.x,
    dy: ecdhPubJwk.y,
    sx: ecdsaPubJwk.x,
    sy: ecdsaPubJwk.y,
    t: Date.now(),
    r: bytesToBase64Url(crypto.getRandomValues(new Uint8Array(6)))
  };
  return bytesToBase64Url(TEXT_ENCODER.encode(JSON.stringify(compact)));
}

export async function parseInvitePayload(rawInput) {
  let token = rawInput.trim();
  const hashIndex = token.indexOf('#invite=');
  if (hashIndex !== -1) {
    token = token.slice(hashIndex + '#invite='.length).trim();
  }
  const parsed = JSON.parse(TEXT_DECODER.decode(base64UrlToBytes(token)));
  if (!parsed || parsed.v !== 1 || !parsed.dx || !parsed.dy || !parsed.sx || !parsed.sy) {
    throw new Error('INVALID_INVITE');
  }
  const ecdhPubJwk = { kty: 'EC', crv: 'P-256', x: parsed.dx, y: parsed.dy, ext: true };
  const ecdsaPubJwk = { kty: 'EC', crv: 'P-256', x: parsed.sx, y: parsed.sy, ext: true };
  const fingerprint = await computeFingerprint(ecdhPubJwk, ecdsaPubJwk);
  return {
    id: fingerprint,
    alias: String(parsed.n || 'Контакт').slice(0, 32),
    ecdhPubJwk,
    ecdsaPubJwk,
    createdAt: parsed.t || Date.now()
  };
}
