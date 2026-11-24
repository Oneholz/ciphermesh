/**
 * CipherMesh Local-First IndexedDB Storage Layer
 * Stores: vault (encrypted keys), contacts, messages, outbox, seenIds
 */

const DB_NAME = 'ciphermesh_local_v1';
const DB_VERSION = 1;
const SEEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

let dbInstance = null;

function openDb() {
  if (dbInstance) return Promise.resolve(dbInstance);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains('vault')) {
        db.createObjectStore('vault', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('contacts')) {
        db.createObjectStore('contacts', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('messages')) {
        const msgStore = db.createObjectStore('messages', { keyPath: 'msgId' });
        msgStore.createIndex('by_chat', 'chatId', { unique: false });
      }
      if (!db.objectStoreNames.contains('outbox')) {
        const outStore = db.createObjectStore('outbox', { keyPath: 'msgId' });
        outStore.createIndex('by_recipient', 'recipientId', { unique: false });
      }
      if (!db.objectStoreNames.contains('seenIds')) {
        db.createObjectStore('seenIds', { keyPath: 'msgId' });
      }
    };

    req.onsuccess = () => {
      dbInstance = req.result;
      resolve(dbInstance);
    };

    req.onerror = () => reject(req.error || new Error('IDB_OPEN_FAILED'));
  });
}

function runTx(storeNames, mode, operation) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(storeNames, mode);
        let result;
        tx.oncomplete = () => resolve(result);
        tx.onerror = () => reject(tx.error || new Error('IDB_TX_FAILED'));
        tx.onabort = () => reject(tx.error || new Error('IDB_TX_ABORTED'));
        Promise.resolve(operation(tx))
          .then((res) => {
            result = res;
          })
          .catch((err) => {
            try {
              tx.abort();
            } catch {
              // ignore abort error
            }
            reject(err);
          });
      })
  );
}

function reqToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function getVault() {
  return runTx('vault', 'readonly', (tx) => reqToPromise(tx.objectStore('vault').get('primary')));
}

export async function saveVault(vaultRecord) {
  return runTx('vault', 'readwrite', (tx) =>
    reqToPromise(tx.objectStore('vault').put({ ...vaultRecord, id: 'primary' }))
  );
}

export async function getAllContacts() {
  const list = await runTx('contacts', 'readonly', (tx) =>
    reqToPromise(tx.objectStore('contacts').getAll())
  );
  return list.sort((a, b) => (b.lastMessageAt || b.addedAt || 0) - (a.lastMessageAt || a.addedAt || 0));
}

export async function getContact(contactId) {
  return runTx('contacts', 'readonly', (tx) => reqToPromise(tx.objectStore('contacts').get(contactId)));
}

export async function saveContact(contact) {
  return runTx('contacts', 'readwrite', (tx) => reqToPromise(tx.objectStore('contacts').put(contact)));
}

export async function getMessagesForChat(chatId) {
  const list = await runTx('messages', 'readonly', (tx) => {
    const index = tx.objectStore('messages').index('by_chat');
    return reqToPromise(index.getAll(chatId));
  });
  return list.sort((a, b) => a.timestamp - b.timestamp);
}

export async function saveMessage(message) {
  return runTx('messages', 'readwrite', (tx) => reqToPromise(tx.objectStore('messages').put(message)));
}

export async function updateMessageStatus(msgId, status) {
  return runTx('messages', 'readwrite', async (tx) => {
    const store = tx.objectStore('messages');
    const existing = await reqToPromise(store.get(msgId));
    if (!existing) return false;
    existing.status = status;
    await reqToPromise(store.put(existing));
    return true;
  });
}

export async function deleteMessagesForChat(chatId) {
  return runTx(['messages', 'contacts'], 'readwrite', async (tx) => {
    const msgStore = tx.objectStore('messages');
    const index = msgStore.index('by_chat');
    const keys = await reqToPromise(index.getAllKeys(chatId));
    for (const key of keys) {
      msgStore.delete(key);
    }
    const contactStore = tx.objectStore('contacts');
    const contact = await reqToPromise(contactStore.get(chatId));
    if (contact) {
      contact.lastPreview = '';
      contact.unreadCount = 0;
      contactStore.put(contact);
    }
  });
}

export async function enqueueOutbox(entry) {
  return runTx('outbox', 'readwrite', (tx) => reqToPromise(tx.objectStore('outbox').put(entry)));
}

export async function getOutboxForRecipient(recipientId) {
  const items = await runTx('outbox', 'readonly', (tx) => {
    const index = tx.objectStore('outbox').index('by_recipient');
    return reqToPromise(index.getAll(recipientId));
  });
  return items.sort((a, b) => a.createdAt - b.createdAt);
}

export async function removeOutboxItem(msgId) {
  return runTx('outbox', 'readwrite', (tx) => reqToPromise(tx.objectStore('outbox').delete(msgId)));
}

export async function hasSeenMessageId(msgId) {
  const found = await runTx('seenIds', 'readonly', (tx) => reqToPromise(tx.objectStore('seenIds').get(msgId)));
  return Boolean(found);
}

export async function markMessageIdSeen(msgId) {
  return runTx('seenIds', 'readwrite', (tx) =>
    reqToPromise(tx.objectStore('seenIds').put({ msgId, seenAt: Date.now() }))
  );
}

export async function pruneOldSeenIds() {
  const cutoff = Date.now() - SEEN_TTL_MS;
  return runTx('seenIds', 'readwrite', async (tx) => {
    const store = tx.objectStore('seenIds');
    const all = await reqToPromise(store.getAll());
    for (const item of all) {
      if (item.seenAt < cutoff) {
        store.delete(item.msgId);
      }
    }
  });
}

export async function panicWipeAllData() {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }

  await new Promise((resolve) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => resolve();
    req.onblocked = () => resolve();
  });

  try {
    sessionStorage.clear();
    localStorage.clear();
  } catch {
    // ignore storage errors
  }

  if ('caches' in window) {
    try {
      const names = await caches.keys();
      await Promise.all(names.map((name) => caches.delete(name)));
    } catch {
      // ignore cache errors
    }
  }
}
