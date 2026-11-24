/**
 * CipherMesh Application Controller
 * Manages: Onboarding/Unlock, P2P Lifecycle, Messaging, Outbox, QR Invites, Wipe & Backup
 */

import {
  generateIdentityKeys,
  importPrivateIdentity,
  encryptWithPassword,
  decryptWithPassword,
  deriveRoomCredentials,
  encryptAndSignPacket,
  createSignedControlPacket,
  buildInvitePayload,
  parseInvitePayload
} from './crypto.js';
import {
  getVault,
  saveVault,
  getAllContacts,
  getContact,
  saveContact,
  getMessagesForChat,
  saveMessage,
  updateMessageStatus,
  deleteMessagesForChat,
  enqueueOutbox,
  pruneOldSeenIds,
  panicWipeAllData
} from './db.js';
import { P2PNetwork } from './p2p.js';
import { renderQrToCanvas, isCameraQrSupported, startQrScanner } from './qr.js';
import {
  createEl,
  showScreen,
  setNetworkStatus,
  renderChatList,
  renderMessages,
  openModal,
  closeModal,
  showToast
} from './ui.js';

const state = {
  vault: null,
  identity: null,
  roomCredentials: null,
  activeChatId: null,
  pendingInviteToken: null,
  stopScanner: null
};

const network = new P2PNetwork({
  onStatusChange: (isOnline, label) => {
    setNetworkStatus(isOnline, label);
  },
  onPeerPresence: async (userId) => {
    await refreshChatList();
    if (state.activeChatId === userId) {
      updateDialogHeaderStatus(userId);
    }
  },
  onIncomingMessage: async ({ msgId, senderId, text, timestamp }) => {
    await saveMessage({
      msgId,
      chatId: senderId,
      direction: 'in',
      text,
      timestamp,
      status: 'received'
    });

    const contact = await getContact(senderId);
    if (contact) {
      contact.lastMessageAt = timestamp;
      contact.lastPreview = text.slice(0, 60);
      if (state.activeChatId !== senderId) {
        contact.unreadCount = (contact.unreadCount || 0) + 1;
      }
      await saveContact(contact);
    }

    if (state.activeChatId === senderId) {
      await refreshActiveDialog();
    } else {
      showToast(`Новое сообщение от ${contact ? contact.alias : 'контакта'}`);
    }
    await refreshChatList();
  },
  onDeliveryAck: async (chatId, refMsgId) => {
    const updated = await updateMessageStatus(refMsgId, 'delivered');
    if (updated && state.activeChatId === chatId) {
      await refreshActiveDialog();
    }
  },
  onRemoteWipeChat: async (chatId) => {
    await deleteMessagesForChat(chatId);
    if (state.activeChatId === chatId) {
      await refreshActiveDialog();
    }
    await refreshChatList();
    showToast('Собеседник удалил историю чата у обоих');
  }
});

function captureInviteFromUrl() {
  if (window.location.hash && window.location.hash.startsWith('#invite=')) {
    state.pendingInviteToken = window.location.hash;
    history.replaceState(null, '', window.location.pathname + window.location.search);
  }
}

async function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    try {
      await navigator.serviceWorker.register('./service-worker.js');
    } catch {
      // SW registration may fail on non-HTTPS local file opens
    }
  }
}

async function initAuthScreen() {
  const vault = await getVault();
  state.vault = vault || null;

  const setupForm = document.getElementById('form-setup');
  const unlockForm = document.getElementById('form-unlock');

  if (!vault) {
    setupForm.classList.remove('hidden');
    unlockForm.classList.add('hidden');
  } else {
    setupForm.classList.add('hidden');
    unlockForm.classList.remove('hidden');
    document.getElementById('unlock-profile-hint').textContent =
      `Профиль: ${vault.profileName} · ID: ${vault.fingerprint.slice(0, 12)}`;
  }
  showScreen('screen-auth');
}

async function enterMessenger(decryptedSecretPayload, vaultRecord) {
  const { ecdhPrivateKey, ecdsaPrivateKey } = await importPrivateIdentity(
    decryptedSecretPayload.ecdhPrivJwk,
    decryptedSecretPayload.ecdsaPrivJwk
  );

  state.vault = vaultRecord;
  state.identity = {
    fingerprint: vaultRecord.fingerprint,
    profileName: vaultRecord.profileName,
    ecdhPubJwk: vaultRecord.ecdhPubJwk,
    ecdsaPubJwk: vaultRecord.ecdsaPubJwk,
    ecdhPrivateKey,
    ecdsaPrivateKey
  };
  state.roomCredentials = {
    roomId: decryptedSecretPayload.roomId,
    signalingPassword: decryptedSecretPayload.signalingPassword
  };

  await pruneOldSeenIds();
  showScreen('screen-chats');
  await refreshChatList();

  await network.connect({
    roomId: state.roomCredentials.roomId,
    signalingPassword: state.roomCredentials.signalingPassword,
    identity: state.identity
  });

  if (state.pendingInviteToken) {
    const token = state.pendingInviteToken;
    state.pendingInviteToken = null;
    openAddContactModal(token);
  }
}

async function lockApp() {
  await network.disconnect();
  state.identity = null;
  state.roomCredentials = null;
  state.activeChatId = null;
  document.getElementById('unlock-pin').value = '';
  document.getElementById('unlock-error').classList.add('hidden');
  await initAuthScreen();
}

async function refreshChatList() {
  const contacts = await getAllContacts();
  renderChatList(
    contacts,
    (userId) => network.isUserOnline(userId),
    (chatId) => openDialog(chatId)
  );
}

function updateDialogHeaderStatus(chatId) {
  const statusEl = document.getElementById('dialog-peer-status');
  const online = network.isUserOnline(chatId);
  statusEl.textContent = online ? 'В сети' : 'Офлайн';
}

async function openDialog(chatId) {
  const contact = await getContact(chatId);
  if (!contact) return;

  state.activeChatId = chatId;
  if (contact.unreadCount > 0) {
    contact.unreadCount = 0;
    await saveContact(contact);
    await refreshChatList();
  }

  document.getElementById('dialog-peer-name').textContent = contact.alias;
  updateDialogHeaderStatus(chatId);
  await refreshActiveDialog();
  showScreen('screen-dialog');
}

async function refreshActiveDialog() {
  if (!state.activeChatId) return;
  const messages = await getMessagesForChat(state.activeChatId);
  renderMessages(messages);
}

async function handleSendMessage(event) {
  event.preventDefault();
  if (!state.activeChatId || !state.identity) return;

  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text) return;

  const contact = await getContact(state.activeChatId);
  if (!contact) return;

  input.value = '';
  input.style.height = 'auto';

  const envelope = await encryptAndSignPacket({
    type: 'msg',
    plaintextObj: { text },
    myEcdhPrivateKey: state.identity.ecdhPrivateKey,
    myEcdsaPrivateKey: state.identity.ecdsaPrivateKey,
    peerEcdhPubJwk: contact.ecdhPubJwk,
    senderId: state.identity.fingerprint,
    recipientId: contact.id
  });

  await saveMessage({
    msgId: envelope.msg_id,
    chatId: contact.id,
    direction: 'out',
    text,
    timestamp: envelope.timestamp,
    status: 'queued'
  });

  await enqueueOutbox({
    msgId: envelope.msg_id,
    recipientId: contact.id,
    kind: 'msg',
    envelope,
    createdAt: envelope.timestamp
  });

  contact.lastMessageAt = envelope.timestamp;
  contact.lastPreview = `Вы: ${text.slice(0, 56)}`;
  await saveContact(contact);

  await refreshActiveDialog();
  await refreshChatList();

  if (network.isUserOnline(contact.id)) {
    await network.sendToUser(contact.id, envelope);
  }
}

function openMyQrModal() {
  if (!state.identity) return;

  const token = buildInvitePayload({
    name: state.identity.profileName,
    ecdhPubJwk: state.identity.ecdhPubJwk,
    ecdsaPubJwk: state.identity.ecdsaPubJwk
  });
  const baseUrl = window.location.origin + window.location.pathname;
  const inviteUrl = `${baseUrl}#invite=${token}`;

  const hint = createEl(
    'p',
    'card-hint',
    'Отсканируйте QR-код на телефоне друга или отправьте ему эту одноразовую ссылку-инвайт.'
  );

  const qrFrame = createEl('div', 'qr-frame');
  const canvas = createEl('canvas', 'qr-canvas');
  qrFrame.appendChild(canvas);
  renderQrToCanvas(canvas, inviteUrl, 240);

  const linkArea = createEl('textarea', 'input textarea-code');
  linkArea.readOnly = true;
  linkArea.value = inviteUrl;

  const copyBtn = createEl('button', 'btn btn--primary btn--full', 'Скопировать ссылку-инвайт');
  copyBtn.type = 'button';
  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(inviteUrl);
      showToast('Ссылка-инвайт скопирована');
    } catch {
      linkArea.select();
      showToast('Выделите и скопируйте ссылку вручную');
    }
  });

  openModal('Мой QR и инвайт', [hint, qrFrame, linkArea, copyBtn]);
}

function stopActiveScanner() {
  if (state.stopScanner) {
    state.stopScanner();
    state.stopScanner = null;
  }
}

function openAddContactModal(prefilledToken = '') {
  stopActiveScanner();
  const nodes = [];

  const hint = createEl(
    'p',
    'card-hint',
    'Вставьте ссылку-инвайт друга или отсканируйте его QR-код камерой.'
  );
  nodes.push(hint);

  const input = createEl('textarea', 'input textarea-code');
  input.placeholder = 'https://...#invite=... или токен';
  input.value = prefilledToken;

  const errorEl = createEl('p', 'form-error hidden');

  if (isCameraQrSupported()) {
    const scanBtn = createEl('button', 'btn btn--secondary btn--full', 'Сканировать QR камерой');
    scanBtn.type = 'button';
    const video = createEl('video', 'scanner-video hidden');
    video.setAttribute('playsinline', 'true');

    scanBtn.addEventListener('click', async () => {
      errorEl.classList.add('hidden');
      video.classList.remove('hidden');
      try {
        state.stopScanner = await startQrScanner(video, (rawValue) => {
          input.value = rawValue;
          video.classList.add('hidden');
          showToast('QR-код распознан');
        });
      } catch {
        video.classList.add('hidden');
        errorEl.textContent = 'Не удалось открыть камеру. Вставьте ссылку-инвайт вручную.';
        errorEl.classList.remove('hidden');
      }
    });
    nodes.push(scanBtn, video);
  }

  const addBtn = createEl('button', 'btn btn--primary btn--full', 'Добавить в контакты');
  addBtn.type = 'button';
  addBtn.addEventListener('click', async () => {
    errorEl.classList.add('hidden');
    try {
      const parsed = await parseInvitePayload(input.value);
      if (parsed.id === state.identity.fingerprint) {
        throw new Error('SELF_CONTACT');
      }
      const existing = await getContact(parsed.id);
      await saveContact({
        id: parsed.id,
        alias: parsed.alias,
        ecdhPubJwk: parsed.ecdhPubJwk,
        ecdsaPubJwk: parsed.ecdsaPubJwk,
        addedAt: existing ? existing.addedAt : Date.now(),
        lastMessageAt: existing ? existing.lastMessageAt : 0,
        lastPreview: existing ? existing.lastPreview : '',
        unreadCount: existing ? existing.unreadCount : 0
      });
      stopActiveScanner();
      closeModal();
      await refreshChatList();
      showToast(`Контакт «${parsed.alias}» добавлен`);
    } catch (err) {
      errorEl.textContent =
        err.message === 'SELF_CONTACT'
          ? 'Нельзя добавить собственный профиль.'
          : 'Некорректная ссылка-инвайт или повреждённый ключ.';
      errorEl.classList.remove('hidden');
    }
  });

  nodes.push(input, errorEl, addBtn);
  openModal('Добавить контакт', nodes);
}

function openWipeBothModal() {
  if (!state.activeChatId || !state.identity) return;
  const chatId = state.activeChatId;

  const warn = createEl(
    'p',
    'card-hint',
    'История переписки будет немедленно стерта на вашем устройстве, а собеседнику уйдёт подписанная команда на удаление (если он офлайн — она выполнится сразу при подключении).'
  );

  const confirmBtn = createEl('button', 'btn btn--danger btn--full', 'Удалить чат у обоих');
  confirmBtn.type = 'button';
  confirmBtn.addEventListener('click', async () => {
    const wipePkt = await createSignedControlPacket({
      type: 'wipe_chat',
      senderId: state.identity.fingerprint,
      recipientId: chatId,
      myEcdsaPrivateKey: state.identity.ecdsaPrivateKey
    });

    await enqueueOutbox({
      msgId: wipePkt.msg_id,
      recipientId: chatId,
      kind: 'wipe_chat',
      envelope: wipePkt,
      createdAt: wipePkt.timestamp
    });

    if (network.isUserOnline(chatId)) {
      await network.sendToUser(chatId, wipePkt);
    }

    await deleteMessagesForChat(chatId);
    closeModal();
    await refreshActiveDialog();
    await refreshChatList();
    showToast('Чат очищен, команда удаления отправлена');
  });

  const cancelBtn = createEl('button', 'btn btn--secondary btn--full', 'Отмена');
  cancelBtn.type = 'button';
  cancelBtn.addEventListener('click', closeModal);

  openModal('Удалить чат у обоих', [warn, confirmBtn, cancelBtn]);
}

function openPanicModal() {
  const warn = createEl(
    'p',
    'card-hint',
    'Экстренное стирание полностью уничтожит ключи, контакты, очередь сообщений и кэш приложения на этом устройстве. Восстановление возможно только из резервной копии (.json).'
  );

  const confirmBtn = createEl('button', 'btn btn--danger btn--full', 'Стереть всё немедленно');
  confirmBtn.type = 'button';
  confirmBtn.addEventListener('click', async () => {
    await network.disconnect();
    await panicWipeAllData();
    window.location.reload();
  });

  const cancelBtn = createEl('button', 'btn btn--secondary btn--full', 'Отмена');
  cancelBtn.type = 'button';
  cancelBtn.addEventListener('click', closeModal);

  openModal('Паника: полное стирание', [warn, confirmBtn, cancelBtn]);
}

function openSettingsModal() {
  if (!state.vault || !state.identity) return;

  const idBox = createEl('div', 'info-box');
  idBox.append(
    createEl('span', 'info-box-label', `Профиль: ${state.identity.profileName}`),
    document.createTextNode(`Fingerprint: ${state.identity.fingerprint}`)
  );

  const backupHint = createEl(
    'p',
    'card-hint',
    'Резервная копия сохраняет зашифрованные ключи и список контактов в .json. Приватные ключи остаются зашифрованы вашим паролем.'
  );

  const exportBtn = createEl('button', 'btn btn--secondary btn--full', 'Экспорт резервной копии (.json)');
  exportBtn.type = 'button';
  exportBtn.addEventListener('click', async () => {
    const contacts = await getAllContacts();
    const backup = {
      format: 'ciphermesh-backup-v1',
      exportedAt: Date.now(),
      vault: state.vault,
      contacts: contacts.map((c) => ({
        id: c.id,
        alias: c.alias,
        ecdhPubJwk: c.ecdhPubJwk,
        ecdsaPubJwk: c.ecdsaPubJwk,
        addedAt: c.addedAt
      }))
    };

    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ciphermesh-backup-${state.identity.fingerprint.slice(0, 8)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('Зашифрованная резервная копия сохранена');
  });

  const importBtn = createEl('button', 'btn btn--ghost btn--full', 'Импорт резервной копии (.json)');
  importBtn.type = 'button';
  importBtn.addEventListener('click', () => {
    document.getElementById('file-import-backup').click();
  });

  const panicBtn = createEl('button', 'btn btn--danger btn--full', 'Паника: стереть все данные');
  panicBtn.type = 'button';
  panicBtn.addEventListener('click', () => {
    openPanicModal();
  });

  openModal('Настройки и безопасность', [idBox, backupHint, exportBtn, importBtn, panicBtn]);
}

async function handleBackupFileSelected(event) {
  const file = event.target.files && event.target.files[0];
  event.target.value = '';
  if (!file) return;

  let backup;
  try {
    backup = JSON.parse(await file.text());
    if (!backup || backup.format !== 'ciphermesh-backup-v1' || !backup.vault || !backup.vault.encryptedSecrets) {
      throw new Error('BAD_BACKUP');
    }
  } catch {
    showToast('Неверный формат файла резервной копии');
    return;
  }

  const hint = createEl(
    'p',
    'card-hint',
    `Введите пароль от резервной копии профиля «${backup.vault.profileName}» для проверки и восстановления.`
  );
  const pinInput = createEl('input', 'input');
  pinInput.type = 'password';
  pinInput.placeholder = 'Пароль от резервной копии';

  const errorEl = createEl('p', 'form-error hidden');

  const restoreBtn = createEl('button', 'btn btn--primary btn--full', 'Восстановить аккаунт');
  restoreBtn.type = 'button';
  restoreBtn.addEventListener('click', async () => {
    errorEl.classList.add('hidden');
    try {
      const decrypted = await decryptWithPassword(backup.vault.encryptedSecrets, pinInput.value);
      await saveVault(backup.vault);
      if (Array.isArray(backup.contacts)) {
        for (const c of backup.contacts) {
          if (c && c.id && c.ecdhPubJwk && c.ecdsaPubJwk) {
            await saveContact({
              id: c.id,
              alias: String(c.alias || 'Контакт').slice(0, 32),
              ecdhPubJwk: c.ecdhPubJwk,
              ecdsaPubJwk: c.ecdsaPubJwk,
              addedAt: c.addedAt || Date.now(),
              lastMessageAt: 0,
              lastPreview: '',
              unreadCount: 0
            });
          }
        }
      }
      closeModal();
      showToast('Аккаунт восстановлен из резервной копии');
      await enterMessenger(decrypted, backup.vault);
    } catch {
      errorEl.textContent = 'Неверный пароль или повреждённый бэкап.';
      errorEl.classList.remove('hidden');
    }
  });

  openModal('Импорт резервной копии', [hint, pinInput, errorEl, restoreBtn]);
}

function bindEvents() {
  // Setup submit
  document.getElementById('form-setup').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = document.getElementById('setup-error');
    const submitBtn = document.getElementById('btn-setup-submit');
    errorEl.classList.add('hidden');

    const name = document.getElementById('setup-name').value.trim();
    const roomSecret = document.getElementById('setup-room').value.trim();
    const pin = document.getElementById('setup-pin').value;
    const pinConfirm = document.getElementById('setup-pin-confirm').value;

    if (pin !== pinConfirm) {
      errorEl.textContent = 'Пароли не совпадают.';
      errorEl.classList.remove('hidden');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Генерация ключей P-256...';
    try {
      const keys = await generateIdentityKeys();
      const roomCredentials = await deriveRoomCredentials(roomSecret);

      const secretPayload = {
        ecdhPrivJwk: keys.ecdhPrivJwk,
        ecdsaPrivJwk: keys.ecdsaPrivJwk,
        roomId: roomCredentials.roomId,
        signalingPassword: roomCredentials.signalingPassword
      };

      const encryptedSecrets = await encryptWithPassword(secretPayload, pin);
      const vaultRecord = {
        profileName: name.slice(0, 32),
        fingerprint: keys.fingerprint,
        ecdhPubJwk: keys.ecdhPubJwk,
        ecdsaPubJwk: keys.ecdsaPubJwk,
        encryptedSecrets,
        createdAt: Date.now()
      };

      await saveVault(vaultRecord);
      await enterMessenger(secretPayload, vaultRecord);
    } catch {
      errorEl.textContent = 'Ошибка создания ключей WebCrypto.';
      errorEl.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Создать ключи и войти';
    }
  });

  // Unlock submit
  document.getElementById('form-unlock').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = document.getElementById('unlock-error');
    const submitBtn = document.getElementById('btn-unlock-submit');
    const pin = document.getElementById('unlock-pin').value;
    errorEl.classList.add('hidden');

    submitBtn.disabled = true;
    submitBtn.textContent = 'Расшифровка PBKDF2...';
    try {
      const decrypted = await decryptWithPassword(state.vault.encryptedSecrets, pin);
      document.getElementById('unlock-pin').value = '';
      await enterMessenger(decrypted, state.vault);
    } catch {
      errorEl.textContent = 'Неверный пароль.';
      errorEl.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Расшифровать и подключиться';
    }
  });

  document.getElementById('btn-setup-import').addEventListener('click', () => {
    document.getElementById('file-import-backup').click();
  });
  document.getElementById('btn-unlock-panic').addEventListener('click', openPanicModal);
  document.getElementById('btn-lock-app').addEventListener('click', lockApp);
  document.getElementById('btn-open-settings').addEventListener('click', openSettingsModal);
  document.getElementById('btn-my-qr').addEventListener('click', openMyQrModal);
  document.getElementById('btn-add-contact').addEventListener('click', () => openAddContactModal(''));
  document.getElementById('btn-wipe-both').addEventListener('click', openWipeBothModal);

  document.getElementById('btn-back-chats').addEventListener('click', async () => {
    state.activeChatId = null;
    showScreen('screen-chats');
    await refreshChatList();
  });

  document.getElementById('form-message').addEventListener('submit', handleSendMessage);

  const msgInput = document.getElementById('message-input');
  msgInput.addEventListener('input', () => {
    msgInput.style.height = 'auto';
    msgInput.style.height = `${Math.min(msgInput.scrollHeight, 120)}px`;
  });

  document.getElementById('btn-modal-close').addEventListener('click', () => {
    stopActiveScanner();
    closeModal();
  });
  document.getElementById('modal-backdrop').addEventListener('click', (event) => {
    if (event.target.id === 'modal-backdrop') {
      stopActiveScanner();
      closeModal();
    }
  });

  document.getElementById('file-import-backup').addEventListener('change', handleBackupFileSelected);
}

async function bootstrap() {
  captureInviteFromUrl();
  bindEvents();
  await registerServiceWorker();
  await initAuthScreen();
}

bootstrap();
