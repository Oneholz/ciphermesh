/**
 * CipherMesh Safe DOM UI Module
 * Strict Anti-XSS: Uses ONLY textContent and DOM creation APIs (no HTML string injection or dynamic code execution)
 */

let toastTimer = null;

export function clearElement(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

export function createEl(tag, className = '', text = '') {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== '') el.textContent = text;
  return el;
}

export function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach((node) => {
    node.classList.toggle('screen--active', node.id === screenId);
  });
}

export function setNetworkStatus(isOnline, text) {
  const dot = document.getElementById('network-status-dot');
  const label = document.getElementById('network-status-text');
  dot.classList.toggle('status-dot--online', isOnline);
  dot.classList.toggle('status-dot--offline', !isOnline);
  label.textContent = text;
}

export function formatShortTime(ts) {
  if (!ts) return '';
  const date = new Date(ts);
  return date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

export function renderChatList(contacts, isOnlineFn, onSelectChat) {
  const listEl = document.getElementById('chat-list');
  const emptyEl = document.getElementById('chat-list-empty');
  clearElement(listEl);

  if (!contacts.length) {
    emptyEl.classList.remove('hidden');
    return;
  }
  emptyEl.classList.add('hidden');

  for (const contact of contacts) {
    const online = isOnlineFn(contact.id);
    const btn = createEl('button', 'chat-item');
    btn.type = 'button';
    btn.setAttribute('role', 'listitem');
    btn.addEventListener('click', () => onSelectChat(contact.id));

    const avatar = createEl('div', 'chat-avatar', (contact.alias || '?').slice(0, 2).toUpperCase());
    const dot = createEl(
      'span',
      `chat-avatar-dot ${online ? 'status-dot--online' : 'status-dot--offline'}`
    );
    avatar.appendChild(dot);

    const meta = createEl('div', 'chat-meta');
    const rowTop = createEl('div', 'chat-row-top');
    const nameEl = createEl('span', 'chat-name', contact.alias);
    const timeEl = createEl('span', 'chat-time', formatShortTime(contact.lastMessageAt));
    rowTop.append(nameEl, timeEl);

    const rowBottom = createEl('div', 'chat-row-bottom');
    const previewText = contact.lastPreview || (online ? 'В сети · готов к P2P' : 'Офлайн · сообщения уйдут в очередь');
    const previewEl = createEl('span', 'chat-preview', previewText);
    rowBottom.appendChild(previewEl);

    if (contact.unreadCount > 0) {
      const badge = createEl('span', 'unread-badge', String(contact.unreadCount));
      rowBottom.appendChild(badge);
    }

    meta.append(rowTop, rowBottom);
    btn.append(avatar, meta);
    listEl.appendChild(btn);
  }
}

export function renderMessages(messages) {
  const container = document.getElementById('messages-container');
  clearElement(container);

  if (!messages.length) {
    const empty = createEl('div', 'empty-state');
    empty.append(
      createEl('p', 'empty-title', 'Канал защищён E2EE'),
      createEl('p', 'empty-desc', 'Сообщения шифруются AES-256-GCM с общим ключом ECDH и подписываются ECDSA.')
    );
    container.appendChild(empty);
    return;
  }

  for (const msg of messages) {
    const isOut = msg.direction === 'out';
    const row = createEl('div', `msg-row ${isOut ? 'msg-row--out' : 'msg-row--in'}`);
    const bubble = createEl('div', 'msg-bubble', msg.text);

    const meta = createEl('div', 'msg-meta');
    meta.appendChild(createEl('span', '', formatShortTime(msg.timestamp)));

    if (isOut) {
      const isDelivered = msg.status === 'delivered';
      const statusLabel = isDelivered ? 'Доставлено' : 'В очереди';
      const statusClass = isDelivered ? 'msg-status--delivered' : 'msg-status--queued';
      meta.appendChild(createEl('span', statusClass, statusLabel));
    }

    row.append(bubble, meta);
    container.appendChild(row);
  }

  container.scrollTop = container.scrollHeight;
}

export function openModal(title, contentNodes) {
  const backdrop = document.getElementById('modal-backdrop');
  const titleEl = document.getElementById('modal-title');
  const bodyEl = document.getElementById('modal-body');

  titleEl.textContent = title;
  clearElement(bodyEl);
  for (const node of contentNodes) {
    bodyEl.appendChild(node);
  }
  backdrop.classList.remove('hidden');
}

export function closeModal() {
  const backdrop = document.getElementById('modal-backdrop');
  const bodyEl = document.getElementById('modal-body');
  backdrop.classList.add('hidden');
  clearElement(bodyEl);
}

export function showToast(message) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.classList.remove('hidden');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.add('hidden');
  }, 3000);
}
