
'use strict';

const $ = id => document.getElementById(id);

const state = {
  user: null,
  chatId: null,
  busy: false,
  imageMode: false,
  register: false,
  chats: []
};

const messagesEl = $('messages');
const chatArea = $('chatArea');
const promptEl = $('prompt');
const statusEl = $('status');

if (window.marked) {
  marked.setOptions({ gfm: true, breaks: true });
}

function renderMarkdown(text) {
  const source = String(text ?? '');

  if (window.marked && window.DOMPurify) {
    return DOMPurify.sanitize(marked.parse(source), {
      USE_PROFILES: { html: false }
    });
  }

  const div = document.createElement('div');
  div.textContent = source;
  return div.innerHTML.replace(/\n/g, '<br>');
}

function showStatus(text = '', error = false) {
  statusEl.textContent = text;
  statusEl.classList.toggle('show', Boolean(text));
  statusEl.classList.toggle('error', Boolean(error));
}

function scrollToBottom() {
  requestAnimationFrame(() => {
    chatArea.scrollTop = chatArea.scrollHeight;
  });
}

function addMessage(role, content, image = null, options = {}) {
  const row = document.createElement('div');
  row.className = `message ${role}`;

  if (role === 'assistant') {
    const mark = document.createElement('div');
    mark.className = 'message-mark';
    mark.textContent = 'L';
    row.appendChild(mark);
  }

  const bubble = document.createElement('div');
  bubble.className = 'bubble';

  if (role === 'assistant' && !options.loading) {
    bubble.innerHTML = renderMarkdown(content);
  } else {
    bubble.textContent = content || '';
  }

  if (image) {
    const img = document.createElement('img');
    img.className = 'message-image';
    img.src = image;
    img.alt = 'Созданное изображение';
    img.loading = 'lazy';
    bubble.appendChild(img);
  }

  row.appendChild(bubble);
  messagesEl.appendChild(row);

  scrollToBottom();

  return { row, bubble };
}

function resetView() {
  messagesEl.replaceChildren();
  $('welcome').classList.remove('hidden');
  state.chatId = null;
  showStatus('');
  scrollToBottom();
}

function setBusy(value) {
  state.busy = value;

  $('send').disabled = value;
  $('send').textContent = value ? '…' : '↑';

  promptEl.disabled = value;
  $('imageMode').disabled = value;
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {})
    }
  });

  let data;

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(data.error || `Ошибка сервера (${response.status})`);
  }

  return data;
}

async function loadMe() {
  try {
    const data = await api('/api/auth/me');

    state.user = data.user;

    updateProfile();

    if (state.user) {
      await loadChats();
      await refreshRank();
    }
  } catch (err) {
    console.warn('Проверка аккаунта:', err.message);
  }
}

function updateProfile() {
  const loggedIn = Boolean(state.user);

  $('profile').classList.toggle('hidden', !loggedIn);
  $('authSide').classList.toggle('hidden', loggedIn);
  $('loginTop').classList.toggle('hidden', loggedIn);
  $('accountTools').classList.toggle('hidden', !loggedIn);

  if (loggedIn) {
    const name =
      state.user.name ||
      state.user.username ||
      'Пользователь';

    const rank = ['FREE', 'PLUS', 'MODER', 'ADMIN'].includes(state.user.rank)
      ? state.user.rank
      : 'FREE';

    $('profileName').textContent = name;
    $('profileEmail').textContent =
      state.user.email || state.user.username || '';

    $('avatar').textContent = [...name][0]?.toUpperCase() || 'M';

    $('rankBadge').textContent = rank;
    $('rankBadge').dataset.rank = rank;

    $('adminOpen').classList.toggle(
      'hidden',
      !['ADMIN', 'MODER'].includes(rank)
    );

    $('adminOpen').textContent = 'Панель управления';

    $('adminCodes').classList.toggle('hidden', rank !== 'ADMIN');

    $('adminTitle').textContent =
      rank === 'MODER'
        ? 'Панель модератора'
        : 'Панель администратора';

    $('adminSubtitle').textContent =
      rank === 'MODER'
        ? 'Управление пользователями'
        : 'Управление рангами Maut AI';
  }
}

async function loadChats() {
  if (!state.user) return;

  try {
    const data = await api('/api/chats');

    state.chats = data.chats || [];

    const history = $('history');
    history.replaceChildren();

    if (!state.chats.length) {
      const empty = document.createElement('div');
      empty.className = 'small muted';
      empty.textContent = 'Пока нет чатов';
      history.appendChild(empty);
      return;
    }

    for (const chat of state.chats) {
      const button = document.createElement('button');

      button.className =
        'history-item' +
        (Number(chat.id) === Number(state.chatId) ? ' active' : '');

      button.textContent = chat.title || 'Новый чат';
      button.title = chat.title || 'Новый чат';

      button.addEventListener('click', () => openChat(chat.id));

      history.appendChild(button);
    }
  } catch (err) {
    console.warn('Загрузка истории:', err.message);
  }
}

async function createChat() {
  if (!state.user) return null;

  const data = await api('/api/chats', {
    method: 'POST',
    body: JSON.stringify({})
  });

  state.chatId = data.chat.id;

  await loadChats();

  return state.chatId;
}

async function openChat(id) {
  try {
    showStatus('Загружаю чат…');

    const data = await api(
      `/api/chats/${encodeURIComponent(id)}`
    );

    state.chatId = data.chat.id;

    messagesEl.replaceChildren();

    $('welcome').classList.add('hidden');

    for (const message of data.messages || []) {
      addMessage(
        message.role,
        message.content,
        message.image
      );
    }

    showStatus('');

    await loadChats();

    $('sidebar').classList.remove('open');

    scrollToBottom();
  } catch (err) {
    showStatus(err.message, true);
  }
}

async function saveMessage(role, content, image = null) {
  if (!state.user || !state.chatId) return;

  await api(
    `/api/chats/${encodeURIComponent(state.chatId)}/messages`,
    {
      method: 'POST',
      body: JSON.stringify({
        role,
        content,
        image
      })
    }
  );
}

async function sendMessage(text = promptEl.value) {
  text = String(text || '').trim();

  if (!text || state.busy) return;

  if (text.length > 30000) {
    showStatus(
      'Сообщение превышает лимит 30 000 символов.',
      true
    );
    return;
  }

  const makeImage = state.imageMode;

  promptEl.value = '';
  promptEl.style.height = '31px';

  $('welcome').classList.add('hidden');

  showStatus('');

  addMessage('user', text);

  setBusy(true);

  let pending;

  try {
    if (state.user && !state.chatId) {
      await createChat();
    }

    if (state.user) {
      await saveMessage('user', text);
    }

    if (makeImage) {
      showStatus('Создаю изображение…');

      pending = addMessage(
        'assistant',
        'Создаю изображение…'
      );

      const data = await api('/api/images', {
        method: 'POST',
        body: JSON.stringify({ prompt: text })
      });

      pending.row.remove();

      addMessage(
        'assistant',
        'Готово! Вот твоё изображение:',
        data.image
      );

      if (state.user) {
        await saveMessage(
          'assistant',
          'Готово! Вот твоё изображение:',
          data.image
        );
      }
    } else {
      pending = addMessage('assistant', 'Думаю…');

      const history = [
        ...messagesEl.querySelectorAll('.message')
      ]
        .slice(0, -2)
        .map(row => ({
          role: row.classList.contains('user')
            ? 'user'
            : 'assistant',
          content:
            row.querySelector('.bubble')?.innerText || ''
        }))
        .filter(item => item.content)
        .slice(-10);

      const data = await api('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
          message: text,
          history
        })
      });

      pending.row.remove();

      addMessage(
        'assistant',
        data.reply || 'Не удалось получить ответ.'
      );

      if (state.user) {
        await saveMessage(
          'assistant',
          data.reply || 'Не удалось получить ответ.'
        );
      }
    }

    if (state.user) {
      await loadChats();
    }

    showStatus('');
  } catch (err) {
    if (pending?.row?.isConnected) {
      pending.row.remove();
    }

    addMessage(
      'assistant',
      `**Ошибка:** ${err.message}`
    );

    showStatus(err.message, true);
  } finally {
    setBusy(false);

    state.imageMode = false;

    $('imageMode').style.borderColor = '';

    promptEl.focus();

    scrollToBottom();
  }
}

/* =========================
   МОДАЛЬНЫЕ ОКНА
========================= */

// Закрывает все открытые модальные окна перед открытием нового.
function closeAllModals(exceptId = null) {
  document.querySelectorAll('.modal-layer.open').forEach(modal => {
    if (modal.id !== exceptId) {
      modal.classList.remove('open');
    }
  });
}

function showAuth(register = false) {
  // Сначала закрываем все остальные окна.
  closeAllModals('authModal');

  state.register = register;

  $('authTitle').textContent = register
    ? 'Создать аккаунт'
    : 'Войти в Maut AI';

  $('authSubtitle').textContent = register
    ? 'Создай аккаунт, чтобы сохранять историю чатов.'
    : 'Рады видеть тебя снова.';

  $('nameField').classList.toggle('hidden', !register);

  $('authName').required = register;

  $('authPassword').autocomplete = register
    ? 'new-password'
    : 'current-password';

  $('authSubmit').textContent = register
    ? 'Зарегистрироваться'
    : 'Войти';

  $('switchAuth').textContent = register
    ? 'Уже есть аккаунт? Войти'
    : 'Нет аккаунта? Зарегистрироваться';

  $('authError').textContent = '';

  // Показываем одно окно после закрытия остальных.
  $('authModal').classList.add('open');
}

function closeAuth() {
  $('authModal').classList.remove('open');
}

// Переключение входа и регистрации.
$('switchAuth').addEventListener('click', event => {
  event.preventDefault();
  event.stopPropagation();

  showAuth(!state.register);
});

$('authForm').addEventListener('submit', async event => {
  event.preventDefault();

  $('authError').textContent = '';
  $('authSubmit').disabled = true;

  try {
    const body = {
      email: $('authEmail').value.trim(),
      password: $('authPassword').value
    };

    let endpoint = '/api/auth/login';

    if (state.register) {
      endpoint = '/api/auth/register';
      body.name = $('authName').value.trim();
    }

    const data = await api(endpoint, {
      method: 'POST',
      body: JSON.stringify(body)
    });

    state.user = data.user;

    updateProfile();

    closeAuth();

    resetView();

    await loadChats();
    await refreshRank();

    showStatus('Вход выполнен.');

    setTimeout(() => showStatus(''), 2000);
  } catch (err) {
    $('authError').textContent = err.message;
  } finally {
    $('authSubmit').disabled = false;
  }
});

$('closeModal').addEventListener('click', closeAuth);

$('authModal').addEventListener('click', event => {
  if (event.target === $('authModal')) {
    closeAuth();
  }
});

$('loginTop').addEventListener('click', () => showAuth(false));
$('authSide').addEventListener('click', () => showAuth(false));

/* =========================
   ВЫХОД И НОВЫЙ ЧАТ
========================= */

$('logout').addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({})
    });
  } catch (err) {
    showStatus(err.message, true);
  }

  state.user = null;
  state.chats = [];

  updateProfile();
  resetView();

  await loadChats();
});

$('newChat').addEventListener('click', () => {
  resetView();
  loadChats();

  $('sidebar').classList.remove('open');

  promptEl.focus();
});

$('brandHome').addEventListener('click', event => {
  event.preventDefault();
  resetView();
});

/* =========================
   БОКОВАЯ ПАНЕЛЬ
========================= */

$('sidebarToggle').addEventListener('click', () => {
  if (window.matchMedia('(max-width: 760px)').matches) {
    $('sidebar').classList.toggle('open');
  } else {
    document
      .querySelector('.layout')
      .classList.toggle('sidebar-collapsed');
  }
});

window.addEventListener('resize', () => {
  if (!window.matchMedia('(max-width: 760px)').matches) {
    $('sidebar').classList.remove('open');
  }
});

/* =========================
   СОЗДАНИЕ ИЗОБРАЖЕНИЙ
========================= */

$('imageMode').addEventListener('click', () => {
  state.imageMode = !state.imageMode;

  $('imageMode').style.borderColor =
    state.imageMode ? 'var(--green)' : '';

  promptEl.placeholder = state.imageMode
    ? 'Опиши изображение, которое нужно создать…'
    : 'Напиши сообщение Maut AI…';

  promptEl.focus();
});

/* =========================
   ОТПРАВКА СООБЩЕНИЙ
========================= */

$('composer').addEventListener('submit', event => {
  event.preventDefault();
  sendMessage();
});

promptEl.addEventListener('keydown', event => {
  if (
    event.key === 'Enter' &&
    !event.shiftKey &&
    !event.isComposing
  ) {
    event.preventDefault();
    sendMessage();
  }
});

promptEl.addEventListener('input', () => {
  promptEl.style.height = '31px';

  promptEl.style.height =
    Math.min(promptEl.scrollHeight, 180) + 'px';
});

document.querySelectorAll('[data-prompt]').forEach(button => {
  button.addEventListener('click', () => {
    promptEl.value = button.dataset.prompt;

    promptEl.dispatchEvent(new Event('input'));

    sendMessage();
  });
});

/* =========================
   РАНГИ
========================= */

async function refreshRank() {
  if (!state.user) return;

  try {
    const data = await api('/api/ranks/me');

    state.user.rank = data.rank;

    updateProfile();
  } catch (err) {
    console.warn(err);
  }
}

$('redeemOpen').addEventListener('click', () => {
  closeAllModals('redeemModal');

  $('redeemError').textContent = '';
  $('redeemCode').value = '';

  $('redeemModal').classList.add('open');
});

$('redeemForm').addEventListener('submit', async event => {
  event.preventDefault();

  $('redeemSubmit').disabled = true;
  $('redeemError').textContent = '';

  try {
    const data = await api('/api/ranks/redeem', {
      method: 'POST',
      body: JSON.stringify({
        code: $('redeemCode').value
      })
    });

    state.user.rank = data.rank;

    updateProfile();

    $('redeemModal').classList.remove('open');

    showStatus('Ранг активирован: ' + data.rank);

    setTimeout(() => showStatus(''), 2500);
  } catch (err) {
    $('redeemError').textContent = err.message;
  } finally {
    $('redeemSubmit').disabled = false;
  }
});

/* =========================
   АДМИНИСТРАТИВНАЯ ПАНЕЛЬ
========================= */

$('adminOpen').addEventListener('click', async () => {
  closeAllModals('adminModal');

  $('adminModal').classList.add('open');

  await loadAdminUsers();
});

async function loadAdminUsers() {
  $('adminUsers').textContent = 'Загрузка…';
  $('adminError').textContent = '';

  try {
    const data = await api('/api/admin/users');

    const root = $('adminUsers');

    root.replaceChildren();

    const viewerRank =
      data.viewer_rank ||
      state.user?.rank ||
      'FREE';

    for (const person of data.users || []) {
      const row = document.createElement('div');

      row.className = 'admin-user';

      const info = document.createElement('div');

      const name = document.createElement('strong');

      name.textContent =
        person.display_name ||
        person.username;

      const detail = document.createElement('div');

      detail.className = 'muted';

      const until = person.muted_until
        ? Date.parse(person.muted_until)
        : 0;

      const activeMute = Boolean(
        until && until > Date.now()
      );

      detail.textContent =
        `${person.email || ''} · ${person.rank || 'FREE'}` +
        (activeMute ? ' · МУТ АКТИВЕН' : '');

      info.append(name, detail);

      row.append(info);

      if (viewerRank === 'ADMIN') {
        const select = document.createElement('select');

        for (const rank of ['FREE', 'PLUS', 'MODER', 'ADMIN']) {
          const opt = document.createElement('option');

          opt.value = rank;
          opt.textContent = rank;
          opt.selected = rank === (person.rank || 'FREE');

          select.appendChild(opt);
        }

        const save = document.createElement('button');

        save.type = 'button';
        save.textContent = 'Сохранить';

        save.addEventListener('click', async () => {
          try {
            await api(`/api/admin/users/${person.id}/rank`, {
              method: 'POST',
              body: JSON.stringify({
                rank: select.value
              })
            });

            showStatus('Ранг обновлён');

            await loadAdminUsers();
          } catch (err) {
            $('adminError').textContent = err.message;
          }
        });

        row.append(select, save);
      }

      const canModerMute =
        viewerRank === 'ADMIN' ||
        (
          viewerRank === 'MODER' &&
          ['FREE', 'PLUS'].includes(person.rank)
        );

      if (
        canModerMute &&
        Number(person.id) !== Number(state.user?.id) &&
        person.rank !== 'ADMIN'
      ) {
        const mute = document.createElement('button');

        mute.type = 'button';

        mute.textContent = activeMute
          ? 'Продлить мут'
          : 'Мут 7 минут';

        mute.addEventListener('click', async () => {
          mute.disabled = true;

          try {
            await api(`/api/admin/users/${person.id}/mute`, {
              method: 'POST',
              body: JSON.stringify({})
            });

            showStatus('Мут выдан на 7 минут');

            await loadAdminUsers();
          } catch (err) {
            $('adminError').textContent = err.message;
          } finally {
            mute.disabled = false;
          }
        });

        row.append(mute);
      }

      root.appendChild(row);
    }
  } catch (err) {
    $('adminUsers').textContent =
      'Не удалось загрузить пользователей.';

    $('adminError').textContent = err.message;
  }
}

$('createCodes').addEventListener('click', async () => {
  $('codeResult').classList.add('hidden');
  $('adminError').textContent = '';

  try {
    const data = await api('/api/admin/codes', {
      method: 'POST',
      body: JSON.stringify({
        rank: $('codeRank').value,
        amount: Number($('codeAmount').value)
      })
    });

    $('codeResult').textContent = data.codes.join('\n');

    $('codeResult').classList.remove('hidden');
  } catch (err) {
    $('adminError').textContent = err.message;
  }
});

/* =========================
   ЗАКРЫТИЕ ОСТАЛЬНЫХ ОКОН
========================= */

document.querySelectorAll('[data-close]').forEach(button => {
  button.addEventListener('click', () => {
    const modal = $(button.dataset.close);

    if (modal) {
      modal.classList.remove('open');
    }
  });
});

$('redeemModal').addEventListener('click', event => {
  if (event.target === $('redeemModal')) {
    $('redeemModal').classList.remove('open');
  }
});

$('adminModal').addEventListener('click', event => {
  if (event.target === $('adminModal')) {
    $('adminModal').classList.remove('open');
  }
});

/* =========================
   ЗАПУСК
========================= */

loadMe();
