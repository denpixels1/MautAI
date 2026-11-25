
const $ = id => document.getElementById(id);

const promptBox = $('prompt');
const messagesEl = $('messages');
const welcome = $('welcome');

let user = null;
let isRegister = false;
let imageMode = false;
let chatMessages = [];
let currentTitle = '';
let isSending = false;

function status(text, error = false) {
  const el = $('status');
  if (!el) return;

  el.textContent = text;
  el.classList.toggle('show', Boolean(text));
  el.classList.toggle('error', error);
}

function showAuthError(text) {
  const el = $('authError');
  if (el) el.textContent = text || '';
}

function addMessage(role, text, image = null) {
  welcome?.classList.add('hidden');

  const row = document.createElement('div');
  row.className = `message ${role}`;

  if (role === 'assistant') {
    const mark = document.createElement('div');
    mark.className = 'message-mark';
    mark.textContent = '✳';
    row.append(mark);
  }

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text || '';

  if (image) {
    const img = document.createElement('img');
    img.className = 'message-image';
    img.src = image;
    img.alt = 'Изображение Maut AI';

    const link = document.createElement('a');
    link.href = image;
    link.download = 'maut-ai-image.png';
    link.className = 'download-link';
    link.textContent = 'Скачать изображение';

    bubble.append(
      document.createElement('br'),
      img,
      document.createElement('br'),
      link
    );
  }

  row.append(bubble);
  messagesEl.append(row);

  window.scrollTo({
    top: document.body.scrollHeight,
    behavior: 'smooth'
  });

  return bubble;
}

function updateProfile() {
  const displayName =
    user?.name ||
    user?.username ||
    user?.email ||
    'Гость';

  if ($('profileName')) {
    $('profileName').textContent = displayName;
  }

  if ($('profileEmail')) {
    $('profileEmail').textContent =
      user?.email || (user ? 'Аккаунт Maut AI' : 'Войди, чтобы начать');
  }

  if ($('avatar')) {
    $('avatar').textContent = displayName.slice(0, 1).toUpperCase();
  }

  if ($('loginBtn')) {
    $('loginBtn').textContent = user ? 'Выйти' : 'Войти';
  }
}

// Универсальный запрос к серверу.
// Cookie сессии передаётся браузером автоматически.
async function request(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {})
    }
  });

  let data = {};

  try {
    data = await response.json();
  } catch {
    // Сервер мог вернуть пустой ответ.
  }

  if (!response.ok) {
    const error = new Error(
      data.error || `Ошибка сервера (${response.status})`
    );

    error.status = response.status;
    throw error;
  }

  return data;
}

async function api(url, body = {}) {
  return request(url, {
    method: 'POST',
    body: JSON.stringify(body)
  });
}

// Восстанавливаем аккаунт из серверной сессии.
async function checkUser() {
  try {
    const data = await request('/api/auth/me', {
      method: 'GET'
    });

    user = data.user || null;
    updateProfile();
  } catch (error) {
    console.error('Проверка аккаунта:', error);

    // При временной сетевой ошибке не стираем состояние
    // и не показываем ложное сообщение о выходе.
    status('Не удалось проверить аккаунт. Обнови страницу позже.', true);
  }
}

function openAuth(register = false) {
  isRegister = register;
  showAuthError('');

  $('authModal').classList.add('open');
  $('authModal').setAttribute('aria-hidden', 'false');

  $('modalTitle').textContent = register
    ? 'Создать аккаунт'
    : 'Войти в Maut AI';

  $('modalSubtitle').textContent = register
    ? 'Создай аккаунт, чтобы пользоваться Maut AI.'
    : 'Войди в свой аккаунт Maut AI.';

  $('nameLabel').classList.toggle('hidden', !register);
  $('name').required = register;

  $('password').autocomplete = register
    ? 'new-password'
    : 'current-password';

  $('authSubmit').textContent = register
    ? 'Зарегистрироваться'
    : 'Войти';

  $('switchAuth').textContent = register
    ? 'Уже есть аккаунт? Войти'
    : 'Нет аккаунта? Зарегистрироваться';
}

function closeAuth() {
  $('authModal').classList.remove('open');
  $('authModal').setAttribute('aria-hidden', 'true');
}

$('closeModal').onclick = closeAuth;

$('authModal').addEventListener('click', event => {
  if (event.target === $('authModal')) {
    closeAuth();
  }
});

$('switchAuth').onclick = () => openAuth(!isRegister);

// Вход и выход.
$('loginBtn').onclick = async () => {
  if (!user) {
    openAuth(false);
    return;
  }

  try {
    await api('/api/auth/logout', {});

    user = null;
    updateProfile();
    chatMessages = [];

    status('Ты вышел из аккаунта.');
  } catch (error) {
    status(error.message, true);
  }
};

$('profileMenu').onclick = () => {
  if (user) {
    status('Ты вошёл как ' + (user.email || user.username || user.name));
  } else {
    openAuth(false);
  }
};

// Регистрация и вход.
$('authForm').addEventListener('submit', async event => {
  event.preventDefault();

  const submitButton = $('authSubmit');
  submitButton.disabled = true;
  showAuthError('');

  const name = $('name').value.trim();
  const email = $('email').value.trim();
  const password = $('password').value;

  try {
    let data;

    if (isRegister) {
      // Совместимость с сервером, который принимает username,
      // и с формой, которая использует name и email.
      data = await api('/api/auth/register', {
        username: name || email,
        name,
        email,
        password
      });
    } else {
      data = await api('/api/auth/login', {
        username: email || name,
        name,
        email,
        password
      });
    }

    user = data.user || null;

    if (!user) {
      throw new Error('Сервер не вернул данные аккаунта.');
    }

    updateProfile();
    closeAuth();
    $('password').value = '';

    status('Готово! Ты вошёл в Maut AI.');
  } catch (error) {
    showAuthError(error.message);
  } finally {
    submitButton.disabled = false;
  }
});

// История чатов в боковой панели.
function addHistory(title) {
  const history = $('history');
  if (!history) return;

  const empty = history.querySelector('.muted');
  if (empty) empty.remove();

  const button = document.createElement('button');
  button.className = 'history-item';
  button.textContent = title.slice(0, 70);
  button.title = title;

  button.onclick = () => {
    status('Это название предыдущего чата. Полная история пока не сохраняется.');
  };

  history.prepend(button);
}

function newChat() {
  chatMessages = [];
  currentTitle = '';

  messagesEl.replaceChildren();
  welcome?.classList.remove('hidden');

  promptBox.value = '';
  promptBox.placeholder = 'Напиши Maut AI';

  imageMode = false;
  status('');

  $('sidebar')?.classList.remove('open');
}

$('newChat').onclick = newChat;

// Отправка сообщений.
async function send() {
  if (isSending) return;

  const text = promptBox.value.trim();
  if (!text) return;

  if (!user) {
    openAuth(false);
    status('Сначала войди или создай аккаунт.', true);
    return;
  }

  isSending = true;
  promptBox.value = '';
  promptBox.style.height = 'auto';
  status('');

  if (!currentTitle) {
    currentTitle = text;
    addHistory(text);
  }

  if (imageMode) {
    imageMode = false;

    addMessage('user', text);
    const bubble = addMessage('assistant', 'Создаю изображение…');

    $('sendBtn').disabled = true;

    try {
      const data = await api('/api/images', {
        prompt: text
      });

      if (!data.image) {
        throw new Error('Сервис не вернул изображение.');
      }

      bubble.textContent = 'Готово!';

      const img = document.createElement('img');
      img.className = 'message-image';
      img.src = data.image;
      img.alt = 'Созданное изображение';

      const link = document.createElement('a');
      link.href = data.image;
      link.download = 'maut-ai-image.png';
      link.className = 'download-link';
      link.textContent = 'Скачать изображение';

      bubble.append(
        document.createElement('br'),
        img,
        document.createElement('br'),
        link
      );
    } catch (error) {
      bubble.textContent = error.message;
      status(error.message, true);
    } finally {
      isSending = false;
      $('sendBtn').disabled = false;
    }

    return;
  }

  addMessage('user', text);

  chatMessages.push({
    role: 'user',
    content: text
  });

  const bubble = addMessage('assistant', 'Думаю…');
  $('sendBtn').disabled = true;

  try {
    // server.js ожидает поле message и массив history.
    const data = await api('/api/chat', {
      message: text,
      history: chatMessages.slice(0, -1)
    });

    const answer = data.reply || data.text;

    if (typeof answer !== 'string' || !answer.trim()) {
      throw new Error('ИИ вернул пустой ответ.');
    }

    bubble.textContent = answer;

    chatMessages.push({
      role: 'assistant',
      content: answer
    });
  } catch (error) {
    bubble.textContent = error.message;
    status(error.message, true);

    // Удаляем последнее сообщение пользователя из контекста,
    // если сервер не ответил.
    chatMessages.pop();
  } finally {
    isSending = false;
    $('sendBtn').disabled = false;
    promptBox.focus();
  }
}

$('chatForm').addEventListener('submit', event => {
  event.preventDefault();
  send();
});

promptBox.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    send();
  }
});

promptBox.addEventListener('input', () => {
  promptBox.style.height = 'auto';
  promptBox.style.height =
    Math.min(promptBox.scrollHeight, 180) + 'px';
});

function chooseImage() {
  if (!user) {
    openAuth(false);
    status('Войди, чтобы создавать изображения.', true);
    return;
  }

  imageMode = true;
  promptBox.placeholder = 'Опиши изображение, которое нужно создать…';
  promptBox.focus();

  status('Режим создания изображений включён.');
}

$('imageBtn').onclick = chooseImage;
$('imageMode').onclick = chooseImage;

document.querySelectorAll('[data-prompt]').forEach(button => {
  button.onclick = () => {
    promptBox.value = button.dataset.prompt;
    send();
  };
});

document.querySelectorAll('[data-image]').forEach(button => {
  button.onclick = chooseImage;
});

$('menuBtn').onclick = () => {
  $('sidebar').classList.toggle('open');
};

// При загрузке страницы восстанавливаем аккаунт.
checkUser();
