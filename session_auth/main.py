"""
Session Аутентификация с FastAPI
Stateful аутентификация с использованием сессий

Этот модуль реализует полноценную систему аутентификации на основе сессий:
- Регистрация и авторизация пользователей
- Сессии с несколькими вариантами хранения (SQLite, файлы)
- Веб-интерфейс для демонстрации функциональности
- REST API для интеграции с другими приложениями

Альтернативы Redis:
1. SQLite - встроенная база данных для хранения сессий
2. Файловое хранилище - сессии в JSON файлах
3. In-memory хранилище - сессии в памяти (для разработки)
"""

# Импорт необходимых модулей FastAPI для создания веб-приложения
from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
from fastapi.responses import HTMLResponse  # Для возврата HTML страниц
from fastapi.staticfiles import StaticFiles  # Для обслуживания статических файлов

# Импорт Pydantic для валидации данных
from pydantic import BaseModel, EmailStr  # Базовые модели и валидация email

# Импорт библиотек для работы с безопасностью и сессиями
import bcrypt  # Для безопасного хеширования паролей с солью
import sqlite3  # Для работы с локальной базой данных SQLite
import json  # Для работы с JSON файлами
import os  # Для работы с файловой системой
import uuid  # Для генерации уникальных идентификаторов сессий

# Импорт модулей для работы с датами и временем
from datetime import datetime, timedelta  # Для установки времени жизни сессий
from typing import Optional, Dict, Any  # Для типизации
import secrets  # Для генерации криптографически стойких случайных строк

# Создание экземпляра FastAPI приложения с метаданными
app = FastAPI(title="Session Authentication", version="1.0.0")

# Монтирование статических файлов для обслуживания CSS, JS и других ресурсов
app.mount("/static", StaticFiles(directory="static"), name="static")

# =============================================================================
# КОНФИГУРАЦИЯ СЕССИЙ
# =============================================================================

# Секретный ключ для подписи сессий
# ⚠️ ВАЖНО: В продакшене используйте переменную окружения!
SECRET_KEY = "your-secret-key-change-in-production"

# Время жизни сессии в часах
SESSION_EXPIRE_HOURS = 24

# Тип хранилища сессий (sqlite, file, memory)
SESSION_STORAGE_TYPE = "sqlite"  # Можно изменить на "file" или "memory"

# Путь к файлам сессий (для file хранилища)
SESSIONS_DIR = "sessions"

# =============================================================================
# PYDANTIC СХЕМЫ ДАННЫХ ДЛЯ ВАЛИДАЦИИ
# =============================================================================

class UserRegister(BaseModel):
    """Схема для регистрации нового пользователя"""
    email: EmailStr  # Автоматическая валидация email формата
    password: str    # Пароль пользователя (будет захеширован)

class UserLogin(BaseModel):
    """Схема для входа пользователя в систему"""
    email: EmailStr  # Email для входа
    password: str    # Пароль для проверки

class UserResponse(BaseModel):
    """Схема ответа с информацией о пользователе"""
    id: int         # Уникальный идентификатор пользователя
    email: str      # Email пользователя
    created_at: str # Дата и время регистрации пользователя

class SessionInfo(BaseModel):
    """Схема информации о сессии"""
    session_id: str
    user_id: int
    created_at: str
    expires_at: str
    last_activity: str

# =============================================================================
# СИСТЕМА ХРАНЕНИЯ СЕССИЙ
# =============================================================================

class SessionStorage:
    """Базовый класс для хранения сессий"""
    
    def create_session(self, user_id: int) -> str:
        """Создание новой сессии"""
        raise NotImplementedError
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Получение сессии по ID"""
        raise NotImplementedError
    
    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Обновление сессии"""
        raise NotImplementedError
    
    def delete_session(self, session_id: str) -> bool:
        """Удаление сессии"""
        raise NotImplementedError
    
    def cleanup_expired(self) -> int:
        """Очистка истекших сессий"""
        raise NotImplementedError

class SQLiteSessionStorage(SessionStorage):
    """Хранение сессий в SQLite базе данных"""
    
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """Инициализация таблицы сессий"""
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        
        # Создание таблицы пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Создание таблицы сессий
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data TEXT DEFAULT '{}',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("SQLite база данных инициализирована")
    
    def create_session(self, user_id: int) -> str:
        """Создание новой сессии в SQLite"""
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=SESSION_EXPIRE_HOURS)
        
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (id, user_id, expires_at, data)
            VALUES (?, ?, ?, ?)
        ''', (session_id, user_id, expires_at, json.dumps({})))
        
        conn.commit()
        conn.close()
        
        print(f"Создана новая сессия: {session_id[:8]}... для пользователя {user_id}")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Получение сессии из SQLite"""
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, created_at, expires_at, last_activity, data
            FROM sessions WHERE id = ? AND expires_at > datetime('now')
        ''', (session_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            print(f"Сессия {session_id[:8]}... не найдена или истекла")
            return None
        
        user_id, created_at, expires_at, last_activity, data = result
        
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'created_at': created_at,
            'expires_at': expires_at,
            'last_activity': last_activity,
            'data': json.loads(data) if data else {}
        }
        
        print(f"Найдена сессия {session_id[:8]}... для пользователя {user_id}")
        return session_data
    
    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Обновление сессии в SQLite"""
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sessions 
            SET last_activity = datetime('now'), data = ?
            WHERE id = ? AND expires_at > datetime('now')
        ''', (json.dumps(data), session_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def delete_session(self, session_id: str) -> bool:
        """Удаление сессии из SQLite"""
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
        success = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        
        return success
    
    def cleanup_expired(self) -> int:
        """Очистка истекших сессий из SQLite"""
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM sessions WHERE expires_at <= datetime("now")')
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted_count

class FileSessionStorage(SessionStorage):
    """Хранение сессий в JSON файлах"""
    
    def __init__(self):
        self.sessions_dir = SESSIONS_DIR
        os.makedirs(self.sessions_dir, exist_ok=True)
    
    def _get_session_file(self, session_id: str) -> str:
        """Получение пути к файлу сессии"""
        return os.path.join(self.sessions_dir, f"{session_id}.json")
    
    def create_session(self, user_id: int) -> str:
        """Создание новой сессии в файле"""
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=SESSION_EXPIRE_HOURS)
        
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at.isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'data': {}
        }
        
        session_file = self._get_session_file(session_id)
        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, ensure_ascii=False, indent=2)
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Получение сессии из файла"""
        session_file = self._get_session_file(session_id)
        
        if not os.path.exists(session_file):
            return None
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            # Проверяем, не истекла ли сессия
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.utcnow() > expires_at:
                os.remove(session_file)  # Удаляем истекшую сессию
                return None
            
            return session_data
        except (json.JSONDecodeError, KeyError, ValueError):
            # Если файл поврежден, удаляем его
            if os.path.exists(session_file):
                os.remove(session_file)
            return None
    
    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Обновление сессии в файле"""
        session_file = self._get_session_file(session_id)
        
        if not os.path.exists(session_file):
            return False
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            # Проверяем, не истекла ли сессия
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.utcnow() > expires_at:
                os.remove(session_file)
                return False
            
            # Обновляем данные
            session_data['last_activity'] = datetime.utcnow().isoformat()
            session_data['data'] = data
            
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
            
            return True
        except (json.JSONDecodeError, KeyError, ValueError):
            return False
    
    def delete_session(self, session_id: str) -> bool:
        """Удаление сессии из файла"""
        session_file = self._get_session_file(session_id)
        
        if os.path.exists(session_file):
            os.remove(session_file)
            return True
        
        return False
    
    def cleanup_expired(self) -> int:
        """Очистка истекших сессий из файлов"""
        deleted_count = 0
        
        for filename in os.listdir(self.sessions_dir):
            if filename.endswith('.json'):
                session_file = os.path.join(self.sessions_dir, filename)
                
                try:
                    with open(session_file, 'r', encoding='utf-8') as f:
                        session_data = json.load(f)
                    
                    expires_at = datetime.fromisoformat(session_data['expires_at'])
                    if datetime.utcnow() > expires_at:
                        os.remove(session_file)
                        deleted_count += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    # Удаляем поврежденные файлы
                    os.remove(session_file)
                    deleted_count += 1
        
        return deleted_count

class MemorySessionStorage(SessionStorage):
    """Хранение сессий в памяти (для разработки)"""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def create_session(self, user_id: int) -> str:
        """Создание новой сессии в памяти"""
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=SESSION_EXPIRE_HOURS)
        
        self.sessions[session_id] = {
            'session_id': session_id,
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at.isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'data': {}
        }
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Получение сессии из памяти"""
        if session_id not in self.sessions:
            return None
        
        session_data = self.sessions[session_id]
        
        # Проверяем, не истекла ли сессия
        expires_at = datetime.fromisoformat(session_data['expires_at'])
        if datetime.utcnow() > expires_at:
            del self.sessions[session_id]
            return None
        
        return session_data
    
    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Обновление сессии в памяти"""
        if session_id not in self.sessions:
            return False
        
        session_data = self.sessions[session_id]
        
        # Проверяем, не истекла ли сессия
        expires_at = datetime.fromisoformat(session_data['expires_at'])
        if datetime.utcnow() > expires_at:
            del self.sessions[session_id]
            return False
        
        # Обновляем данные
        session_data['last_activity'] = datetime.utcnow().isoformat()
        session_data['data'] = data
        
        return True
    
    def delete_session(self, session_id: str) -> bool:
        """Удаление сессии из памяти"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
    
    def cleanup_expired(self) -> int:
        """Очистка истекших сессий из памяти"""
        deleted_count = 0
        current_time = datetime.utcnow()
        
        expired_sessions = []
        for session_id, session_data in self.sessions.items():
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if current_time > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            deleted_count += 1
        
        return deleted_count

# Создание экземпляра хранилища сессий
def get_session_storage() -> SessionStorage:
    """Получение экземпляра хранилища сессий"""
    if SESSION_STORAGE_TYPE == "sqlite":
        return SQLiteSessionStorage()
    elif SESSION_STORAGE_TYPE == "file":
        return FileSessionStorage()
    elif SESSION_STORAGE_TYPE == "memory":
        return MemorySessionStorage()
    else:
        raise ValueError(f"Неизвестный тип хранилища: {SESSION_STORAGE_TYPE}")

# Глобальный экземпляр хранилища
session_storage = get_session_storage()

# =============================================================================
# ФУНКЦИИ БЕЗОПАСНОСТИ И РАБОТЫ С ПОЛЬЗОВАТЕЛЯМИ
# =============================================================================

def hash_password(password: str) -> str:
    """Безопасное хеширование пароля с использованием bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Проверка пароля против сохраненного хеша"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def get_user_by_email(email: str) -> Optional[tuple]:
    """Получение пользователя по email из базы данных"""
    conn = sqlite3.connect('session_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, password_hash, created_at FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email: str, password: str) -> Optional[int]:
    """Создание нового пользователя в базе данных"""
    password_hash = hash_password(password)
    conn = sqlite3.connect('session_users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
                      (email, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_user_by_id(user_id: int) -> Optional[tuple]:
    """Получение пользователя по ID"""
    conn = sqlite3.connect('session_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, password_hash, created_at FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

# =============================================================================
# ЗАВИСИМОСТИ И MIDDLEWARE ДЛЯ СЕССИЙ
# =============================================================================

def get_current_user(request: Request) -> int:
    """
    Извлечение и проверка текущего пользователя из сессии
    
    Args:
        request: FastAPI Request объект
        
    Returns:
        int: ID пользователя из сессии
        
    Raises:
        HTTPException: При отсутствии или невалидной сессии
        
    Принцип работы:
    1. Извлекает session_id из cookies
    2. Получает данные сессии из хранилища
    3. Проверяет валидность сессии
    4. Обновляет время последней активности
    5. Возвращает ID пользователя или выбрасывает исключение
    """
    # Получаем session_id из cookies
    session_id = request.cookies.get('session_id')
    print(f"get_current_user: session_id из cookie = {session_id[:8] if session_id else 'None'}...")
    
    if not session_id:
        print("get_current_user: Сессия не найдена в cookies")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Сессия не найдена"
        )
    
    # Получаем данные сессии
    session_data = session_storage.get_session(session_id)
    if not session_data:
        print("get_current_user: Недействительная сессия")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительная сессия"
        )
    
    # Обновляем время последней активности
    session_storage.update_session(session_id, session_data.get('data', {}))
    
    print(f"get_current_user: Пользователь {session_data['user_id']} авторизован")
    return session_data['user_id']

def create_session_response(user_id: int, response: Response) -> Response:
    """
    Создание ответа с установкой cookie сессии
    
    Args:
        user_id: ID пользователя
        response: FastAPI Response объект
        
    Returns:
        Response: Ответ с установленным cookie сессии
    """
    # Создаем новую сессию
    session_id = session_storage.create_session(user_id)
    
    # Устанавливаем cookie с сессией
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=SESSION_EXPIRE_HOURS * 3600,  # Время жизни в секундах
        httponly=True,  # Защита от XSS атак
        secure=False,   # В продакшене должно быть True для HTTPS
        samesite="lax"  # Защита от CSRF атак
    )
    
    print(f"create_session_response: Установлен cookie session_id = {session_id[:8]}...")
    return response

# =============================================================================
# HTML ИНТЕРФЕЙС И ВЕБ-СТРАНИЦЫ
# =============================================================================

@app.get("/", response_class=HTMLResponse)
def read_root():
    """
    Главная страница с формами регистрации и входа
    
    Возвращает HTML страницу с:
    - Формами регистрации и входа
    - Индикатором состояния авторизации
    - Информацией о текущей сессии
    - JavaScript для интерактивности
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Session Аутентификация</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; }
            input[type="email"], input[type="password"] { width: 100%; padding: 8px; margin-bottom: 10px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; margin: 5px; }
            button:hover { background: #0056b3; }
            button:disabled { background: #6c757d; cursor: not-allowed; }
            .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            .auth-status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; }
            .auth-status.authenticated { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .auth-status.not-authenticated { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .user-info { background: #e7f3ff; padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #007bff; }
            .session-info { background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #28a745; }
            .loading { opacity: 0.6; pointer-events: none; }
            .storage-info { background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #ffc107; }
        </style>
    </head>
    <body>
        <h1>Session Аутентификация</h1>
        
        <div class="storage-info">
            <strong>Тип хранилища сессий:</strong> <span id="storage-type">""" + SESSION_STORAGE_TYPE + """</span>
        </div>
        
        <div id="messages"></div>
        
        <!-- Индикатор состояния авторизации -->
        <div id="auth-status" class="auth-status not-authenticated">
            🔒 Не авторизован
        </div>
        
        <!-- Информация о пользователе -->
        <div id="user-info" class="user-info" style="display: none;">
            <h3>👤 Информация о пользователе</h3>
            <p><strong>Email:</strong> <span id="user-email"></span></p>
            <p><strong>ID:</strong> <span id="user-id"></span></p>
            <p><strong>Дата регистрации:</strong> <span id="user-created"></span></p>
        </div>
        
        <!-- Информация о сессии -->
        <div id="session-info" class="session-info" style="display: none;">
            <h3>🔑 Информация о сессии</h3>
            <p><strong>Session ID:</strong> <span id="session-id"></span></p>
            <p><strong>Создана:</strong> <span id="session-created"></span></p>
            <p><strong>Истекает:</strong> <span id="session-expires"></span></p>
            <p><strong>Последняя активность:</strong> <span id="session-last-activity"></span></p>
        </div>
        
        <h2>Регистрация</h2>
        <form id="registerForm">
            <div class="form-group">
                <label for="reg_email">Email:</label>
                <input type="email" id="reg_email" name="email" required>
            </div>
            <div class="form-group">
                <label for="reg_password">Пароль:</label>
                <input type="password" id="reg_password" name="password" required>
            </div>
            <button type="submit">Зарегистрироваться</button>
        </form>
        
        <h2>Вход</h2>
        <form id="loginForm">
            <div class="form-group">
                <label for="login_email">Email:</label>
                <input type="email" id="login_email" name="email" required>
            </div>
            <div class="form-group">
                <label for="login_password">Пароль:</label>
                <input type="password" id="login_password" name="password" required>
            </div>
            <button type="submit">Войти</button>
        </form>
        
        <h2>Профиль</h2>
        <button onclick="checkProfile()">Проверить профиль</button>
        <button onclick="getSessionInfo()">Информация о сессии</button>
        <button onclick="logout()">Выйти</button>
        
        <h2>Тестирование</h2>
        <button onclick="fillTestData()">Заполнить тестовые данные</button>
        <button onclick="cleanupSessions()">Очистить истекшие сессии</button>
        <button onclick="debugSession()">Отладка сессии</button>
        
        <script>
            function showMessage(message, type) {
                const messagesDiv = document.getElementById('messages');
                const div = document.createElement('div');
                div.className = `message ${type}`;
                div.textContent = message;
                messagesDiv.appendChild(div);
                setTimeout(() => {
                    if (div.parentNode) {
                        div.remove();
                    }
                }, 5000);
            }
            
            function updateAuthStatus(isAuthenticated, userInfo = null, sessionInfo = null) {
                const statusDiv = document.getElementById('auth-status');
                const userInfoDiv = document.getElementById('user-info');
                const sessionInfoDiv = document.getElementById('session-info');
                
                if (isAuthenticated && userInfo) {
                    statusDiv.className = 'auth-status authenticated';
                    statusDiv.innerHTML = '✅ Авторизован';
                    
                    userInfoDiv.style.display = 'block';
                    document.getElementById('user-email').textContent = userInfo.email;
                    document.getElementById('user-id').textContent = userInfo.id;
                    document.getElementById('user-created').textContent = new Date(userInfo.created_at).toLocaleString('ru-RU');
                    
                    if (sessionInfo) {
                        sessionInfoDiv.style.display = 'block';
                        document.getElementById('session-id').textContent = sessionInfo.session_id.substring(0, 8) + '...';
                        document.getElementById('session-created').textContent = new Date(sessionInfo.created_at).toLocaleString('ru-RU');
                        document.getElementById('session-expires').textContent = new Date(sessionInfo.expires_at).toLocaleString('ru-RU');
                        document.getElementById('session-last-activity').textContent = new Date(sessionInfo.last_activity).toLocaleString('ru-RU');
                    }
                } else {
                    statusDiv.className = 'auth-status not-authenticated';
                    statusDiv.innerHTML = '🔒 Не авторизован';
                    
                    userInfoDiv.style.display = 'none';
                    sessionInfoDiv.style.display = 'none';
                }
            }
            
            function setLoading(formId, isLoading) {
                const form = document.getElementById(formId);
                const buttons = form.querySelectorAll('button');
                buttons.forEach(btn => {
                    if (isLoading) {
                        btn.disabled = true;
                        btn.dataset.originalText = btn.textContent;
                        btn.textContent = btn.textContent + '...';
                    } else {
                        btn.disabled = false;
                        if (btn.dataset.originalText) {
                            btn.textContent = btn.dataset.originalText;
                        }
                    }
                });
                if (isLoading) {
                    form.classList.add('loading');
                } else {
                    form.classList.remove('loading');
                }
            }
            
            document.getElementById('registerForm').onsubmit = async (e) => {
                e.preventDefault();
                setLoading('registerForm', true);
                
                try {
                    const formData = new FormData(e.target);
                    const email = formData.get('email');
                    const password = formData.get('password');
                    
                    if (!email || !password) {
                        showMessage('❌ Пожалуйста, заполните все поля', 'error');
                        return;
                    }
                    
                    const response = await fetch('/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        showMessage('🎉 Регистрация успешна! Теперь вы можете войти в систему.', 'success');
                        e.target.reset();
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                    }
                } catch (error) {
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                } finally {
                    setLoading('registerForm', false);
                }
            };
            
            document.getElementById('loginForm').onsubmit = async (e) => {
                e.preventDefault();
                setLoading('loginForm', true);
                
                try {
                    const formData = new FormData(e.target);
                    const email = formData.get('email');
                    const password = formData.get('password');
                    
                    if (!email || !password) {
                        showMessage('❌ Пожалуйста, заполните все поля', 'error');
                        return;
                    }
                    
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        showMessage('🎉 Вход выполнен успешно!', 'success');
                        e.target.reset();
                        
                        // Автоматически проверяем профиль и обновляем UI
                        await checkProfile();
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                    }
                } catch (error) {
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                } finally {
                    setLoading('loginForm', false);
                }
            };
            
            async function checkProfile() {
                try {
                    const response = await fetch('/profile');
                    const result = await response.json();
                    
                    if (response.ok) {
                        updateAuthStatus(true, result);
                        showMessage(`👋 Добро пожаловать, ${result.email}!`, 'info');
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                        updateAuthStatus(false);
                    }
                } catch (error) {
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                    updateAuthStatus(false);
                }
            }
            
            async function getSessionInfo() {
                try {
                    const response = await fetch('/session-info');
                    const result = await response.json();
                    
                    if (response.ok) {
                        updateAuthStatus(true, null, result);
                        showMessage('📋 Информация о сессии обновлена', 'info');
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                    }
                } catch (error) {
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                }
            }
            
            async function logout() {
                try {
                    const response = await fetch('/logout', { method: 'POST' });
                    const result = await response.json();
                    
                    if (response.ok) {
                        showMessage('👋 Выход выполнен успешно!', 'success');
                        updateAuthStatus(false);
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                    }
                } catch (error) {
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                }
            }
            
            function fillTestData() {
                document.getElementById('reg_email').value = 'test@example.com';
                document.getElementById('reg_password').value = 'testpass123';
                document.getElementById('login_email').value = 'test@example.com';
                document.getElementById('login_password').value = 'testpass123';
                showMessage('📝 Заполнены тестовые данные', 'info');
            }
            
            async function cleanupSessions() {
                try {
                    const response = await fetch('/cleanup-sessions', { method: 'POST' });
                    const result = await response.json();
                    
                    if (response.ok) {
                        showMessage(`🧹 Очищено ${result.deleted_count} истекших сессий`, 'success');
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                    }
                } catch (error) {
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                }
            }
            
            async function debugSession() {
                try {
                    const response = await fetch('/debug-session');
                    const result = await response.json();
                    
                    console.log('Debug session info:', result);
                    
                    let message = `🔍 Отладка сессии:\n`;
                    message += `Session ID: ${result.session_id_from_cookie || 'не найден'}\n`;
                    message += `Тип хранилища: ${result.storage_type}\n`;
                    message += `Сессия существует: ${result.session_exists ? 'да' : 'нет'}\n`;
                    message += `Cookies: ${JSON.stringify(result.cookies)}`;
                    
                    if (result.session_data) {
                        message += `\nДанные сессии: ${JSON.stringify(result.session_data, null, 2)}`;
                    }
                    
                    showMessage(message, 'info');
                } catch (error) {
                    showMessage(`❌ Ошибка отладки: ${error.message}`, 'error');
                }
            }
            
            // Проверяем статус авторизации при загрузке страницы
            window.onload = function() {
                checkProfile();
            };
        </script>
    </body>
    </html>
    """
    return html

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.post("/register", response_model=dict)
def register(user: UserRegister):
    """
    Регистрация нового пользователя в системе
    
    Args:
        user: Данные пользователя (email и password) из Pydantic схемы
        
    Returns:
        dict: Сообщение об успешной регистрации
        
    Raises:
        HTTPException: При невалидных данных или дубликате email
    """
    print(f"Register request received: email={user.email}, password_length={len(user.password)}")
    
    # Проверка минимальной длины пароля
    if len(user.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен содержать минимум 6 символов"
        )
    
    # Создание пользователя в БД
    user_id = create_user(user.email, user.password)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    
    return {"message": "Пользователь успешно зарегистрирован"}

@app.post("/login", response_model=dict)
def login(user: UserLogin, response: Response):
    """
    Вход пользователя в систему и создание сессии
    
    Args:
        user: Данные для входа (email и password) из Pydantic схемы
        response: FastAPI Response объект для установки cookie
        
    Returns:
        dict: Сообщение об успешном входе
        
    Raises:
        HTTPException: При неверных учетных данных
    """
    print(f"Login request received: email={user.email}, password_length={len(user.password)}")
    
    # Поиск пользователя по email
    user_data = get_user_by_email(user.email)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )
    
    # Распаковка данных пользователя из БД
    user_id, user_email, password_hash, created_at = user_data
    
    # Проверка пароля против хеша из БД
    if not verify_password(user.password, password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )
    
    # Создание сессии и установка cookie
    create_session_response(user_id, response)
    
    return {"message": "Вход выполнен успешно"}

@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: int = Depends(get_current_user)):
    """
    Получение информации о профиле текущего пользователя (защищенный маршрут)
    
    Args:
        current_user: ID пользователя из сессии (автоматически извлекается)
        
    Returns:
        UserResponse: Информация о пользователе (id, email, created_at)
        
    Raises:
        HTTPException: При невалидной сессии или отсутствии пользователя
    """
    # Получение информации о пользователе
    user_data = get_user_by_id(current_user)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    
    # Распаковка данных пользователя
    user_id, email, password_hash, created_at = user_data
    return UserResponse(
        id=user_id,
        email=email,
        created_at=created_at
    )

@app.get("/session-info", response_model=SessionInfo)
def get_session_info(request: Request, current_user: int = Depends(get_current_user)):
    """
    Получение информации о текущей сессии
    
    Args:
        request: FastAPI Request объект для получения session_id
        current_user: ID пользователя из сессии
        
    Returns:
        SessionInfo: Информация о сессии
        
    Raises:
        HTTPException: При невалидной сессии
    """
    # Получаем session_id из cookies
    session_id = request.cookies.get('session_id')
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Сессия не найдена"
        )
    
    # Получаем данные сессии (не обновляем время активности, так как это уже сделано в get_current_user)
    session_data = session_storage.get_session(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительная сессия"
        )
    
    return SessionInfo(
        session_id=session_data['session_id'],
        user_id=session_data['user_id'],
        created_at=session_data['created_at'],
        expires_at=session_data['expires_at'],
        last_activity=session_data['last_activity']
    )

@app.post("/logout", response_model=dict)
def logout(request: Request, response: Response):
    """
    Выход пользователя из системы (удаление сессии)
    
    Args:
        request: FastAPI Request объект для получения session_id
        response: FastAPI Response объект для удаления cookie
        
    Returns:
        dict: Сообщение об успешном выходе
    """
    # Получаем session_id из cookies
    session_id = request.cookies.get('session_id')
    
    if session_id:
        # Удаляем сессию из хранилища
        session_storage.delete_session(session_id)
    
    # Удаляем cookie сессии
    response.delete_cookie(key="session_id")
    
    return {"message": "Выход выполнен успешно"}

@app.post("/cleanup-sessions", response_model=dict)
def cleanup_sessions():
    """
    Очистка истекших сессий
    
    Returns:
        dict: Количество удаленных сессий
    """
    deleted_count = session_storage.cleanup_expired()
    return {"message": f"Очищено {deleted_count} истекших сессий", "deleted_count": deleted_count}

@app.get("/storage-info", response_model=dict)
def get_storage_info():
    """
    Получение информации о текущем хранилище сессий
    
    Returns:
        dict: Информация о хранилище
    """
    return {
        "storage_type": SESSION_STORAGE_TYPE,
        "session_expire_hours": SESSION_EXPIRE_HOURS,
        "description": {
            "sqlite": "Сессии хранятся в SQLite базе данных",
            "file": "Сессии хранятся в JSON файлах",
            "memory": "Сессии хранятся в памяти (для разработки)"
        }.get(SESSION_STORAGE_TYPE, "Неизвестный тип хранилища")
    }

@app.get("/debug-session")
def debug_session(request: Request):
    """
    Отладочный endpoint для проверки сессии
    
    Returns:
        dict: Отладочная информация о сессии
    """
    session_id = request.cookies.get('session_id')
    
    debug_info = {
        "session_id_from_cookie": session_id,
        "cookies": dict(request.cookies),
        "session_exists": False,
        "session_data": None,
        "storage_type": SESSION_STORAGE_TYPE
    }
    
    if session_id:
        session_data = session_storage.get_session(session_id)
        debug_info["session_exists"] = session_data is not None
        debug_info["session_data"] = session_data
    
    return debug_info

# =============================================================================
# ЗАПУСК ПРИЛОЖЕНИЯ
# =============================================================================

if __name__ == "__main__":
    """
    Точка входа в приложение
    
    Выполняется только при прямом запуске файла (python main.py)
    Не выполняется при импорте модуля
    """
    import uvicorn  # ASGI сервер для FastAPI
    
    # Инициализация базы данных (создание таблиц если не существуют)
    if SESSION_STORAGE_TYPE == "sqlite":
        session_storage.init_db()
    
    # Информационные сообщения для пользователя
    print("Запуск сервера Session аутентификации...")
    print(f"Тип хранилища сессий: {SESSION_STORAGE_TYPE}")
    print("Откройте http://localhost:8000 в браузере")
    print("API документация: http://localhost:8000/docs")
    print("\nАльтернативы Redis:")
    print("1. SQLite - встроенная база данных")
    print("2. Файловое хранилище - JSON файлы")
    print("3. In-memory хранилище - память (для разработки)")
    
    # Запуск ASGI сервера
    uvicorn.run(app, host="0.0.0.0", port=8000)
