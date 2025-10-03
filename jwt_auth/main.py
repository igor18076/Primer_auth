"""
JWT Аутентификация с FastAPI
Stateless аутентификация с JSON Web Tokens

Этот модуль реализует полноценную систему аутентификации на основе JWT токенов:
- Регистрация и авторизация пользователей
- Access и Refresh токены для безопасной работы
- Веб-интерфейс для демонстрации функциональности
- REST API для интеграции с другими приложениями
"""

# Импорт необходимых модулей FastAPI для создания веб-приложения
from fastapi import FastAPI, HTTPException, Depends, status  # Основные компоненты FastAPI
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # Для работы с Bearer токенами
from fastapi.responses import HTMLResponse  # Для возврата HTML страниц
from fastapi.staticfiles import StaticFiles  # Для обслуживания статических файлов

# Импорт Pydantic для валидации данных
from pydantic import BaseModel, EmailStr  # Базовые модели и валидация email

# Импорт библиотек для работы с JWT токенами и безопасностью
import jwt  # PyJWT для создания и проверки JWT токенов
import bcrypt  # Для безопасного хеширования паролей с солью
import sqlite3  # Для работы с локальной базой данных SQLite

# Импорт модулей для работы с датами и временем
from datetime import datetime, timedelta  # Для установки времени жизни токенов
from typing import Optional  # Для типизации опциональных параметров
import secrets  # Для генерации криптографически стойких случайных строк

# Создание экземпляра FastAPI приложения с метаданными
app = FastAPI(title="JWT Authentication", version="1.0.0")

# Монтирование статических файлов для обслуживания CSS, JS и других ресурсов
# Это позволяет обращаться к файлам через URL /static/filename
app.mount("/static", StaticFiles(directory="."), name="static")

# =============================================================================
# КОНФИГУРАЦИЯ JWT АУТЕНТИФИКАЦИИ
# =============================================================================

# Секретный ключ для подписи JWT токенов
# ⚠️ ВАЖНО: В продакшене используйте переменную окружения!
SECRET_KEY = "your-secret-key-change-in-production"

# Алгоритм шифрования для JWT токенов (HMAC с SHA-256)
ALGORITHM = "HS256"

# Время жизни access токена в минутах (короткий срок для безопасности)
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Время жизни refresh токена в днях (длинный срок для удобства пользователя)
REFRESH_TOKEN_EXPIRE_DAYS = 7

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

class Token(BaseModel):
    """Схема ответа с токенами после успешного входа"""
    access_token: str   # Короткоживущий токен для доступа к API
    refresh_token: str  # Долгоживущий токен для обновления access токена
    token_type: str     # Тип токена (обычно "bearer")

class TokenRefresh(BaseModel):
    """Схема для запроса обновления access токена"""
    refresh_token: str  # Refresh токен для получения нового access токена

class UserResponse(BaseModel):
    """Схема ответа с информацией о пользователе"""
    id: int         # Уникальный идентификатор пользователя
    email: str      # Email пользователя
    created_at: str # Дата и время регистрации пользователя

# =============================================================================
# ФУНКЦИИ РАБОТЫ С БАЗОЙ ДАННЫХ
# =============================================================================

def init_db():
    """
    Инициализация базы данных SQLite
    
    Создает две таблицы:
    1. users - для хранения информации о пользователях
    2. refresh_tokens - для хранения refresh токенов с их хешами
    """
    # Подключение к базе данных SQLite (создается автоматически если не существует)
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()  # Создание курсора для выполнения SQL команд
    
    # Создание таблицы пользователей
    # IF NOT EXISTS предотвращает ошибку если таблица уже существует
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Автоинкрементный ID
            email TEXT UNIQUE NOT NULL,             -- Уникальный email
            password_hash TEXT NOT NULL,            -- Хеш пароля (не сам пароль!)
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Время создания записи
        )
    ''')
    
    # Создание таблицы refresh токенов
    # Храним хеш токена, а не сам токен для безопасности
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,   -- Автоинкрементный ID
            user_id INTEGER NOT NULL,               -- Ссылка на пользователя
            token_hash TEXT NOT NULL,               -- Хеш refresh токена
            expires_at TIMESTAMP NOT NULL,          -- Время истечения токена
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Время создания
            FOREIGN KEY (user_id) REFERENCES users (id)      -- Внешний ключ
        )
    ''')
    
    # Сохранение изменений в базе данных
    conn.commit()
    # Закрытие соединения для освобождения ресурсов
    conn.close()

# =============================================================================
# ФУНКЦИИ БЕЗОПАСНОСТИ И ХЕШИРОВАНИЯ
# =============================================================================

def hash_password(password: str) -> str:
    """
    Безопасное хеширование пароля с использованием bcrypt
    
    Args:
        password: Пароль в открытом виде
        
    Returns:
        str: Хеш пароля с солью (безопасен для хранения в БД)
        
    Принцип работы:
    1. Генерируется случайная соль
    2. Пароль + соль хешируются с помощью bcrypt
    3. Результат содержит и соль, и хеш
    """
    # Генерация криптографически стойкой случайной соли
    salt = bcrypt.gensalt()
    # Хеширование пароля с солью и возврат результата как строки
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """
    Проверка пароля против сохраненного хеша
    
    Args:
        password: Пароль в открытом виде (от пользователя)
        password_hash: Сохраненный хеш из базы данных
        
    Returns:
        bool: True если пароль правильный, False если нет
        
    Принцип работы:
    1. Извлекает соль из сохраненного хеша
    2. Хеширует введенный пароль с той же солью
    3. Сравнивает результаты (константное время для защиты от timing атак)
    """
    # Безопасное сравнение с защитой от timing атак
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def get_user_by_email(email: str) -> Optional[tuple]:
    """
    Получение пользователя по email из базы данных
    
    Args:
        email: Email адрес пользователя для поиска
        
    Returns:
        Optional[tuple]: Кортеж (id, email, password_hash, created_at) или None если не найден
        
    Принцип работы:
    1. Подключается к БД SQLite
    2. Выполняет параметризованный запрос (защита от SQL injection)
    3. Возвращает первую найденную запись или None
    4. Закрывает соединение для освобождения ресурсов
    """
    conn = sqlite3.connect('jwt_users.db')  # Подключение к БД
    cursor = conn.cursor()  # Создание курсора для выполнения запросов
    # Параметризованный запрос для защиты от SQL injection
    cursor.execute('SELECT id, email, password_hash, created_at FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()  # Получение первой записи или None
    conn.close()  # Закрытие соединения
    return user

def create_user(email: str, password: str) -> Optional[int]:
    """
    Создание нового пользователя в базе данных
    
    Args:
        email: Email адрес пользователя
        password: Пароль в открытом виде (будет захеширован)
        
    Returns:
        Optional[int]: ID созданного пользователя или None при ошибке
        
    Принцип работы:
    1. Хеширует пароль с помощью bcrypt
    2. Подключается к БД и создает курсор
    3. Пытается вставить новую запись
    4. При успехе возвращает ID пользователя
    5. При ошибке IntegrityError (дубликат email) возвращает None
    6. Всегда закрывает соединение с БД
    """
    password_hash = hash_password(password)  # Хешируем пароль перед сохранением
    conn = sqlite3.connect('jwt_users.db')  # Подключение к БД
    cursor = conn.cursor()  # Создание курсора
    try:
        # Параметризованный INSERT запрос для безопасности
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
                      (email, password_hash))
        conn.commit()  # Сохранение изменений в БД
        user_id = cursor.lastrowid  # Получение ID созданной записи
        conn.close()  # Закрытие соединения
        return user_id  # Возврат ID пользователя
    except sqlite3.IntegrityError:  # Ошибка при дубликате email
        conn.close()  # Закрытие соединения при ошибке
        return None  # Возврат None при ошибке

# =============================================================================
# ФУНКЦИИ РАБОТЫ С JWT ТОКЕНАМИ
# =============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Создание JWT access токена для доступа к API
    
    Args:
        data: Словарь с данными для включения в токен (обычно {"sub": user_id})
        expires_delta: Опциональное время жизни токена
        
    Returns:
        str: Закодированный JWT токен
        
    Принцип работы:
    1. Копирует входящие данные
    2. Устанавливает время истечения (по умолчанию 30 минут)
    3. Добавляет тип токена ("access")
    4. Подписывает токен секретным ключом
    5. Возвращает строковое представление токена
    """
    to_encode = data.copy()  # Копируем данные чтобы не изменить оригинал
    
    # Устанавливаем время истечения токена
    if expires_delta:  # Если передано конкретное время
        expire = datetime.utcnow() + expires_delta
    else:  # Используем значение по умолчанию
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Добавляем время истечения и тип токена в payload
    to_encode.update({"exp": expire, "type": "access"})
    
    # Кодируем токен с секретным ключом и алгоритмом
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(user_id: int) -> str:
    """
    Создание refresh токена для обновления access токенов
    
    Args:
        user_id: ID пользователя для которого создается токен
        
    Returns:
        str: Оригинальный refresh токен (не хеш!)
        
    Принцип работы:
    1. Генерирует криптографически стойкую случайную строку
    2. Хеширует токен для безопасного хранения в БД
    3. Сохраняет хеш токена в БД с временем истечения
    4. Возвращает оригинальный токен клиенту
    
    Безопасность:
    - В БД хранится только хеш токена, не сам токен
    - Используется криптографически стойкая генерация
    - Токен имеет ограниченное время жизни
    """
    # Генерация криптографически стойкой случайной строки (32 байта)
    token = secrets.token_urlsafe(32)
    # Хешируем токен для безопасного хранения в БД
    token_hash = hash_password(token)
    
    # Сохранение refresh токена в БД
    conn = sqlite3.connect('jwt_users.db')  # Подключение к БД
    cursor = conn.cursor()  # Создание курсора
    # Вычисляем время истечения токена
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    # Параметризованный INSERT запрос
    cursor.execute('''
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at) 
        VALUES (?, ?, ?)
    ''', (user_id, token_hash, expires_at))
    conn.commit()  # Сохранение изменений
    conn.close()  # Закрытие соединения
    
    return token  # Возвращаем оригинальный токен (не хеш!)

def verify_refresh_token(token: str) -> Optional[int]:
    """
    Проверка refresh токена и получение ID пользователя
    
    Args:
        token: Refresh токен в оригинальном виде от клиента
        
    Returns:
        Optional[int]: ID пользователя если токен валиден, None если нет
        
    Принцип работы:
    1. Получает все активные (не истекшие) refresh токены из БД
    2. Проверяет входящий токен против каждого хеша
    3. При совпадении возвращает ID пользователя
    4. Если токен не найден или истек - возвращает None
    
    Безопасность:
    - Проверяет только не истекшие токены
    - Использует безопасное сравнение хешей
    - Не раскрывает информацию о существовании токенов
    """
    conn = sqlite3.connect('jwt_users.db')  # Подключение к БД
    cursor = conn.cursor()  # Создание курсора
    
    # Получаем все активные refresh токены (не истекшие)
    cursor.execute('''
        SELECT user_id, token_hash FROM refresh_tokens 
        WHERE expires_at > datetime('now')
    ''')
    tokens = cursor.fetchall()  # Получение всех активных токенов
    conn.close()  # Закрытие соединения
    
    # Проверяем входящий токен против каждого хеша
    for user_id, token_hash in tokens:
        if verify_password(token, token_hash):  # Безопасное сравнение
            return user_id  # Возвращаем ID пользователя при совпадении
    
    return None  # Токен не найден или истек

def revoke_refresh_token(token: str):
    """
    Отзыв (удаление) refresh токена из базы данных
    
    Args:
        token: Refresh токен для отзыва
        
    Принцип работы:
    1. Получает все активные refresh токены из БД
    2. Проверяет входящий токен против каждого хеша
    3. При совпадении удаляет токен из БД
    4. Сохраняет изменения и закрывает соединение
    
    Использование:
    - При выходе пользователя из системы
    - При подозрении на компрометацию токена
    - При смене пароля пользователя
    """
    conn = sqlite3.connect('jwt_users.db')  # Подключение к БД
    cursor = conn.cursor()  # Создание курсора
    
    # Получаем все активные refresh токены для проверки
    cursor.execute('''
        SELECT id, token_hash FROM refresh_tokens 
        WHERE expires_at > datetime('now')
    ''')
    tokens = cursor.fetchall()  # Получение всех активных токенов
    
    # Ищем и удаляем соответствующий токен
    for token_id, token_hash in tokens:
        if verify_password(token, token_hash):  # Проверяем токен
            # Удаляем токен из БД по ID
            cursor.execute('DELETE FROM refresh_tokens WHERE id = ?', (token_id,))
            break  # Прерываем цикл после удаления
    
    conn.commit()  # Сохранение изменений в БД
    conn.close()  # Закрытие соединения

# =============================================================================
# ЗАВИСИМОСТИ И MIDDLEWARE
# =============================================================================

# Создание экземпляра HTTPBearer для извлечения токенов из заголовка Authorization
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Извлечение и проверка текущего пользователя из JWT токена
    
    Args:
        credentials: Объект с токеном из заголовка Authorization: Bearer <token>
        
    Returns:
        int: ID пользователя из токена
        
    Raises:
        HTTPException: При невалидном токене или ошибке декодирования
        
    Принцип работы:
    1. Извлекает токен из заголовка Authorization
    2. Декодирует JWT токен с проверкой подписи
    3. Проверяет тип токена (должен быть "access")
    4. Извлекает ID пользователя из поля "sub"
    5. Возвращает ID пользователя или выбрасывает исключение
    
    Использование:
    - Как зависимость в защищенных эндпоинтах
    - Автоматически проверяет токен при каждом запросе
    """
    try:
        token = credentials.credentials  # Извлекаем токен из заголовка
        # Декодируем токен с проверкой подписи и алгоритма
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Проверяем тип токена (должен быть access, не refresh)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Извлекаем ID пользователя из поля "sub" (subject)
        user_id: int = payload.get("sub")
        if user_id is None:  # Если ID пользователя отсутствует
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        return user_id  # Возвращаем ID пользователя
    except jwt.PyJWTError:  # Ошибка декодирования или проверки токена
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

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
    - Кнопками для работы с токенами
    - JavaScript для интерактивности
    - Автоматическим заполнением форм из URL параметров
    
    Особенности:
    - Responsive дизайн
    - Автоматическая валидация форм
    - Обработка ошибок с пользовательскими сообщениями
    - Поддержка URL параметров для автоматического входа
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>JWT Аутентификация</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; }
            input[type="email"], input[type="password"], input[type="text"] { width: 100%; padding: 8px; margin-bottom: 10px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; margin: 5px; }
            button:hover { background: #0056b3; }
            button:disabled { background: #6c757d; cursor: not-allowed; }
            .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            .token-display { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; word-break: break-all; }
            .auth-status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; }
            .auth-status.authenticated { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .auth-status.not-authenticated { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .user-info { background: #e7f3ff; padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #007bff; }
            .loading { opacity: 0.6; pointer-events: none; }
        </style>
    </head>
    <body>
        <h1>JWT Аутентификация</h1>
        
        <div id="messages"></div>
        
        <!-- Индикатор работы JavaScript -->
        <div id="js-status" style="background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 4px;">
            <strong>Статус JavaScript:</strong> <span id="js-indicator">Загрузка...</span>
        </div>
        
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
        
        <h2>Токены</h2>
        <div id="tokens" class="token-display" style="display: none;">
            <strong>Access Token:</strong><br>
            <span id="access_token"></span><br><br>
            <strong>Refresh Token:</strong><br>
            <span id="refresh_token"></span>
        </div>
        
        <h2>Профиль</h2>
        <button onclick="checkProfile()">Проверить профиль</button>
        <button onclick="refreshToken()">Обновить токен</button>
        <button onclick="logout()">Выйти</button>
        
        <h2>Тестирование</h2>
        <button onclick="testUrlParams()">Тест URL параметров</button>
        <button onclick="fillTestData()">Заполнить тестовые данные</button>
        
        <script>
            console.log('JWT Auth script loaded'); // Отладка
            
            // Обновляем индикатор JavaScript
            document.addEventListener('DOMContentLoaded', function() {
                const jsIndicator = document.getElementById('js-indicator');
                if (jsIndicator) {
                    jsIndicator.textContent = '✅ JavaScript работает!';
                    jsIndicator.style.color = 'green';
                }
            });
            
            let accessToken = null;
            let refreshTokenValue = null;
            
            function showMessage(message, type) {
                console.log('showMessage called:', message, type); // Отладка
                const messagesDiv = document.getElementById('messages');
                if (!messagesDiv) {
                    console.error('Messages div not found!');
                    return;
                }
                
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
            
            // Тест функции showMessage
            setTimeout(() => {
                console.log('Testing showMessage function');
                showMessage('🔧 JavaScript загружен и работает!', 'info');
            }, 1000);
            
            // Функция для получения параметров из URL
            function getUrlParams() {
                const urlParams = new URLSearchParams(window.location.search);
                return {
                    email: urlParams.get('email'),
                    password: urlParams.get('password')
                };
            }
            
            // Автоматическое заполнение форм из URL параметров
            function fillFormsFromUrl() {
                const params = getUrlParams();
                console.log('URL params:', params); // Отладка
                
                if (params.email) {
                    // Заполняем поля email в обеих формах
                    const regEmailField = document.getElementById('reg_email');
                    const loginEmailField = document.getElementById('login_email');
                    
                    if (regEmailField) {
                        regEmailField.value = params.email;
                        console.log('Filled reg_email with:', params.email);
                    }
                    if (loginEmailField) {
                        loginEmailField.value = params.email;
                        console.log('Filled login_email with:', params.email);
                    }
                }
                
                if (params.password) {
                    // Заполняем поля пароля в обеих формах
                    const regPasswordField = document.getElementById('reg_password');
                    const loginPasswordField = document.getElementById('login_password');
                    
                    if (regPasswordField) {
                        regPasswordField.value = params.password;
                        console.log('Filled reg_password');
                    }
                    if (loginPasswordField) {
                        loginPasswordField.value = params.password;
                        console.log('Filled login_password');
                    }
                }
                
                // Показываем сообщение о том, что формы заполнены
                if (params.email || params.password) {
                    showMessage('📝 Формы заполнены из URL параметров', 'info');
                }
            }
            
            // Автоматический вход, если переданы данные в URL
            async function autoLoginFromUrl() {
                const params = getUrlParams();
                if (params.email && params.password) {
                    console.log('Attempting auto-login with URL params');
                    showMessage('🔄 Попытка автоматического входа...', 'info');
                    
                    try {
                        const response = await fetch('/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                email: params.email, 
                                password: params.password 
                            })
                        });
                        
                        const result = await response.json();
                        
                        if (response.ok) {
                            showMessage('🎉 Автоматический вход выполнен успешно!', 'success');
                            showTokens(result);
                            await checkProfile();
                            
                            // Очищаем URL от параметров после успешного входа
                            window.history.replaceState({}, document.title, window.location.pathname);
                        } else {
                            showMessage(`❌ Автоматический вход не удался: ${result.detail}`, 'error');
                        }
                    } catch (error) {
                        console.error('Auto-login error:', error);
                        showMessage(`❌ Ошибка автоматического входа: ${error.message}`, 'error');
                    }
                }
            }
            
            // Вызываем заполнение форм при загрузке страницы
            document.addEventListener('DOMContentLoaded', function() {
                console.log('DOM loaded, filling forms from URL');
                fillFormsFromUrl();
                
                // Пытаемся автоматически войти, если переданы данные
                setTimeout(autoLoginFromUrl, 1500); // Небольшая задержка для загрузки интерфейса
            });
            
            function updateAuthStatus(isAuthenticated, userInfo = null) {
                const statusDiv = document.getElementById('auth-status');
                const userInfoDiv = document.getElementById('user-info');
                
                if (isAuthenticated && userInfo) {
                    statusDiv.className = 'auth-status authenticated';
                    statusDiv.innerHTML = '✅ Авторизован';
                    
                    userInfoDiv.style.display = 'block';
                    document.getElementById('user-email').textContent = userInfo.email;
                    document.getElementById('user-id').textContent = userInfo.id;
                    document.getElementById('user-created').textContent = new Date(userInfo.created_at).toLocaleString('ru-RU');
                } else {
                    statusDiv.className = 'auth-status not-authenticated';
                    statusDiv.innerHTML = '🔒 Не авторизован';
                    
                    userInfoDiv.style.display = 'none';
                }
            }
            
            function showTokens(tokens) {
                accessToken = tokens.access_token;
                refreshTokenValue = tokens.refresh_token;
                document.getElementById('access_token').textContent = tokens.access_token;
                document.getElementById('refresh_token').textContent = tokens.refresh_token;
                document.getElementById('tokens').style.display = 'block';
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
                console.log('Register form submitted'); // Отладка
                setLoading('registerForm', true);
                
                try {
                    const formData = new FormData(e.target);
                    const email = formData.get('email');
                    const password = formData.get('password');
                    
                    console.log('Form data extracted:', { email, password: password ? '***' : 'empty' }); // Отладка
                    console.log('Email type:', typeof email, 'Password type:', typeof password); // Отладка
                    
                    // Проверяем валидность данных
                    if (!email || !password) {
                        showMessage('❌ Пожалуйста, заполните все поля', 'error');
                        return;
                    }
                    
                    const requestData = { email, password };
                    console.log('Sending register request:', requestData); // Отладка
                    
                    const response = await fetch('/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestData)
                    });
                    
                    console.log('Register response status:', response.status); // Отладка
                    const result = await response.json();
                    console.log('Register response:', result); // Отладка
                    
                    if (response.ok) {
                        showMessage('🎉 Регистрация успешна! Теперь вы можете войти в систему.', 'success');
                        e.target.reset();
                    } else {
                        if (response.status === 422) {
                            console.error('Validation error:', result);
                            showMessage(`❌ Ошибка валидации: ${JSON.stringify(result)}`, 'error');
                        } else {
                            showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                        }
                    }
                } catch (error) {
                    console.error('Register error:', error); // Отладка
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                } finally {
                    setLoading('registerForm', false);
                }
            };
            
            document.getElementById('loginForm').onsubmit = async (e) => {
                e.preventDefault();
                console.log('Login form submitted');
                setLoading('loginForm', true);
                
                try {
                    const formData = new FormData(e.target);
                    const email = formData.get('email');
                    const password = formData.get('password');
                    
                    console.log('Login form data extracted:', { email, password: password ? '***' : 'empty' }); // Отладка
                    
                    // Проверяем валидность данных
                    if (!email || !password) {
                        showMessage('❌ Пожалуйста, заполните все поля', 'error');
                        return;
                    }
                    
                    const requestData = { email, password };
                    console.log('Sending login request:', requestData); // Отладка
                    
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestData)
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        showMessage('🎉 Вход выполнен успешно!', 'success');
                        showTokens(result);
                        e.target.reset();
                        
                        // 🔥 Автоматически проверяем профиль и обновляем UI
                        await checkProfile(); // ← вот это главное!
                    } else {
                        if (response.status === 422) {
                            console.error('Login validation error:', result);
                            showMessage(`❌ Ошибка валидации: ${JSON.stringify(result)}`, 'error');
                        } else {
                            showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                        }
                    }
                } catch (error) {
                    console.error('Login error:', error);
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                } finally {
                    setLoading('loginForm', false);
                }
            };
            
            async function checkProfile() {
                console.log('checkProfile called, accessToken:', accessToken ? 'exists' : 'null'); // Отладка
                if (!accessToken) {
                    showMessage('❌ Сначала войдите в систему', 'error');
                    return;
                }
                
                try {
                    console.log('Sending profile request with token:', accessToken.substring(0, 20) + '...'); // Отладка
                    const response = await fetch('/profile', {
                        headers: { 'Authorization': `Bearer ${accessToken}` }
                    });
                    
                    console.log('Profile response status:', response.status); // Отладка
                    const result = await response.json();
                    console.log('Profile response:', result); // Отладка
                    
                    if (response.ok) {
                        updateAuthStatus(true, result);
                        showMessage(`👋 Добро пожаловать, ${result.email}!`, 'info');
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                        if (response.status === 401) {
                            console.log('Token expired, clearing state'); // Отладка
                            accessToken = null;
                            refreshTokenValue = null;
                            document.getElementById('tokens').style.display = 'none';
                            updateAuthStatus(false);
                        }
                    }
                } catch (error) {
                    console.error('Profile error:', error); // Отладка
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                }
            }
            
            async function refreshToken() {
                console.log('refreshToken called, refreshTokenValue:', refreshTokenValue ? 'exists' : 'null'); // Отладка
                if (!refreshTokenValue) {
                    showMessage('❌ Нет refresh токена', 'error');
                    return;
                }
                
                try {
                    console.log('Sending refresh request'); // Отладка
                    const response = await fetch('/refresh', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ refresh_token: refreshTokenValue })
                    });
                    
                    console.log('Refresh response status:', response.status); // Отладка
                    const result = await response.json();
                    console.log('Refresh response:', result); // Отладка
                    
                    if (response.ok) {
                        showMessage('🔄 Токен обновлен успешно!', 'success');
                        showTokens(result);
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                        if (response.status === 401) {
                            console.log('Refresh token expired, clearing state'); // Отладка
                            accessToken = null;
                            refreshTokenValue = null;
                            document.getElementById('tokens').style.display = 'none';
                            updateAuthStatus(false);
                        }
                    }
                } catch (error) {
                    console.error('Refresh error:', error); // Отладка
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                }
            }
            
            async function logout() {
                console.log('logout called, refreshTokenValue:', refreshTokenValue ? 'exists' : 'null'); // Отладка
                if (!refreshTokenValue) {
                    showMessage('❌ Нет токена для выхода', 'error');
                    return;
                }
                
                try {
                    console.log('Sending logout request'); // Отладка
                    const response = await fetch('/logout', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ refresh_token: refreshTokenValue })
                    });
                    
                    console.log('Logout response status:', response.status); // Отладка
                    const result = await response.json();
                    console.log('Logout response:', result); // Отладка
                    
                    if (response.ok) {
                        showMessage('👋 Выход выполнен успешно!', 'success');
                        accessToken = null;
                        refreshTokenValue = null;
                        document.getElementById('tokens').style.display = 'none';
                        updateAuthStatus(false);
                    } else {
                        showMessage(`❌ Ошибка: ${result.detail}`, 'error');
                    }
                } catch (error) {
                    console.error('Logout error:', error); // Отладка
                    showMessage(`❌ Ошибка сети: ${error.message}`, 'error');
                }
            }
            
            // Функции для тестирования
            function testUrlParams() {
                console.log('testUrlParams called');
                const params = getUrlParams();
                console.log('Current URL params:', params);
                showMessage(`📋 URL параметры: email=${params.email || 'не задан'}, password=${params.password ? 'задан' : 'не задан'}`, 'info');
            }
            
            function fillTestData() {
                console.log('fillTestData called');
                document.getElementById('reg_email').value = 'test@example.com';
                document.getElementById('reg_password').value = 'testpass123';
                document.getElementById('login_email').value = 'test@example.com';
                document.getElementById('login_password').value = 'testpass123';
                showMessage('📝 Заполнены тестовые данные', 'info');
            }
            
            // Проверяем, что все функции определены
            window.addEventListener('load', function() {
                console.log('Page loaded, checking functions...');
                console.log('showMessage defined:', typeof showMessage === 'function');
                console.log('testUrlParams defined:', typeof testUrlParams === 'function');
                console.log('fillTestData defined:', typeof fillTestData === 'function');
                console.log('checkProfile defined:', typeof checkProfile === 'function');
                console.log('refreshToken defined:', typeof refreshToken === 'function');
                console.log('logout defined:', typeof logout === 'function');
                
                // Простая проверка работы JavaScript
                if (typeof showMessage === 'function') {
                    console.log('✅ All functions loaded successfully');
                    showMessage('✅ JavaScript полностью загружен и готов к работе!', 'success');
                } else {
                    console.error('❌ Some functions failed to load');
                }
            });
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
        
    Процесс регистрации:
    1. Валидация длины пароля (минимум 6 символов)
    2. Хеширование пароля с помощью bcrypt
    3. Сохранение пользователя в БД
    4. Возврат сообщения об успехе или ошибки
    
    Безопасность:
    - Пароль никогда не сохраняется в открытом виде
    - Email проверяется на уникальность
    - Используется параметризованные SQL запросы
    """
    print(f"Register request received: email={user.email}, password_length={len(user.password)}")  # Отладка
    
    # Проверка минимальной длины пароля
    if len(user.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен содержать минимум 6 символов"
        )
    
    # Создание пользователя в БД (пароль будет захеширован)
    user_id = create_user(user.email, user.password)
    if user_id is None:  # Пользователь с таким email уже существует
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    
    return {"message": "Пользователь успешно зарегистрирован"}

@app.post("/login", response_model=Token)
def login(user: UserLogin):
    """
    Вход пользователя в систему и выдача JWT токенов
    
    Args:
        user: Данные для входа (email и password) из Pydantic схемы
        
    Returns:
        Token: Объект с access_token, refresh_token и token_type
        
    Raises:
        HTTPException: При неверных учетных данных
        
    Процесс входа:
    1. Поиск пользователя по email в БД
    2. Проверка пароля против сохраненного хеша
    3. Создание access токена (короткоживущий)
    4. Создание refresh токена (долгоживущий)
    5. Возврат обоих токенов клиенту
    
    Безопасность:
    - Использует безопасное сравнение паролей
    - Не раскрывает информацию о существовании пользователей
    - Создает токены с ограниченным временем жизни
    """
    print(f"Login request received: email={user.email}, password_length={len(user.password)}")  # Отладка
    
    # Поиск пользователя по email
    user_data = get_user_by_email(user.email)
    if not user_data:  # Пользователь не найден
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
    
    # Создание JWT токенов для авторизованного пользователя
    access_token = create_access_token(data={"sub": user_id})  # Access токен с ID пользователя
    refresh_token = create_refresh_token(user_id)  # Refresh токен для обновления
    
    return {
        "access_token": access_token,    # Короткоживущий токен для API
        "refresh_token": refresh_token,  # Долгоживущий токен для обновления
        "token_type": "bearer"           # Тип токена для клиента
    }

@app.post("/refresh", response_model=Token)
def refresh_token(token_data: TokenRefresh):
    """
    Обновление access токена с помощью refresh токена
    
    Args:
        token_data: Объект с refresh_token из Pydantic схемы
        
    Returns:
        Token: Новый access_token и тот же refresh_token
        
    Raises:
        HTTPException: При невалидном или истекшем refresh токене
        
    Процесс обновления:
    1. Проверка валидности refresh токена
    2. Извлечение ID пользователя из токена
    3. Создание нового access токена
    4. Возврат нового access токена (refresh остается тот же)
    
    Безопасность:
    - Refresh токен проверяется против хешей в БД
    - Проверяется время истечения токена
    - Возвращается только новый access токен
    """
    # Проверяем refresh токен и получаем ID пользователя
    user_id = verify_refresh_token(token_data.refresh_token)
    if user_id is None:  # Токен невалиден или истек
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный refresh токен"
        )
    
    # Создание нового access токена для пользователя
    access_token = create_access_token(data={"sub": user_id})
    
    return {
        "access_token": access_token,                    # Новый access токен
        "refresh_token": token_data.refresh_token,       # Тот же refresh токен
        "token_type": "bearer"                           # Тип токена
    }

@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: int = Depends(get_current_user)):
    """
    Получение информации о профиле текущего пользователя (защищенный маршрут)
    
    Args:
        current_user: ID пользователя из JWT токена (автоматически извлекается)
        
    Returns:
        UserResponse: Информация о пользователе (id, email, created_at)
        
    Raises:
        HTTPException: При невалидном токене или отсутствии пользователя
        
    Особенности:
    - Требует валидный access токен в заголовке Authorization
    - Автоматически проверяет токен через зависимость get_current_user
    - Возвращает только публичную информацию о пользователе
    - Не возвращает хеш пароля или другие чувствительные данные
    """
    # Подключение к БД для получения информации о пользователе
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    # Параметризованный запрос для получения публичной информации
    cursor.execute('SELECT id, email, created_at FROM users WHERE id = ?', (current_user,))
    user = cursor.fetchone()  # Получение данных пользователя
    conn.close()  # Закрытие соединения
    
    if not user:  # Пользователь не найден (маловероятно, но возможно)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    
    # Распаковка данных пользователя
    user_id, email, created_at = user
    return UserResponse(
        id=user_id,           # ID пользователя
        email=email,          # Email пользователя
        created_at=created_at # Дата регистрации
    )

@app.post("/logout", response_model=dict)
def logout(token_data: TokenRefresh):
    """
    Выход пользователя из системы (отзыв refresh токена)
    
    Args:
        token_data: Объект с refresh_token для отзыва
        
    Returns:
        dict: Сообщение об успешном выходе
        
    Процесс выхода:
    1. Получает refresh токен от клиента
    2. Отзывает токен (удаляет из БД)
    3. Возвращает подтверждение выхода
    
    Безопасность:
    - Access токены истекают автоматически (не требуют отзыва)
    - Refresh токен удаляется из БД (мгновенный отзыв)
    - Клиент должен удалить токены из локального хранилища
    """
    # Отзыв refresh токена (удаление из БД)
    revoke_refresh_token(token_data.refresh_token)
    return {"message": "Выход выполнен успешно"}

@app.get("/test-js", response_class=HTMLResponse)
def test_javascript():
    """
    Тестовая страница для проверки работы JavaScript
    
    Возвращает HTML страницу с:
    - Индикатором работы JavaScript
    - Кнопками для тестирования функций
    - Подробными логами в консоль браузера
    - Проверкой всех основных функций
    
    Используется для:
    - Диагностики проблем с JavaScript
    - Тестирования функций перед использованием
    - Демонстрации работы системы
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>JavaScript Test</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; margin: 5px; }
            button:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <h1>🧪 Тест JavaScript</h1>
        
        <div id="messages"></div>
        
        <div id="js-status" style="background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 4px;">
            <strong>Статус JavaScript:</strong> <span id="js-indicator">Загрузка...</span>
        </div>
        
        <h2>Тестирование функций</h2>
        <button onclick="testFunction()">Тест кнопки</button>
        <button onclick="testMessage()">Тест сообщений</button>
        <button onclick="testUrlParams()">Тест URL параметров</button>
        
        <h2>Информация</h2>
        <p>Эта страница предназначена для тестирования работы JavaScript в приложении.</p>
        <p>Если все кнопки работают и появляются сообщения, значит JavaScript функционирует корректно.</p>
        
        <script>
            console.log('Test JavaScript loaded');
            
            function showMessage(message, type) {
                console.log('showMessage called:', message, type);
                const messagesDiv = document.getElementById('messages');
                if (!messagesDiv) {
                    console.error('Messages div not found!');
                    return;
                }
                
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
            
            function testFunction() {
                console.log('testFunction called');
                showMessage('✅ Кнопка работает! JavaScript функционирует корректно.', 'success');
            }
            
            function testMessage() {
                console.log('testMessage called');
                showMessage('📝 Тест сообщений: это информационное сообщение', 'info');
                setTimeout(() => {
                    showMessage('❌ Тест сообщений: это сообщение об ошибке', 'error');
                }, 1000);
            }
            
            function testUrlParams() {
                console.log('testUrlParams called');
                const urlParams = new URLSearchParams(window.location.search);
                const email = urlParams.get('email');
                const password = urlParams.get('password');
                showMessage(`📋 URL параметры: email=${email || 'не задан'}, password=${password ? 'задан' : 'не задан'}`, 'info');
            }
            
            document.addEventListener('DOMContentLoaded', function() {
                const jsIndicator = document.getElementById('js-indicator');
                if (jsIndicator) {
                    jsIndicator.textContent = '✅ JavaScript работает!';
                    jsIndicator.style.color = 'green';
                }
                console.log('DOM loaded');
                showMessage('🔧 JavaScript загружен и готов к работе!', 'success');
            });
        </script>
    </body>
    </html>
    """
    return html

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
    init_db()
    
    # Информационные сообщения для пользователя
    print("Запуск сервера JWT аутентификации...")
    print("Откройте http://localhost:8000 в браузере")
    print("API документация: http://localhost:8000/docs")
    print("Тест JavaScript: http://localhost:8000/test-js")
    
    # Запуск ASGI сервера
    # host="0.0.0.0" - доступ со всех интерфейсов
    # port=8000 - порт для HTTP соединений
    uvicorn.run(app, host="0.0.0.0", port=8000)
