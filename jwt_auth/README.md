# JWT Аутентификация - Полное Руководство

## 📋 Содержание
1. [Обзор системы](#обзор-системы)
2. [Архитектура и принципы работы](#архитектура-и-принципы-работы)
3. [Установка и запуск](#установка-и-запуск)
4. [Детальное объяснение кода](#детальное-объяснение-кода)
5. [API Endpoints](#api-endpoints)
6. [Безопасность](#безопасность)
7. [Тестирование](#тестирование)
8. [Развертывание в продакшене](#развертывание-в-продакшене)

## 🎯 Обзор системы

Этот проект представляет собой **полноценную систему аутентификации на основе JWT токенов**, реализованную с использованием FastAPI. Система демонстрирует современные подходы к stateless аутентификации и включает:

- ✅ **Регистрацию и авторизацию** пользователей
- ✅ **Access и Refresh токены** для безопасной работы
- ✅ **Веб-интерфейс** для демонстрации функциональности
- ✅ **REST API** для интеграции с другими приложениями
- ✅ **Автоматическую документацию** FastAPI
- ✅ **Подробные комментарии** к каждой строке кода

## 🏗️ Архитектура и принципы работы

### JWT (JSON Web Token) - что это?

JWT - это стандарт для безопасной передачи информации между сторонами в виде JSON объекта. Токен состоит из трех частей, разделенных точками:

```
header.payload.signature
```

**Пример JWT токена:**
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEsInR5cGUiOiJhY2Nlc3MiLCJleHAiOjE2OTk5OTk5OTl9.signature_hash
```

### Архитектура системы

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   FastAPI       │    │   SQLite DB     │
│   (HTML/JS)     │◄──►│   Backend       │◄──►│   (Users +      │
│                 │    │                 │    │    Tokens)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   Browser       │    │   JWT Tokens    │
│   Storage       │    │   (Access +     │
│   (LocalStorage)│    │    Refresh)     │
└─────────────────┘    └─────────────────┘
```

### Принцип работы JWT аутентификации

1. **Регистрация**: Пользователь создает аккаунт → пароль хешируется → сохраняется в БД
2. **Вход**: Проверка email/пароля → создание access + refresh токенов → возврат токенов
3. **Доступ к API**: Клиент отправляет access токен → сервер проверяет подпись → доступ разрешен
4. **Обновление токена**: Access токен истек → клиент отправляет refresh токен → новый access токен

### Типы токенов

#### Access Token (Короткоживущий)
- **Время жизни**: 30 минут
- **Назначение**: Доступ к защищенным ресурсам
- **Содержит**: ID пользователя, тип токена, время истечения
- **Хранится**: В памяти браузера (JavaScript)

#### Refresh Token (Долгоживущий)
- **Время жизни**: 7 дней
- **Назначение**: Обновление access токенов
- **Содержит**: Случайную строку (хешируется в БД)
- **Хранится**: В памяти браузера + хеш в БД

## 🚀 Установка и запуск

### Требования
- Python 3.8+
- pip (менеджер пакетов Python)

### Пошаговая установка

```bash
# 1. Переход в директорию проекта
cd Primer_auth/jwt_auth

# 2. Создание виртуального окружения
python -m venv venv

# 3. Активация виртуального окружения
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Установка зависимостей
pip install -r requirements.txt

# 5. Запуск сервера
python main.py
```

### Проверка работы

После запуска откройте в браузере:
- **Главная страница**: http://localhost:8000
- **API документация**: http://localhost:8000/docs
- **Тест JavaScript**: http://localhost:8000/test-js

## 🔍 Детальное объяснение кода

### Структура файла main.py

```python
# 1. ИМПОРТЫ И НАСТРОЙКИ
# 2. PYDANTIC СХЕМЫ ДАННЫХ
# 3. ФУНКЦИИ РАБОТЫ С БАЗОЙ ДАННЫХ
# 4. ФУНКЦИИ БЕЗОПАСНОСТИ И ХЕШИРОВАНИЯ
# 5. ФУНКЦИИ РАБОТЫ С JWT ТОКЕНАМИ
# 6. ЗАВИСИМОСТИ И MIDDLEWARE
# 7. HTML ИНТЕРФЕЙС
# 8. API ENDPOINTS
# 9. ЗАПУСК ПРИЛОЖЕНИЯ
```

### 1. Импорты и настройки

```python
# FastAPI компоненты
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

# Валидация данных
from pydantic import BaseModel, EmailStr

# Безопасность и JWT
import jwt  # PyJWT для работы с токенами
import bcrypt  # Хеширование паролей
import secrets  # Криптографически стойкие случайные строки

# База данных и время
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
```

### 2. Pydantic схемы данных

```python
class UserRegister(BaseModel):
    """Схема для регистрации нового пользователя"""
    email: EmailStr  # Автоматическая валидация email
    password: str    # Пароль (будет захеширован)

class UserLogin(BaseModel):
    """Схема для входа пользователя"""
    email: EmailStr
    password: str

class Token(BaseModel):
    """Ответ с токенами после входа"""
    access_token: str   # Короткоживущий токен
    refresh_token: str  # Долгоживущий токен
    token_type: str     # Тип токена ("bearer")
```

### 3. Функции работы с базой данных

#### init_db() - Инициализация БД
```python
def init_db():
    """Создает таблицы users и refresh_tokens"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    
    # Таблица пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Таблица refresh токенов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
```

#### get_user_by_email() - Поиск пользователя
```python
def get_user_by_email(email: str) -> Optional[tuple]:
    """Получает пользователя по email из БД"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, password_hash, created_at FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()  # Возвращает кортеж или None
    conn.close()
    return user
```

#### create_user() - Создание пользователя
```python
def create_user(email: str, password: str) -> Optional[int]:
    """Создает нового пользователя в БД"""
    password_hash = hash_password(password)  # Хешируем пароль
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
                      (email, password_hash))
        conn.commit()
        user_id = cursor.lastrowid  # ID созданного пользователя
        conn.close()
        return user_id
    except sqlite3.IntegrityError:  # Email уже существует
        conn.close()
        return None
```

### 4. Функции безопасности

#### hash_password() - Хеширование пароля
```python
def hash_password(password: str) -> str:
    """Безопасное хеширование с bcrypt"""
    salt = bcrypt.gensalt()  # Генерируем случайную соль
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
```

#### verify_password() - Проверка пароля
```python
def verify_password(password: str, password_hash: str) -> bool:
    """Проверка пароля против хеша"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
```

### 5. Функции работы с JWT токенами

#### create_access_token() - Создание access токена
```python
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Создает JWT access токен"""
    to_encode = data.copy()  # Копируем данные
    
    # Устанавливаем время истечения
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Добавляем время истечения и тип токена
    to_encode.update({"exp": expire, "type": "access"})
    
    # Кодируем токен с секретным ключом
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
```

#### create_refresh_token() - Создание refresh токена
```python
def create_refresh_token(user_id: int) -> str:
    """Создает refresh токен и сохраняет его хеш в БД"""
    # Генерируем криптографически стойкую случайную строку
    token = secrets.token_urlsafe(32)
    token_hash = hash_password(token)  # Хешируем токен для хранения
    
    # Сохраняем в БД
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    cursor.execute('''
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at) 
        VALUES (?, ?, ?)
    ''', (user_id, token_hash, expires_at))
    conn.commit()
    conn.close()
    
    return token  # Возвращаем оригинальный токен (не хеш)
```

#### verify_refresh_token() - Проверка refresh токена
```python
def verify_refresh_token(token: str) -> Optional[int]:
    """Проверяет refresh токен и возвращает user_id"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    
    # Получаем все активные refresh токены
    cursor.execute('''
        SELECT user_id, token_hash FROM refresh_tokens 
        WHERE expires_at > datetime('now')
    ''')
    tokens = cursor.fetchall()
    conn.close()
    
    # Проверяем токен против всех хешей
    for user_id, token_hash in tokens:
        if verify_password(token, token_hash):
            return user_id
    
    return None  # Токен не найден или истек
```

### 6. Зависимости и middleware

#### get_current_user() - Проверка токена
```python
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Извлекает пользователя из JWT токена"""
    try:
        token = credentials.credentials  # Получаем токен из заголовка
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Декодируем
        
        # Проверяем тип токена
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id: int = payload.get("sub")  # ID пользователя
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return user_id
    except jwt.PyJWTError:  # Ошибка декодирования
        raise HTTPException(status_code=401, detail="Invalid token")
```

## 📡 API Endpoints

### POST /register
**Регистрация нового пользователя**

```python
@app.post("/register", response_model=dict)
def register(user: UserRegister):
    """Регистрация нового пользователя"""
    print(f"Register request received: email={user.email}, password_length={len(user.password)}")
    
    # Проверка длины пароля
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Пароль должен содержать минимум 6 символов")
    
    # Создание пользователя
    user_id = create_user(user.email, user.password)
    if user_id is None:
        raise HTTPException(status_code=400, detail="Пользователь с таким email уже существует")
    
    return {"message": "Пользователь успешно зарегистрирован"}
```

**Пример запроса:**
```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

### POST /login
**Вход пользователя в систему**

```python
@app.post("/login", response_model=Token)
def login(user: UserLogin):
    """Вход пользователя"""
    print(f"Login request received: email={user.email}, password_length={len(user.password)}")
    
    # Поиск пользователя
    user_data = get_user_by_email(user.email)
    if not user_data:
        raise HTTPException(status_code=401, detail="Неверный email или пароль")
    
    user_id, user_email, password_hash, created_at = user_data
    
    # Проверка пароля
    if not verify_password(user.password, password_hash):
        raise HTTPException(status_code=401, detail="Неверный email или пароль")
    
    # Создание токенов
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(user_id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }
```

**Пример запроса:**
```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

### POST /refresh
**Обновление access токена**

```python
@app.post("/refresh", response_model=Token)
def refresh_token(token_data: TokenRefresh):
    """Обновление access токена"""
    user_id = verify_refresh_token(token_data.refresh_token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Недействительный refresh токен")
    
    # Создание нового access токена
    access_token = create_access_token(data={"sub": user_id})
    
    return {
        "access_token": access_token,
        "refresh_token": token_data.refresh_token,  # Refresh токен остается тот же
        "token_type": "bearer"
    }
```

### GET /profile
**Получение информации о пользователе (защищенный маршрут)**

```python
@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: int = Depends(get_current_user)):
    """Защищённый маршрут профиля"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, created_at FROM users WHERE id = ?', (current_user,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id, email, created_at = user
    return UserResponse(id=user_id, email=email, created_at=created_at)
```

**Пример запроса:**
```bash
curl http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### POST /logout
**Выход из системы (отзыв refresh токена)**

```python
@app.post("/logout", response_model=dict)
def logout(token_data: TokenRefresh):
    """Выход из системы (отзыв refresh токена)"""
    revoke_refresh_token(token_data.refresh_token)
    return {"message": "Выход выполнен успешно"}
```

## 🔒 Безопасность

### Принципы безопасности, реализованные в системе:

#### 1. Хеширование паролей
- **Алгоритм**: bcrypt с автоматической солью
- **Защита**: От rainbow tables и dictionary attacks
- **Время**: Константное время сравнения (защита от timing attacks)

#### 2. JWT токены
- **Подпись**: HMAC-SHA256 с секретным ключом
- **Время жизни**: Короткие access токены (30 мин) + длинные refresh токены (7 дней)
- **Содержимое**: Минимальная информация (только user_id)

#### 3. Refresh токены
- **Хранение**: Хеш в БД, оригинал у клиента
- **Отзыв**: Возможность мгновенного отзыва через БД
- **Очистка**: Автоматическое удаление истекших токенов

#### 4. Валидация данных
- **Pydantic**: Автоматическая валидация всех входящих данных
- **Email**: Проверка формата email адресов
- **Пароли**: Минимальная длина и проверка на пустоту

#### 5. Защита от атак
- **SQL Injection**: Параметризованные запросы
- **XSS**: Экранирование HTML в интерфейсе
- **CSRF**: Stateless архитектура (нет cookies)

### Рекомендации для продакшена:

```python
# 1. Используйте переменные окружения
import os
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-key")

# 2. Используйте HTTPS
# Настройте SSL сертификаты

# 3. Ограничьте время жизни токенов
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Еще короче
REFRESH_TOKEN_EXPIRE_DAYS = 1     # Короче

# 4. Добавьте rate limiting
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/login")
@limiter.limit("5/minute")  # Максимум 5 попыток в минуту
def login(request: Request, user: UserLogin):
    # ...
```

## 🧪 Тестирование

### Веб-интерфейс
1. Откройте http://localhost:8000
2. Зарегистрируйте нового пользователя
3. Войдите в систему
4. Проверьте профиль
5. Обновите токен
6. Выйдите из системы

### API тестирование с curl

```bash
# 1. Регистрация
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpass123"}'

# 2. Вход
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpass123"}'

# 3. Профиль (замените YOUR_TOKEN на полученный access_token)
curl http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_TOKEN"

# 4. Обновление токена (замените YOUR_REFRESH_TOKEN)
curl -X POST http://localhost:8000/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'

# 5. Выход
curl -X POST http://localhost:8000/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

### Тестирование JavaScript
1. Откройте http://localhost:8000/test-js
2. Проверьте все кнопки
3. Откройте консоль браузера (F12)
4. Убедитесь, что нет ошибок JavaScript

## 🚀 Развертывание в продакшене

### 1. Переменные окружения
```bash
# .env файл
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/dbname
REDIS_URL=redis://localhost:6379
```

### 2. База данных
```python
# Замените SQLite на PostgreSQL
import psycopg2
from sqlalchemy import create_engine

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
```

### 3. HTTPS и безопасность
```python
# Добавьте middleware для HTTPS
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
app.add_middleware(HTTPSRedirectMiddleware)

# Настройте CORS
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 4. Мониторинг и логирование
```python
import logging
from fastapi import Request
import time

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    logging.info(f"{request.method} {request.url} - {response.status_code} - {process_time:.3f}s")
    return response
```

### 5. Docker контейнеризация
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 📚 Дополнительные ресурсы

- [JWT.io](https://jwt.io/) - Отладка JWT токенов
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/) - Официальная документация
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [bcrypt](https://pypi.org/project/bcrypt/) - Документация библиотеки хеширования
- [PyJWT](https://pyjwt.readthedocs.io/) - Документация JWT библиотеки

## 🤝 Вклад в проект

Если вы хотите улучшить проект:

1. Создайте fork репозитория
2. Создайте ветку для новой функции
3. Внесите изменения с подробными комментариями
4. Создайте Pull Request

## 📄 Лицензия

Этот проект создан в образовательных целях и распространяется свободно.

---

**Примечание**: Этот проект создан для демонстрации современных подходов к JWT аутентификации. В продакшене обязательно следуйте лучшим практикам безопасности и используйте проверенные библиотеки.