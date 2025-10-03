"""
JWT Аутентификация с FastAPI
Stateless аутентификация с JSON Web Tokens
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
import jwt
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
import secrets

app = FastAPI(title="JWT Authentication", version="1.0.0")

# Конфигурация JWT
SECRET_KEY = "your-secret-key-change-in-production"  # В продакшене используйте переменную окружения
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Схемы данных
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenRefresh(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    email: str
    created_at: str

# Инициализация базы данных
def init_db():
    """Создание таблиц пользователей и refresh токенов"""
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

def hash_password(password: str) -> str:
    """Хеширование пароля с солью"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Проверка пароля"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def get_user_by_email(email: str) -> Optional[tuple]:
    """Получение пользователя по email"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, password_hash, created_at FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email: str, password: str) -> Optional[int]:
    """Создание нового пользователя"""
    password_hash = hash_password(password)
    conn = sqlite3.connect('jwt_users.db')
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

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Создание access токена"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(user_id: int) -> str:
    """Создание refresh токена"""
    token = secrets.token_urlsafe(32)
    token_hash = hash_password(token)
    
    # Сохранение refresh токена в БД
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    cursor.execute('''
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at) 
        VALUES (?, ?, ?)
    ''', (user_id, token_hash, expires_at))
    conn.commit()
    conn.close()
    
    return token

def verify_refresh_token(token: str) -> Optional[int]:
    """Проверка refresh токена"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    
    # Получаем все активные refresh токены
    cursor.execute('''
        SELECT user_id, token_hash FROM refresh_tokens 
        WHERE expires_at > datetime('now')
    ''')
    tokens = cursor.fetchall()
    conn.close()
    
    # Проверяем токен
    for user_id, token_hash in tokens:
        if verify_password(token, token_hash):
            return user_id
    
    return None

def revoke_refresh_token(token: str):
    """Отзыв refresh токена"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    
    # Получаем все активные refresh токены
    cursor.execute('''
        SELECT id, token_hash FROM refresh_tokens 
        WHERE expires_at > datetime('now')
    ''')
    tokens = cursor.fetchall()
    
    # Удаляем соответствующий токен
    for token_id, token_hash in tokens:
        if verify_password(token, token_hash):
            cursor.execute('DELETE FROM refresh_tokens WHERE id = ?', (token_id,))
            break
    
    conn.commit()
    conn.close()

# Зависимость для проверки токена
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Получение текущего пользователя из JWT токена"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Проверяем тип токена
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Главная страница с формами"""
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
            .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            .token-display { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; word-break: break-all; }
        </style>
    </head>
    <body>
        <h1>JWT Аутентификация</h1>
        
        <div id="messages"></div>
        
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
        
        <script>
            let accessToken = null;
            let refreshToken = null;
            
            function showMessage(message, type) {
                const div = document.createElement('div');
                div.className = `message ${type}`;
                div.textContent = message;
                document.getElementById('messages').appendChild(div);
                setTimeout(() => div.remove(), 5000);
            }
            
            function showTokens(tokens) {
                accessToken = tokens.access_token;
                refreshToken = tokens.refresh_token;
                document.getElementById('access_token').textContent = tokens.access_token;
                document.getElementById('refresh_token').textContent = tokens.refresh_token;
                document.getElementById('tokens').style.display = 'block';
            }
            
            document.getElementById('registerForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: formData.get('email'),
                        password: formData.get('password')
                    })
                });
                const result = await response.json();
                if (response.ok) {
                    showMessage('Регистрация успешна!', 'success');
                } else {
                    showMessage(result.detail, 'error');
                }
            };
            
            document.getElementById('loginForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: formData.get('email'),
                        password: formData.get('password')
                    })
                });
                const result = await response.json();
                if (response.ok) {
                    showMessage('Вход выполнен!', 'success');
                    showTokens(result);
                } else {
                    showMessage(result.detail, 'error');
                }
            };
            
            async function checkProfile() {
                if (!accessToken) {
                    showMessage('Сначала войдите в систему', 'error');
                    return;
                }
                
                const response = await fetch('/profile', {
                    headers: { 'Authorization': `Bearer ${accessToken}` }
                });
                const result = await response.json();
                if (response.ok) {
                    showMessage(`Добро пожаловать, ${result.email}!`, 'info');
                } else {
                    showMessage(result.detail, 'error');
                }
            }
            
            async function refreshToken() {
                if (!refreshToken) {
                    showMessage('Нет refresh токена', 'error');
                    return;
                }
                
                const response = await fetch('/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refresh_token: refreshToken })
                });
                const result = await response.json();
                if (response.ok) {
                    showMessage('Токен обновлен!', 'success');
                    showTokens(result);
                } else {
                    showMessage(result.detail, 'error');
                }
            }
            
            async function logout() {
                if (!refreshToken) {
                    showMessage('Нет токена для выхода', 'error');
                    return;
                }
                
                const response = await fetch('/logout', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refresh_token: refreshToken })
                });
                const result = await response.json();
                if (response.ok) {
                    showMessage('Выход выполнен!', 'success');
                    accessToken = null;
                    refreshToken = null;
                    document.getElementById('tokens').style.display = 'none';
                } else {
                    showMessage(result.detail, 'error');
                }
            }
        </script>
    </body>
    </html>
    """
    return html

@app.post("/register", response_model=dict)
def register(user: UserRegister):
    """Регистрация нового пользователя"""
    if len(user.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен содержать минимум 6 символов"
        )
    
    user_id = create_user(user.email, user.password)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    
    return {"message": "Пользователь успешно зарегистрирован"}

@app.post("/login", response_model=Token)
def login(user: UserLogin):
    """Вход пользователя"""
    user_data = get_user_by_email(user.email)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )
    
    user_id, user_email, password_hash, created_at = user_data
    
    if not verify_password(user.password, password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )
    
    # Создание токенов
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(user_id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh", response_model=Token)
def refresh_token(token_data: TokenRefresh):
    """Обновление access токена"""
    user_id = verify_refresh_token(token_data.refresh_token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный refresh токен"
        )
    
    # Создание нового access токена
    access_token = create_access_token(data={"sub": user_id})
    
    return {
        "access_token": access_token,
        "refresh_token": token_data.refresh_token,  # Refresh токен остается тот же
        "token_type": "bearer"
    }

@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: int = Depends(get_current_user)):
    """Защищённый маршрут профиля"""
    conn = sqlite3.connect('jwt_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, created_at FROM users WHERE id = ?', (current_user,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    
    user_id, email, created_at = user
    return UserResponse(
        id=user_id,
        email=email,
        created_at=created_at
    )

@app.post("/logout", response_model=dict)
def logout(token_data: TokenRefresh):
    """Выход из системы (отзыв refresh токена)"""
    revoke_refresh_token(token_data.refresh_token)
    return {"message": "Выход выполнен успешно"}

if __name__ == "__main__":
    import uvicorn
    init_db()
    print("Запуск сервера JWT аутентификации...")
    print("Откройте http://localhost:8000 в браузере")
    print("API документация: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
