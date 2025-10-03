"""
OAuth 2.0 аутентификация с Яндекс
Использует Яндекс как Identity Provider
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import httpx
import urllib.parse

app = FastAPI(title="OAuth 2.0 Authentication", version="1.0.0")

# Монтирование статических файлов
app.mount("/static", StaticFiles(directory="static"), name="static")

# Конфигурация OAuth 2.0 для Яндекса
YANDEX_CLIENT_ID = "your-secret-key-change-in-production"  # Замените на ваш Client ID
YANDEX_CLIENT_SECRET = "your-secret-key-change-in-production"  # Замените на ваш Client Secret
SECRET_KEY = "your-secret-key-change-in-production"  # В продакшене используйте переменную окружения

# URLs для Яндекс OAuth 2.0
YANDEX_AUTH_URL = "https://oauth.yandex.ru/authorize"
YANDEX_TOKEN_URL = "https://oauth.yandex.ru/token"
YANDEX_USER_INFO_URL = "https://login.yandex.ru/info"
REDIRECT_URI = "http://localhost:8000/auth/yandex/callback"

# Схемы данных
class UserResponse(BaseModel):
    id: int
    yandex_id: str
    email: str
    name: str
    picture: Optional[str]
    created_at: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Инициализация базы данных
def init_db():
    """Создание таблицы пользователей"""
    conn = sqlite3.connect('oauth_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            yandex_id TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            name TEXT NOT NULL,
            picture TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_or_create_user(yandex_user_info: dict) -> tuple:
    """Получение или создание пользователя из Яндекс данных"""
    yandex_id = yandex_user_info.get('id')
    email = yandex_user_info.get('default_email')
    name = yandex_user_info.get('real_name', yandex_user_info.get('display_name', ''))
    picture = yandex_user_info.get('default_avatar_id')
    
    conn = sqlite3.connect('oauth_users.db')
    cursor = conn.cursor()
    
    # Проверяем, существует ли пользователь
    cursor.execute('SELECT id, yandex_id, email, name, picture, created_at FROM users WHERE yandex_id = ?', (yandex_id,))
    user = cursor.fetchone()
    
    if user:
        conn.close()
        return user
    
    # Создаем нового пользователя
    cursor.execute('''
        INSERT INTO users (yandex_id, email, name, picture) 
        VALUES (?, ?, ?, ?)
    ''', (yandex_id, email, name, picture))
    
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    
    return (user_id, yandex_id, email, name, picture, datetime.now().isoformat())

def create_access_token(user_id: int) -> str:
    """Создание access токена для авторизованного пользователя"""
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "type": "access"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_access_token(token: str) -> Optional[int]:
    """Проверка access токена"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

# Зависимость для проверки токена
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Получение текущего пользователя из access токена"""
    user_id = verify_access_token(credentials.credentials)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    return user_id

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Главная страница с кнопкой входа через Google"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth 2.0 Аутентификация</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
            .google-btn { 
                background: #4285f4; color: white; padding: 15px 30px; border: none; 
                border-radius: 5px; cursor: pointer; font-size: 16px; margin: 20px;
                text-decoration: none; display: inline-block;
            }
            .google-btn:hover { background: #3367d6; }
            .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            .user-info { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .profile-pic { width: 100px; height: 100px; border-radius: 50%; margin: 10px; }
            button { background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; margin: 10px; }
            button:hover { background: #c82333; }
        </style>
    </head>
    <body>
        <h1>OAuth 2.0 Аутентификация</h1>
        <h2>Вход через Яндекс</h2>
        
        <div id="messages"></div>
        
        <div id="login-section">
            <a href="/auth/yandex" class="google-btn">Войти через Яндекс</a>
        </div>
        
        <div id="user-section" style="display: none;">
            <div class="user-info">
                <img id="profile-pic" class="profile-pic" src="" alt="Profile Picture">
                <h3 id="user-name"></h3>
                <p id="user-email"></p>
                <button onclick="checkProfile()">Проверить профиль</button>
                <button onclick="logout()">Выйти</button>
            </div>
        </div>
        
        <script>
            let accessToken = null;
            let isLoading = false;
            let userData = null;
            
            function showMessage(message, type) {
                const div = document.createElement('div');
                div.className = `message ${type}`;
                div.textContent = message;
                document.getElementById('messages').appendChild(div);
                setTimeout(() => div.remove(), 5000);
            }
            
            function showUserInfo(user) {
                document.getElementById('profile-pic').src = user.picture || '/static/default-avatar.svg';
                document.getElementById('user-name').textContent = user.name;
                document.getElementById('user-email').textContent = user.email;
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('user-section').style.display = 'block';
                userData = user; // Кешируем данные пользователя
            }
            
            // Проверяем, есть ли токен в localStorage
            window.onload = function() {
                const token = localStorage.getItem('access_token');
                if (token) {
                    accessToken = token;
                    checkProfile();
                }
            };
            
            async function checkProfile() {
                if (!accessToken) {
                    showMessage('Сначала войдите через Яндекс', 'error');
                    return;
                }
                
                // Предотвращаем повторные запросы
                if (isLoading) {
                    return;
                }
                
                // Если данные уже загружены, показываем их
                if (userData) {
                    showUserInfo(userData);
                    return;
                }
                
                isLoading = true;
                
                try {
                    const response = await fetch('/profile', {
                        headers: { 'Authorization': `Bearer ${accessToken}` }
                    });
                    const result = await response.json();
                    if (response.ok) {
                        showUserInfo(result);
                        showMessage(`Добро пожаловать, ${result.name}!`, 'info');
                    } else {
                        showMessage(result.detail, 'error');
                        localStorage.removeItem('access_token');
                        accessToken = null;
                        userData = null;
                    }
                } catch (error) {
                    showMessage('Ошибка загрузки профиля', 'error');
                } finally {
                    isLoading = false;
                }
            }
            
            async function logout() {
                localStorage.removeItem('access_token');
                accessToken = null;
                userData = null;
                document.getElementById('login-section').style.display = 'block';
                document.getElementById('user-section').style.display = 'none';
                showMessage('Выход выполнен!', 'success');
            }
            
            // Обработка callback от Яндекс
            const urlParams = new URLSearchParams(window.location.search);
            const token = urlParams.get('token');
            if (token) {
                localStorage.setItem('access_token', token);
                accessToken = token;
                window.history.replaceState({}, document.title, window.location.pathname);
                checkProfile();
            }
        </script>
    </body>
    </html>
    """
    return html

@app.get("/auth/yandex")
async def yandex_auth():
    """Инициация OAuth 2.0 flow с Яндекс"""
    params = {
        'response_type': 'code',
        'client_id': YANDEX_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'login:email login:info'
    }
    
    auth_url = f"{YANDEX_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=auth_url)

@app.get("/auth/yandex/callback")
async def yandex_callback(request: Request):
    """Обработка callback от Яндекса"""
    try:
        code = request.query_params.get('code')
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Отсутствует код авторизации"
            )
        
        # Обмен кода на access токен
        async with httpx.AsyncClient() as client:
            token_data = {
                'grant_type': 'authorization_code',
                'code': code,
                'client_id': YANDEX_CLIENT_ID,
                'client_secret': YANDEX_CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
            }
            
            token_response = await client.post(
                YANDEX_TOKEN_URL,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if token_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Не удалось получить access токен"
                )
            
            token_info = token_response.json()
            access_token = token_info.get('access_token')
            
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Access токен не найден в ответе"
                )
            
            # Получение информации о пользователе
            user_response = await client.get(
                YANDEX_USER_INFO_URL,
                headers={'Authorization': f'OAuth {access_token}'}
            )
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Не удалось получить информацию о пользователе"
                )
            
            user_info = user_response.json()
        
        # Получаем или создаем пользователя
        user = get_or_create_user(user_info)
        user_id, yandex_id, email, name, picture, created_at = user
        
        # Создаем access токен
        jwt_token = create_access_token(user_id)
        
        # Перенаправляем на главную страницу с токеном
        return RedirectResponse(
            url=f"/?token={jwt_token}",
            status_code=status.HTTP_302_FOUND
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ошибка аутентификации: {str(e)}"
        )

@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: int = Depends(get_current_user)):
    """Защищённый маршрут профиля"""
    conn = sqlite3.connect('oauth_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, yandex_id, email, name, picture, created_at 
        FROM users WHERE id = ?
    ''', (current_user,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    
    user_id, yandex_id, email, name, picture, created_at = user
    return UserResponse(
        id=user_id,
        yandex_id=yandex_id,
        email=email,
        name=name,
        picture=picture,
        created_at=created_at
    )

@app.post("/logout", response_model=dict)
def logout():
    """Выход из системы"""
    # В OAuth 2.0 обычно токены отзываются на стороне провайдера
    # Здесь мы просто возвращаем успешный ответ
    return {"message": "Выход выполнен успешно"}

if __name__ == "__main__":
    import uvicorn
    init_db()
    print("Запуск сервера OAuth 2.0 аутентификации с Яндекс...")
    print("Откройте http://localhost:8000 в браузере")
    print("API документация: http://localhost:8000/docs")
    print("\nВАЖНО: Настройте Яндекс OAuth 2.0:")
    print("1. Перейдите на https://oauth.yandex.ru/client/new")
    print("2. Создайте новое приложение")
    print("3. Выберите платформу 'Веб-сервисы'")
    print("4. Добавьте redirect URI: http://localhost:8000/auth/yandex/callback")
    print("5. Выберите права доступа: login:email, login:info")
    print("6. Обновите YANDEX_CLIENT_ID и YANDEX_CLIENT_SECRET в коде")
    uvicorn.run(app, host="0.0.0.0", port=8000)
