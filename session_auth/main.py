"""
Сессионная аутентификация с Flask
Использует серверные сессии, хранящиеся в Redis
"""

from flask import Flask, request, jsonify, session, render_template_string
from flask_session import Session
import redis
import bcrypt
import sqlite3
import os
from datetime import timedelta
import uuid

app = Flask(__name__)

# Конфигурация Flask-Session с Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Инициализация сессий
Session(app)

# Инициализация базы данных
def init_db():
    """Создание таблицы пользователей"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    """Хеширование пароля с солью"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, password_hash):
    """Проверка пароля"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash)

def get_user_by_email(email):
    """Получение пользователя по email"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, password_hash FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email, password):
    """Создание нового пользователя"""
    password_hash = hash_password(password)
    conn = sqlite3.connect('users.db')
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

@app.route('/')
def index():
    """Главная страница с формами"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Сессионная Аутентификация</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; }
            input[type="email"], input[type="password"] { width: 100%; padding: 8px; margin-bottom: 10px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            button:hover { background: #0056b3; }
            .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        </style>
    </head>
    <body>
        <h1>Сессионная Аутентификация</h1>
        
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
        
        <h2>Профиль</h2>
        <button onclick="checkProfile()">Проверить профиль</button>
        <button onclick="logout()">Выйти</button>
        
        <script>
            function showMessage(message, type) {
                const div = document.createElement('div');
                div.className = `message ${type}`;
                div.textContent = message;
                document.getElementById('messages').appendChild(div);
                setTimeout(() => div.remove(), 5000);
            }
            
            document.getElementById('registerForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const response = await fetch('/register', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (result.success) {
                    showMessage('Регистрация успешна!', 'success');
                } else {
                    showMessage(result.message, 'error');
                }
            };
            
            document.getElementById('loginForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (result.success) {
                    showMessage('Вход выполнен!', 'success');
                } else {
                    showMessage(result.message, 'error');
                }
            };
            
            async function checkProfile() {
                const response = await fetch('/profile');
                const result = await response.json();
                if (result.success) {
                    showMessage(`Добро пожаловать, ${result.user.email}!`, 'info');
                } else {
                    showMessage(result.message, 'error');
                }
            }
            
            async function logout() {
                const response = await fetch('/logout', { method: 'POST' });
                const result = await response.json();
                if (result.success) {
                    showMessage('Выход выполнен!', 'success');
                }
            }
        </script>
    </body>
    </html>
    """
    return html

@app.route('/register', methods=['POST'])
def register():
    """Регистрация нового пользователя"""
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email и пароль обязательны'})
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Пароль должен содержать минимум 6 символов'})
    
    user_id = create_user(email, password)
    if user_id is None:
        return jsonify({'success': False, 'message': 'Пользователь с таким email уже существует'})
    
    return jsonify({'success': True, 'message': 'Пользователь успешно зарегистрирован'})

@app.route('/login', methods=['POST'])
def login():
    """Вход пользователя"""
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email и пароль обязательны'})
    
    user = get_user_by_email(email)
    if not user:
        return jsonify({'success': False, 'message': 'Неверный email или пароль'})
    
    user_id, user_email, password_hash = user
    
    if not verify_password(password, password_hash):
        return jsonify({'success': False, 'message': 'Неверный email или пароль'})
    
    # Создание сессии
    session['user_id'] = user_id
    session['email'] = user_email
    session.permanent = True
    
    return jsonify({'success': True, 'message': 'Вход выполнен успешно'})

@app.route('/profile')
def profile():
    """Защищённый маршрут профиля"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Необходима авторизация'})
    
    return jsonify({
        'success': True,
        'user': {
            'id': session['user_id'],
            'email': session['email']
        }
    })

@app.route('/logout', methods=['POST'])
def logout():
    """Выход из системы"""
    session.clear()
    return jsonify({'success': True, 'message': 'Выход выполнен успешно'})

if __name__ == '__main__':
    init_db()
    print("Запуск сервера сессионной аутентификации...")
    print("Откройте http://localhost:5000 в браузере")
    app.run(debug=True, host='0.0.0.0', port=5000)
