# Инструкции по запуску Session Authentication

## 🚀 Быстрый старт

### 1. Установка зависимостей

```bash
# Перейдите в папку проекта
cd Primer_auth/session_auth

# Создайте виртуальное окружение
python -m venv venv

# Активируйте виртуальное окружение
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Установите зависимости
pip install -r requirements.txt
```

### 2. Запуск приложения

```bash
python main.py
```

Приложение будет доступно по адресу: **http://localhost:8000**

## 🔧 Смена типа хранилища

### SQLite (по умолчанию)
```python
# В файле main.py
SESSION_STORAGE_TYPE = "sqlite"
```

### Файловое хранилище
```python
# В файле main.py
SESSION_STORAGE_TYPE = "file"
SESSIONS_DIR = "sessions"  # Папка для файлов сессий
```

### In-memory хранилище
```python
# В файле main.py
SESSION_STORAGE_TYPE = "memory"
```

## 📊 Тестирование

### 1. Регистрация пользователя
1. Откройте http://localhost:8000
2. Заполните форму регистрации
3. Нажмите "Зарегистрироваться"

### 2. Вход в систему
1. Заполните форму входа
2. Нажмите "Войти"
3. Сессия будет создана автоматически

### 3. Проверка профиля
1. Нажмите "Проверить профиль"
2. Увидите информацию о пользователе

### 4. Информация о сессии
1. Нажмите "Информация о сессии"
2. Увидите детали текущей сессии

### 5. Выход
1. Нажмите "Выйти"
2. Сессия будет удалена

## 🧪 Тестовые данные

Нажмите кнопку "Заполнить тестовые данные" для автоматического заполнения форм:
- Email: test@example.com
- Пароль: testpass123

## 🔍 Проверка работы

### SQLite хранилище
- Сессии сохраняются в файл `session_users.db`
- Можно открыть файл в SQLite браузере для просмотра

### Файловое хранилище
- Сессии сохраняются в папке `sessions/`
- Каждая сессия - отдельный JSON файл
- Можно открыть файлы для просмотра

### In-memory хранилище
- Сессии хранятся только в памяти
- При перезапуске сервера все сессии теряются

## 🛠 Отладка

### Просмотр логов
```bash
# Запуск с подробными логами
uvicorn main:app --host 0.0.0.0 --port 8000 --log-level debug
```

### Проверка cookies
1. Откройте Developer Tools (F12)
2. Перейдите на вкладку Application/Storage
3. Найдите Cookies для localhost:8000
4. Должен быть cookie с именем `session_id`

### Очистка сессий
- Нажмите кнопку "Очистить истекшие сессии"
- Или удалите файлы в папке `sessions/` (для файлового хранилища)

## 🚨 Устранение проблем

### Ошибка "Сессия не найдена"
- Проверьте, что cookies включены в браузере
- Убедитесь, что cookie `session_id` существует

### Ошибка подключения к базе данных
- Убедитесь, что у приложения есть права на запись в папку
- Проверьте, что SQLite доступен

### Сессии не сохраняются
- Проверьте права на запись в папку `sessions/`
- Убедитесь, что тип хранилища настроен правильно

## 📈 Мониторинг

### Количество активных сессий
```python
# Добавьте в main.py для мониторинга
@app.get("/stats")
def get_stats():
    if SESSION_STORAGE_TYPE == "sqlite":
        conn = sqlite3.connect('session_users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM sessions WHERE expires_at > datetime("now")')
        count = cursor.fetchone()[0]
        conn.close()
        return {"active_sessions": count}
```

### Очистка истекших сессий
```python
# Автоматическая очистка каждые 5 минут
import asyncio
from datetime import datetime

async def cleanup_task():
    while True:
        await asyncio.sleep(300)  # 5 минут
        deleted_count = session_storage.cleanup_expired()
        print(f"Очищено {deleted_count} истекших сессий")

# Запуск в фоне
asyncio.create_task(cleanup_task())
```

## 🔒 Безопасность

### Для продакшена
1. Измените `SECRET_KEY` на случайную строку
2. Установите `secure=True` для cookies (требует HTTPS)
3. Используйте `samesite="strict"` для максимальной защиты
4. Регулярно очищайте истекшие сессии

### Переменные окружения
```bash
# Создайте файл .env
SECRET_KEY=your-super-secret-key-here
SESSION_EXPIRE_HOURS=8
SESSION_STORAGE_TYPE=sqlite
```

## 📚 Дополнительные ресурсы

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [HTTP Cookies Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Security)
- [OWASP Session Management](https://owasp.org/www-community/controls/Session_Management_Cheat_Sheet)
