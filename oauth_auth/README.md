# 🔐 OAuth 2.0 Аутентификация с Яндекс

Полнофункциональная система аутентификации на основе OAuth 2.0 с использованием Яндекс как Identity Provider. Пользователи могут входить в систему через свои Яндекс аккаунты, а приложение получает безопасный доступ к их профильной информации.

## 📋 Содержание

- [Описание](#описание)
- [Технологии](#технологии)
- [Архитектура](#архитектура)
- [Установка и настройка](#установка-и-настройка)
- [Использование](#использование)
- [API Документация](#api-документация)
- [Безопасность](#безопасность)
- [Устранение неполадок](#устранение-неполадок)
- [Развертывание](#развертывание)
- [Расширение функциональности](#расширение-функциональности)

## 🎯 Описание

### Что это такое?

Это современная система аутентификации, которая позволяет пользователям входить в ваше приложение используя свои Яндекс аккаунты. Вместо создания новых учетных записей пользователи используют существующие аккаунты Яндекса, что повышает удобство и безопасность.

### Ключевые особенности

- ✅ **Безопасность**: Не храните пароли пользователей
- ✅ **Удобство**: Пользователи используют существующие аккаунты
- ✅ **Современность**: Основано на стандарте OAuth 2.0
- ✅ **Русскоязычность**: Оптимизировано для русскоязычной аудитории
- ✅ **JWT токены**: Безопасные токены доступа
- ✅ **SQLite база**: Локальное хранение пользователей
- ✅ **Статические файлы**: Поддержка аватаров и ресурсов
- ✅ **REST API**: Полноценное API для интеграции

### Как это работает?

1. **Пользователь** нажимает "Войти через Яндекс"
2. **Приложение** перенаправляет на Яндекс OAuth
3. **Пользователь** авторизуется в Яндексе
4. **Яндекс** возвращает код авторизации
5. **Приложение** обменивает код на access токен
6. **Приложение** получает данные пользователя от Яндекса
7. **Приложение** создает локальную сессию с JWT токеном

## 🛠 Технологии

### Backend
- **FastAPI** 0.104.1 - современный веб-фреймворк
- **httpx** 0.25.2 - асинхронный HTTP клиент
- **PyJWT** 2.8.0 - работа с JSON Web Tokens
- **SQLite** - встроенная база данных
- **uvicorn** 0.24.0 - ASGI сервер

### Frontend
- **HTML5** - семантическая разметка
- **CSS3** - современные стили
- **JavaScript ES6+** - интерактивность
- **Fetch API** - асинхронные запросы

### Интеграции
- **Яндекс OAuth 2.0** - провайдер аутентификации
- **Яндекс API** - получение данных пользователя

## 🏗 Архитектура

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Клиент        │    │   FastAPI App    │    │   Яндекс OAuth  │
│   (Браузер)     │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Запрос входа        │                       │
         ├──────────────────────►│                       │
         │                       │ 2. Редирект на Яндекс │
         │◄───────────────────────├──────────────────────►│
         │                       │                       │
         │ 3. Авторизация        │                       │
         ├──────────────────────►│                       │
         │                       │ 4. Callback с кодом   │
         │◄───────────────────────◄───────────────────────│
         │                       │                       │
         │ 5. JWT токен          │                       │
         │◄───────────────────────│                       │
```

### Компоненты системы

1. **Веб-интерфейс** (`/`) - главная страница с формой входа
2. **OAuth эндпоинты** (`/auth/yandex/*`) - обработка OAuth flow
3. **API профиля** (`/profile`) - защищенный эндпоинт профиля
4. **Статические файлы** (`/static/*`) - аватары и ресурсы
5. **База данных** (`oauth_users.db`) - хранение пользователей

## 🚀 Установка и настройка

### Предварительные требования

- Python 3.8+
- pip (менеджер пакетов Python)
- Аккаунт Яндекс для разработчика

### 1. Клонирование и настройка окружения

```bash
# Перейдите в папку проекта
cd Primer_auth/oauth_auth

# Создайте виртуальное окружение
python -m venv venv

# Активируйте виртуальное окружение
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 3. Настройка Яндекс OAuth 2.0

#### Шаг 1: Регистрация приложения

1. Перейдите на [https://oauth.yandex.ru/client/new](https://oauth.yandex.ru/client/new)
2. Войдите в свой Яндекс аккаунт
3. Заполните форму:
   - **Название приложения**: `Ваше приложение`
   - **Платформа**: `Веб-сервисы`
   - **Callback URI**: `http://localhost:8000/auth/yandex/callback`

#### Шаг 2: Настройка прав доступа

Выберите необходимые права:
- ✅ `login:email` - доступ к email адресу
- ✅ `login:info` - доступ к основной информации профиля

#### Шаг 3: Получение ключей

После создания приложения вы получите:
- **Client ID** - публичный идентификатор
- **Client Secret** - секретный ключ

#### Шаг 4: Обновление конфигурации

Откройте `main.py` и замените:

```python
# Строки 25-26
YANDEX_CLIENT_ID = "ваш-client-id-здесь"
YANDEX_CLIENT_SECRET = "ваш-client-secret-здесь"
```

### 4. Запуск приложения

```bash
python main.py
```

Вы увидите:
```
Запуск сервера OAuth 2.0 аутентификации с Яндекс...
Откройте http://localhost:8000 в браузере
API документация: http://localhost:8000/docs
```

## 💻 Использование

### Веб-интерфейс

1. **Откройте браузер**: http://localhost:8000
2. **Нажмите кнопку**: "Войти через Яндекс"
3. **Авторизуйтесь**: в Яндексе (если не авторизованы)
4. **Разрешите доступ**: вашему приложению
5. **Получите профиль**: автоматически загрузится информация

### Функции интерфейса

- 🔐 **Вход через Яндекс** - основная аутентификация
- 👤 **Проверка профиля** - загрузка данных пользователя
- 🚪 **Выход** - завершение сессии
- 💾 **Автосохранение** - токен сохраняется в localStorage
- 🔄 **Автообновление** - проверка токена при загрузке

### API через curl

#### Получение профиля (требует токен)

```bash
curl http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Ответ:
```json
{
  "id": 1,
  "yandex_id": "123456789",
  "email": "user@yandex.ru",
  "name": "Иван Иванов",
  "picture": "https://avatars.yandex.net/get-yapic/...",
  "created_at": "2024-01-01T12:00:00"
}
```

#### Выход из системы

```bash
curl -X POST http://localhost:8000/logout
```

Ответ:
```json
{
  "message": "Выход выполнен успешно"
}
```

## 📚 API Документация

### Автоматическая документация

FastAPI автоматически генерирует интерактивную документацию:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Эндпоинты

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| GET | `/` | Главная страница | ❌ |
| GET | `/auth/yandex` | Инициация OAuth | ❌ |
| GET | `/auth/yandex/callback` | OAuth callback | ❌ |
| GET | `/profile` | Профиль пользователя | ✅ |
| POST | `/logout` | Выход из системы | ❌ |
| GET | `/static/*` | Статические файлы | ❌ |

### Модели данных

#### UserResponse
```python
{
  "id": int,           # ID пользователя в БД
  "yandex_id": str,    # ID в Яндексе
  "email": str,        # Email адрес
  "name": str,         # Имя пользователя
  "picture": str,      # URL аватара (опционально)
  "created_at": str    # Дата создания (ISO)
}
```

#### Token
```python
{
  "access_token": str,  # JWT токен
  "token_type": str     # Тип токена (Bearer)
}
```

## 🔒 Безопасность

### JWT Токены

- **Алгоритм**: HS256
- **Время жизни**: 24 часа
- **Подпись**: секретным ключом
- **Содержимое**: user_id, exp, type

### Защита данных

- ✅ **HTTPS в продакшене** - обязательное шифрование
- ✅ **Валидация токенов** - проверка подписи и срока
- ✅ **CORS настройки** - контроль доступа
- ✅ **Секретные ключи** - через переменные окружения
- ✅ **SQL инъекции** - параметризованные запросы

### Рекомендации

1. **Смените SECRET_KEY** в продакшене
2. **Используйте HTTPS** для всех запросов
3. **Настройте CORS** для вашего домена
4. **Регулярно обновляйте** зависимости
5. **Мониторьте логи** на подозрительную активность

## 🔧 Устранение неполадок

### Частые проблемы

#### 1. Ошибка "ModuleNotFoundError: No module named 'fastapi'"

**Причина**: Виртуальное окружение не активировано

**Решение**:
```bash
# Активируйте виртуальное окружение
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Установите зависимости
pip install -r requirements.txt
```

#### 2. Ошибка "error while attempting to bind on address ('0.0.0.0', 8000)"

**Причина**: Порт 8000 уже занят

**Решение**:
```bash
# Найдите процесс
netstat -ano | findstr :8000

# Завершите процесс
taskkill /PID <PID> /F

# Или измените порт в main.py
uvicorn.run(app, host="0.0.0.0", port=8001)
```

#### 3. Ошибка "Invalid token" при запросе профиля

**Причина**: Токен истек или недействителен

**Решение**:
- Проверьте время жизни токена (24 часа)
- Убедитесь, что SECRET_KEY не изменился
- Попробуйте войти заново

#### 4. Ошибка "Ошибка аутентификации" при callback

**Причина**: Неверные Client ID/Secret или настройки Яндекс

**Решение**:
- Проверьте Client ID и Secret в коде
- Убедитесь, что Callback URI совпадает
- Проверьте права доступа в Яндекс OAuth

#### 5. 404 ошибка для аватара

**Причина**: Отсутствует файл default-avatar.svg

**Решение**:
- Убедитесь, что папка `static/` существует
- Проверьте наличие файла `static/default-avatar.svg`
- Перезапустите сервер

### Логи и отладка

Включите подробные логи:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Проверьте логи сервера для диагностики проблем.

## 🚀 Развертывание

### Переменные окружения

Создайте файл `.env`:

```bash
YANDEX_CLIENT_ID=your-client-id
YANDEX_CLIENT_SECRET=your-client-secret
SECRET_KEY=your-super-secret-key-change-in-production
DATABASE_URL=sqlite:///oauth_users.db
```

### Docker развертывание

Создайте `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["python", "main.py"]
```

### Nginx конфигурация

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### SSL сертификаты

Используйте Let's Encrypt для бесплатных SSL сертификатов:

```bash
certbot --nginx -d your-domain.com
```

## 🔧 Расширение функциональности

### Добавление других OAuth провайдеров

#### VK OAuth 2.0

```python
# Добавьте в конфигурацию
VK_CLIENT_ID = "your-vk-app-id"
VK_CLIENT_SECRET = "your-vk-app-secret"
VK_AUTH_URL = "https://oauth.vk.com/authorize"
VK_TOKEN_URL = "https://oauth.vk.com/access_token"
VK_USER_INFO_URL = "https://api.vk.com/method/users.get"

# Добавьте эндпоинт
@app.get("/auth/vk")
async def vk_auth():
    params = {
        'client_id': VK_CLIENT_ID,
        'redirect_uri': 'http://localhost:8000/auth/vk/callback',
        'response_type': 'code',
        'scope': 'email'
    }
    auth_url = f"{VK_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=auth_url)
```

#### Google OAuth 2.0

```python
# Добавьте в конфигурацию
GOOGLE_CLIENT_ID = "your-google-client-id"
GOOGLE_CLIENT_SECRET = "your-google-client-secret"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"
```

### Расширение базы данных

#### Связывание аккаунтов

```sql
CREATE TABLE user_oauth_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(provider, provider_id)
);
```

#### Роли пользователей

```sql
CREATE TABLE user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Добавление функций

#### Refresh токены

```python
def create_refresh_token(user_id: int) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(days=30),
        "type": "refresh"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@app.post("/refresh")
async def refresh_token(refresh_token: str):
    # Обмен refresh токена на новый access токен
    pass
```

#### Отзыв токенов

```python
@app.post("/revoke")
async def revoke_token(token: str):
    # Добавление токена в черный список
    # В реальном приложении используйте Redis или БД
    pass
```

#### Двухфакторная аутентификация

```python
import pyotp

def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp(secret: str, token: str):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
```

## 📊 Мониторинг и аналитика

### Логирование

```python
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('oauth.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Логирование событий
@app.get("/auth/yandex")
async def yandex_auth():
    logger.info("OAuth flow initiated")
    # ... остальной код
```

### Метрики

```python
from collections import defaultdict
import time

# Простые метрики
metrics = {
    'auth_attempts': 0,
    'successful_auths': 0,
    'failed_auths': 0,
    'api_calls': defaultdict(int)
}

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    metrics['api_calls'][request.url.path] += 1
    logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    
    return response
```

## 🤝 Вклад в проект

### Как помочь

1. **Fork** репозиторий
2. **Создайте ветку** для новой функции
3. **Сделайте изменения** с тестами
4. **Создайте Pull Request**

### Стандарты кода

- **PEP 8** - стиль кода Python
- **Type hints** - аннотации типов
- **Docstrings** - документация функций
- **Тесты** - покрытие тестами

## 📄 Лицензия

Этот проект распространяется под лицензией MIT. См. файл `LICENSE` для подробностей.

## 📞 Поддержка

Если у вас есть вопросы или проблемы:

1. **Проверьте** раздел "Устранение неполадок"
2. **Создайте Issue** в репозитории
3. **Опишите проблему** подробно с логами

---

**Создано с ❤️ для изучения OAuth 2.0 и современной веб-разработки**