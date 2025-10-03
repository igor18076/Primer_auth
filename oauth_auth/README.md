# OAuth 2.0 / OpenID Connect Аутентификация

## Описание подхода

Эта реализация использует **OAuth 2.0 / OpenID Connect** с Google как Identity Provider. Пользователи аутентифицируются через Google, а ваше приложение получает информацию о пользователе и создает собственную сессию.

### Особенности:
- **Внешний провайдер**: Google обрабатывает аутентификацию
- **Безопасность**: не храните пароли пользователей
- **Удобство**: пользователи используют существующие аккаунты
- **Доверие**: Google гарантирует подлинность пользователя

## Технологии

- **FastAPI** - современный веб-фреймворк
- **Authlib** - библиотека для OAuth 2.0 / OpenID Connect
- **PyJWT** - работа с JSON Web Tokens
- **SQLite** - база данных пользователей

## Настройка Google OAuth 2.0

### 1. Создание проекта в Google Cloud Console

1. Перейдите в [Google Cloud Console](https://console.cloud.google.com/)
2. Создайте новый проект или выберите существующий
3. Включите Google+ API (или Google Identity API)

### 2. Настройка OAuth 2.0 credentials

1. Перейдите в "APIs & Services" → "Credentials"
2. Нажмите "Create Credentials" → "OAuth 2.0 Client IDs"
3. Выберите "Web application"
4. Добавьте authorized redirect URIs:
   - `http://localhost:8000/auth/google/callback` (для разработки)
   - `https://yourdomain.com/auth/google/callback` (для продакшена)

### 3. Обновление конфигурации

Замените в `main.py`:
```python
GOOGLE_CLIENT_ID = "ваш-client-id"
GOOGLE_CLIENT_SECRET = "ваш-client-secret"
```

## Установка и запуск

1. Создайте виртуальное окружение:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate     # Windows
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

3. Настройте Google OAuth 2.0 (см. выше)

4. Запустите приложение:
```bash
python main.py
```

5. Откройте браузер: http://localhost:8000

## Использование

### Веб-интерфейс
1. Откройте http://localhost:8000
2. Нажмите "Войти через Google"
3. Авторизуйтесь в Google
4. Вы будете перенаправлены обратно в приложение
5. Используйте кнопки для проверки профиля и выхода

### API через curl

#### Получение профиля (требует access токен):
```bash
curl http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### Выход:
```bash
curl -X POST http://localhost:8000/logout
```

## Безопасность

- **JWT подпись**: токены подписываются секретным ключом
- **Время жизни токенов**: access токен действует 24 часа
- **HTTPS**: в продакшене обязательно используйте HTTPS
- **Валидация**: проверка токенов от Google
- **Отзыв токенов**: возможность отозвать токены через Google

## Архитектура

```
Клиент (Браузер)
    ↓ перенаправление на Google
Google OAuth 2.0
    ↓ callback с кодом авторизации
FastAPI приложение
    ↓ обмен кода на токен + получение данных пользователя
Google API
    ↓ сохранение/получение пользователя
SQLite (пользователи)
```

## OAuth 2.0 Flow

1. **Authorization Request**: клиент перенаправляется на Google
2. **User Authorization**: пользователь авторизуется в Google
3. **Authorization Grant**: Google возвращает код авторизации
4. **Access Token Request**: приложение обменивает код на access токен
5. **Protected Resource**: приложение получает данные пользователя
6. **Local Session**: создается локальная сессия с JWT токеном

## Преимущества OAuth 2.0

1. **Безопасность**: не храните пароли пользователей
2. **Удобство**: пользователи используют существующие аккаунты
3. **Доверие**: провайдер гарантирует подлинность
4. **Стандартизация**: открытый стандарт
5. **Масштабируемость**: легко добавить других провайдеров

## Недостатки

1. **Зависимость**: зависимость от внешнего сервиса
2. **Сложность**: более сложная настройка
3. **Приватность**: провайдер знает о ваших пользователях
4. **Офлайн**: не работает без интернета

## Расширение функциональности

### Добавление других провайдеров

Можно легко добавить поддержку других OAuth 2.0 провайдеров:

```python
# GitHub OAuth 2.0
github_oauth = OAuth2(
    client_id="your-github-client-id",
    client_secret="your-github-client-secret",
    scope="user:email"
)

# Facebook OAuth 2.0
facebook_oauth = OAuth 2(
    client_id="your-facebook-app-id",
    client_secret="your-facebook-app-secret",
    scope="email"
)
```

### Объединение аккаунтов

Можно связать несколько OAuth аккаунтов с одним пользователем:

```sql
CREATE TABLE user_oauth_accounts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    provider TEXT,
    provider_id TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Переменные окружения

Для продакшена используйте переменные окружения:

```bash
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
export SECRET_KEY="your-secret-key"
```

И обновите код:
```python
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")
```
