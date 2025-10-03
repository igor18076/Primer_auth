# Системы Аутентификации для Веб-приложений

Этот проект содержит три отдельные реализации системы регистрации и авторизации, демонстрирующие разные современные подходы к аутентификации в веб-приложениях.

## 📁 Структура проекта

```
stydenti/
├── session_auth/          # Сессионная аутентификация
│   ├── main.py           # Flask приложение с Redis сессиями
│   ├── requirements.txt  # Зависимости
│   └── README.md         # Подробная документация
├── jwt_auth/             # JWT аутентификация
│   ├── main.py           # FastAPI приложение с JWT токенами
│   ├── requirements.txt  # Зависимости
│   └── README.md         # Подробная документация
├── oauth_auth/           # OAuth 2.0 аутентификация
│   ├── main.py           # FastAPI приложение с Google OAuth
│   ├── requirements.txt  # Зависимости
│   └── README.md         # Подробная документация
└── README.md             # Этот файл
```

## 🚀 Быстрый старт

### 1. Сессионная аутентификация (Flask + Redis)

```bash
cd session_auth
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или venv\Scripts\activate  # Windows
pip install -r requirements.txt
# Запустите Redis сервер
python main.py
# Откройте http://localhost:5000
```

### 2. JWT аутентификация (FastAPI + PyJWT)

```bash
cd jwt_auth
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
# Откройте http://localhost:8000
```

### 3. OAuth 2.0 аутентификация (FastAPI + Google)

```bash
cd oauth_auth
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Настройте Google OAuth 2.0 (см. README.md в папке)
python main.py
# Откройте http://localhost:8000
```

## 🔍 Сравнение подходов

| Аспект | Сессионная | JWT | OAuth 2.0 |
|--------|------------|-----|-----------|
| **Состояние** | Stateful | Stateless | Stateless |
| **Масштабируемость** | Требует Redis | Отличная | Отличная |
| **Безопасность** | Высокая | Средняя | Высокая |
| **Сложность** | Средняя | Низкая | Высокая |
| **Отзыв токенов** | Мгновенный | Сложный | Через провайдера |
| **Зависимости** | Redis | Нет | Внешний провайдер |

## 🛡️ Безопасность

Все реализации включают:

- ✅ **Хеширование паролей** с bcrypt и солью
- ✅ **Защита от CSRF** (сессионная версия)
- ✅ **HttpOnly cookies** (сессионная версия)
- ✅ **JWT подпись** (JWT и OAuth версии)
- ✅ **Валидация входных данных**
- ✅ **Время жизни токенов/сессий**

## 📊 Функциональность

Каждая реализация включает:

- 🔐 **Регистрацию** нового пользователя
- 🔑 **Авторизацию** (вход в систему)
- 👤 **Защищённый маршрут** `/profile`
- 🌐 **Веб-интерфейс** с HTML формами
- 📡 **REST API** с примерами curl
- 📚 **Автоматическую документацию** (FastAPI)

## 🎯 Когда использовать какой подход?

### Сессионная аутентификация
- **Когда**: Традиционные веб-приложения
- **Плюсы**: Простота отзыва, полный контроль
- **Минусы**: Требует Redis, сложность масштабирования

### JWT аутентификация
- **Когда**: API, микросервисы, мобильные приложения
- **Плюсы**: Stateless, масштабируемость
- **Минусы**: Сложность отзыва, размер токенов

### OAuth 2.0
- **Когда**: Интеграция с внешними сервисами
- **Плюсы**: Не храните пароли, доверие пользователей
- **Минусы**: Зависимость от провайдера, сложность настройки

## 🔧 Технические детали

### Сессионная аутентификация
- **Фреймворк**: Flask
- **Сессии**: Redis
- **Хеширование**: bcrypt
- **База данных**: SQLite

### JWT аутентификация
- **Фреймворк**: FastAPI
- **Токены**: PyJWT
- **Refresh токены**: Да
- **База данных**: SQLite

### OAuth 2.0
- **Фреймворк**: FastAPI
- **Провайдер**: Google
- **Библиотека**: Authlib
- **База данных**: SQLite

## 📝 Примеры использования

### Сессионная аутентификация
```bash
# Регистрация
curl -X POST http://localhost:5000/register \
  -d "email=user@example.com" \
  -d "password=password123" \
  -c cookies.txt

# Вход
curl -X POST http://localhost:5000/login \
  -d "email=user@example.com" \
  -d "password=password123" \
  -c cookies.txt

# Профиль
curl http://localhost:5000/profile -b cookies.txt
```

### JWT аутентификация
```bash
# Вход
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Профиль
curl http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### OAuth 2.0
```bash
# Профиль (после OAuth flow)
curl http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🚀 Развёртывание в продакшене

### Общие рекомендации:
1. **Используйте HTTPS** для всех соединений
2. **Настройте переменные окружения** для секретных ключей
3. **Используйте надёжную базу данных** (PostgreSQL, MySQL)
4. **Настройте мониторинг** и логирование
5. **Регулярно обновляйте зависимости**

### Сессионная аутентификация:
- Настройте Redis кластер для высокой доступности
- Используйте Redis Sentinel для автоматического failover

### JWT аутентификация:
- Используйте короткое время жизни access токенов
- Реализуйте blacklist для отзыва токенов
- Рассмотрите использование refresh токенов

### OAuth 2.0:
- Настройте правильные redirect URIs
- Используйте PKCE для дополнительной безопасности
- Реализуйте обработку ошибок от провайдера

## 📚 Дополнительные ресурсы

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT.io](https://jwt.io/) - отладка JWT токенов
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Flask Security](https://flask-security.readthedocs.io/)

## 🤝 Вклад в проект

Если вы хотите улучшить проект:

1. Создайте fork репозитория
2. Создайте ветку для новой функции
3. Внесите изменения
4. Создайте Pull Request

## 📄 Лицензия

Этот проект создан в образовательных целях и распространяется свободно.

---

**Примечание**: Этот проект создан для демонстрации различных подходов к аутентификации. В продакшене обязательно следуйте лучшим практикам безопасности и используйте проверенные библиотеки.
