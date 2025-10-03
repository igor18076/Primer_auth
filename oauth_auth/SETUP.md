# Инструкция по настройке Яндекс OAuth 2.0

## Быстрая настройка

### 1. Регистрация приложения
1. Перейдите на https://oauth.yandex.ru/client/new
2. Заполните форму:
   - **Название**: "Мое приложение" (или любое другое)
   - **Платформа**: "Веб-сервисы"
   - **Callback URI**: `http://localhost:8000/auth/yandex/callback`
   - **Права доступа**: выберите `login:email` и `login:info`

### 2. Получение ключей
После создания приложения вы получите:
- **Client ID** - идентификатор приложения
- **Client Secret** - секретный ключ

### 3. Обновление кода
Замените в файле `main.py`:
```python
YANDEX_CLIENT_ID = "ваш-client-id-здесь"
YANDEX_CLIENT_SECRET = "ваш-client-secret-здесь"
```

### 4. Запуск
```bash
cd Primer_auth/oauth_auth
python -m venv venv
source venv/bin/activate  # или venv\Scripts\activate на Windows
pip install -r requirements.txt
python main.py
```

### 5. Тестирование
1. Откройте http://localhost:8000
2. Нажмите "Войти через Яндекс"
3. Авторизуйтесь в Яндексе
4. Проверьте профиль

## Структура данных пользователя от Яндекса

Яндекс API возвращает следующие поля:
- `id` - уникальный идентификатор пользователя
- `default_email` - основной email адрес
- `real_name` - реальное имя пользователя
- `display_name` - отображаемое имя
- `default_avatar_id` - ID аватара (может быть null)

## Возможные проблемы

1. **Ошибка "Invalid redirect_uri"**
   - Убедитесь, что в настройках приложения указан точно такой же URL: `http://localhost:8000/auth/yandex/callback`

2. **Ошибка "Invalid client"**
   - Проверьте правильность Client ID и Client Secret

3. **Ошибка "Access denied"**
   - Пользователь отклонил запрос на авторизацию

## Для продакшена

1. Используйте HTTPS вместо HTTP
2. Обновите redirect URI на ваш домен
3. Используйте переменные окружения для хранения ключей
4. Настройте мониторинг и логирование

