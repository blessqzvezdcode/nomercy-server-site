# Discord OAuth Setup

Для настройки Discord OAuth авторизации выполните следующие шаги:

## 1. Создайте приложение в Discord Developer Portal

1. Перейдите на https://discord.com/developers/applications
2. Нажмите "New Application"
3. Введите название приложения (например, "NoMercy Marketplace")
4. Нажмите "Create"

## 2. Настройте OAuth2

1. В левом меню выберите "OAuth2"
2. В разделе "Redirects" добавьте URL: `http://localhost:3000/auth/discord/callback`
3. Скопируйте "Client ID" и "Client Secret"

## 3. Создайте файл .env

Создайте файл `.env` в корне проекта со следующим содержимым:

```
# Discord OAuth Configuration
DISCORD_CLIENT_ID=ваш_client_id_здесь
DISCORD_CLIENT_SECRET=ваш_client_secret_здесь
DISCORD_CALLBACK_URL=http://localhost:3000/auth/discord/callback

# Session Secret
SESSION_SECRET=ваш_супер_секретный_ключ_здесь

# Server Port
PORT=3000
```

## 4. Замените значения

- Замените `ваш_client_id_здесь` на Client ID из Discord Developer Portal
- Замените `ваш_client_secret_здесь` на Client Secret из Discord Developer Portal
- Замените `ваш_супер_секретный_ключ_здесь` на случайную строку для сессий

## 5. Перезапустите сервер

После создания файла .env перезапустите сервер командой:
```bash
node server.js
```

## Примечания

- Для продакшена замените `http://localhost:3000` на ваш домен
- Убедитесь, что файл .env добавлен в .gitignore
- Discord OAuth работает только с HTTPS в продакшене


