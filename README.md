# NoMercy Server - Trading Marketplace

Торговая площадка с системой гача для обмена игровыми предметами и картами.

## 🚀 Быстрый старт

### Локальная разработка

```bash
# Клонирование репозитория
git clone <repository-url>
cd nomercy-server-site

# Установка зависимостей
npm install

# Настройка окружения
cp env.example .env
# Отредактируйте .env файл с вашими настройками

# Создание необходимых директорий
npm run setup

# Запуск в режиме разработки
npm run dev
```

### Production развертывание

#### Вариант 1: PM2 (рекомендуется)

```bash
# Установка PM2 глобально
npm install -g pm2

# Развертывание
chmod +x deploy.sh
./deploy.sh production
```

#### Вариант 2: Docker

```bash
# Создание .env файла
cp env.example .env
# Настройте переменные окружения

# Запуск с Docker Compose
./deploy.sh docker
```

## ⚙️ Конфигурация

### Переменные окружения

Скопируйте `env.example` в `.env` и настройте следующие переменные:

```env
# Основные настройки
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Безопасность
SESSION_SECRET=ваш-супер-секретный-ключ-сессии
ADMIN_PASSWORD=ваш-админ-пароль

# Discord OAuth (опционально)
DISCORD_CLIENT_ID=ваш-discord-client-id
DISCORD_CLIENT_SECRET=ваш-discord-client-secret
DISCORD_CALLBACK_URL=https://yourdomain.com/auth/discord/callback

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### SSL/HTTPS настройка

1. Получите SSL сертификат (Let's Encrypt, Cloudflare, и т.д.)
2. Поместите файлы в папку `ssl/`:
   - `ssl/certificate.crt`
   - `ssl/private.key`
3. Обновите `nginx.conf` с вашим доменом

## 🏗️ Архитектура

### Структура проекта

```
nomercy-server-site/
├── server.js              # Основной сервер
├── package.json           # Зависимости и скрипты
├── ecosystem.config.js    # PM2 конфигурация
├── docker-compose.yml     # Docker конфигурация
├── nginx.conf            # Nginx конфигурация
├── deploy.sh             # Скрипт развертывания
├── healthcheck.js        # Health check для Docker
├── views/                # EJS шаблоны
├── public/               # Статические файлы
│   ├── css/
│   ├── js/
│   ├── images/
│   └── uploads/          # Загруженные файлы
├── logs/                 # Логи приложения
└── data/                 # JSON база данных
```

### Технологический стек

- **Backend**: Node.js, Express.js
- **Template Engine**: EJS
- **Database**: JSON файлы (для простоты)
- **Authentication**: Passport.js (Discord OAuth)
- **Security**: Helmet, CSRF, Rate Limiting
- **Logging**: Winston, Morgan
- **Process Manager**: PM2
- **Reverse Proxy**: Nginx
- **Containerization**: Docker

## 🛡️ Безопасность

### Реализованные меры безопасности

- ✅ Helmet.js для HTTP заголовков безопасности
- ✅ Rate limiting для API и аутентификации
- ✅ CSRF защита
- ✅ Input validation и sanitization
- ✅ Secure session configuration
- ✅ Error handling без утечки информации
- ✅ File upload restrictions
- ✅ Nginx security headers

### Рекомендации для production

1. **Используйте HTTPS** - настройте SSL сертификат
2. **Firewall** - ограничьте доступ к портам
3. **Regular updates** - обновляйте зависимости
4. **Monitoring** - настройте мониторинг логов
5. **Backups** - регулярно создавайте резервные копии

## 📊 Мониторинг

### Логи

```bash
# PM2 логи
pm2 logs nomercy-server

# Docker логи
docker-compose logs -f

# Файлы логов
tail -f logs/combined.log
tail -f logs/error.log
```

### Health Check

```bash
# Проверка состояния
curl http://localhost:3000/api/test

# PM2 статус
pm2 status

# Docker статус
docker-compose ps
```

## 🔧 Управление

### PM2 команды

```bash
# Статус
pm2 status

# Перезапуск
pm2 restart nomercy-server

# Остановка
pm2 stop nomercy-server

# Просмотр логов
pm2 logs nomercy-server

# Мониторинг
pm2 monit
```

### Docker команды

```bash
# Статус контейнеров
docker-compose ps

# Перезапуск
docker-compose restart

# Остановка
docker-compose down

# Просмотр логов
docker-compose logs -f app
```

## 🚨 Troubleshooting

### Частые проблемы

1. **Порт занят**
   ```bash
   # Найти процесс на порту 3000
   lsof -i :3000
   # Или на Windows
   netstat -ano | findstr :3000
   ```

2. **Ошибки разрешений**
   ```bash
   # Исправить права на файлы
   chmod +x deploy.sh
   chown -R $USER:$USER logs/ public/uploads/
   ```

3. **SSL проблемы**
   - Проверьте пути к сертификатам в nginx.conf
   - Убедитесь, что сертификат действителен

4. **Проблемы с памятью**
   - Увеличьте лимит памяти в ecosystem.config.js
   - Мониторьте использование памяти через PM2

## 📝 API Endpoints

### Основные маршруты

- `GET /` - Главная страница
- `GET /market` - Маркетплейс
- `GET /cards` - Система гача
- `GET /collection` - Коллекция пользователя
- `GET /profile/:id` - Профиль пользователя
- `GET /admin` - Админ панель

### API маршруты

- `GET /api/test` - Health check
- `POST /api/gacha/pull` - Гача система
- `GET /api/market/listings` - Список товаров
- `POST /api/cards/sell` - Продажа карты

## 🤝 Разработка

### Добавление новых функций

1. Создайте ветку для функции
2. Добавьте маршруты в server.js
3. Создайте EJS шаблоны в views/
4. Добавьте стили в public/css/
5. Обновите документацию
6. Создайте pull request

### Тестирование

```bash
# Запуск тестов (когда будут добавлены)
npm test

# Линтинг (если настроен)
npm run lint
```

## 📄 Лицензия

ISC License - см. файл LICENSE для деталей.

## 👥 Команда

NoMercy Team

---

Для получения поддержки создайте issue в репозитории или свяжитесь с командой разработки.
