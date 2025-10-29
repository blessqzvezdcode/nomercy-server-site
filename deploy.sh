#!/bin/bash

# Скрипт автоматического обновления сайта с GitHub
# Использование: ./deploy.sh

set -e  # Остановить при ошибке

PROJECT_DIR="/var/www/nomercy-server-site"
LOG_FILE="/var/log/deploy.log"

# Функция логирования
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "🚀 Starting deployment..."

# Переходим в директорию проекта
cd "$PROJECT_DIR"

# Проверяем статус Git
log "📋 Checking Git status..."
git status

# Сохраняем локальные изменения (если есть)
if ! git diff-index --quiet HEAD --; then
    log "💾 Stashing local changes..."
    git stash push -m "Auto-stash before deploy $(date)"
fi

# Получаем последние изменения
log "📥 Pulling latest changes from GitHub..."
git pull origin main

# Проверяем изменения в package.json
if git diff HEAD~1 HEAD --name-only | grep -q "package.*\.json"; then
    log "📦 Package files changed, installing dependencies..."
    npm install
fi

# Перезапускаем PM2
log "🔄 Restarting PM2..."
pm2 restart nomercy

# Проверяем статус
log "✅ Checking PM2 status..."
pm2 list

# Проверяем что сайт отвечает
log "🌐 Testing site response..."
if curl -f -s http://127.0.0.1:3000 > /dev/null; then
    log "✅ Site is responding correctly"
else
    log "❌ Site is not responding!"
    exit 1
fi

log "🎉 Deployment completed successfully!"

# Показываем последние коммиты
log "📝 Recent commits:"
git log --oneline -5