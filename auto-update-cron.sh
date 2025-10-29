#!/bin/bash

# Скрипт для автоматической проверки обновлений каждые 5 минут
# Добавьте в crontab: */5 * * * * /var/www/nomercy-server-site/auto-update-cron.sh

PROJECT_DIR="/var/www/nomercy-server-site"
LOG_FILE="/var/log/auto-update.log"
LOCK_FILE="/tmp/auto-update.lock"

# Функция логирования
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Проверяем блокировку (чтобы не запускать несколько раз одновременно)
if [ -f "$LOCK_FILE" ]; then
    log "⏳ Another update process is running, skipping..."
    exit 0
fi

# Создаем блокировку
touch "$LOCK_FILE"

# Функция очистки при выходе
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

cd "$PROJECT_DIR"

# Получаем информацию о удаленных изменениях
git fetch origin main

# Проверяем есть ли новые коммиты
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    log "🆕 New commits found, starting auto-update..."
    
    # Запускаем скрипт обновления
    if ./deploy.sh >> "$LOG_FILE" 2>&1; then
        log "✅ Auto-update completed successfully"
        
        # Отправляем уведомление (опционально)
        # curl -X POST -H 'Content-type: application/json' \
        #     --data '{"text":"🚀 NoMercy site updated successfully!"}' \
        #     YOUR_SLACK_WEBHOOK_URL
    else
        log "❌ Auto-update failed"
        
        # Отправляем уведомление об ошибке (опционально)
        # curl -X POST -H 'Content-type: application/json' \
        #     --data '{"text":"❌ NoMercy site update failed!"}' \
        #     YOUR_SLACK_WEBHOOK_URL
    fi
else
    log "✅ No new commits, site is up to date"
fi
