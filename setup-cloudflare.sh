#!/bin/bash

# Скрипт для настройки Cloudflare через API
# Требует: CLOUDFLARE_API_TOKEN и ZONE_ID

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция логирования
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Проверяем переменные окружения
if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    error "CLOUDFLARE_API_TOKEN не установлен!"
    echo "Получите токен здесь: https://dash.cloudflare.com/profile/api-tokens"
    exit 1
fi

if [ -z "$ZONE_ID" ]; then
    error "ZONE_ID не установлен!"
    echo "Найдите Zone ID в панели Cloudflare для домена nmercy.online"
    exit 1
fi

DOMAIN="nmercy.online"
SERVER_IP="90.156.229.233"

log "🚀 Настройка Cloudflare для $DOMAIN..."

# Функция для API запросов
cf_api() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    curl -s -X $method "https://api.cloudflare.com/client/v4$endpoint" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        ${data:+-d "$data"}
}

# 1. Настройка DNS записей
log "📋 Настройка DNS записей..."

# A запись для основного домена
DNS_RECORD=$(cf_api GET "/zones/$ZONE_ID/dns_records?name=$DOMAIN&type=A")
if echo "$DNS_RECORD" | grep -q '"count":0'; then
    log "Создание A записи для $DOMAIN..."
    cf_api POST "/zones/$ZONE_ID/dns_records" '{
        "type": "A",
        "name": "'$DOMAIN'",
        "content": "'$SERVER_IP'",
        "proxied": true,
        "ttl": 1
    }'
    success "A запись создана"
else
    log "Обновление A записи для $DOMAIN..."
    RECORD_ID=$(echo "$DNS_RECORD" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    cf_api PUT "/zones/$ZONE_ID/dns_records/$RECORD_ID" '{
        "type": "A",
        "name": "'$DOMAIN'",
        "content": "'$SERVER_IP'",
        "proxied": true,
        "ttl": 1
    }'
    success "A запись обновлена"
fi

# A запись для www
WWW_RECORD=$(cf_api GET "/zones/$ZONE_ID/dns_records?name=www.$DOMAIN&type=A")
if echo "$WWW_RECORD" | grep -q '"count":0'; then
    log "Создание A записи для www.$DOMAIN..."
    cf_api POST "/zones/$ZONE_ID/dns_records" '{
        "type": "A",
        "name": "www.'$DOMAIN'",
        "content": "'$SERVER_IP'",
        "proxied": true,
        "ttl": 1
    }'
    success "A запись для www создана"
fi

# 2. Настройка SSL
log "🔒 Настройка SSL..."
cf_api PATCH "/zones/$ZONE_ID/settings/ssl" '{"value": "full"}'
cf_api PATCH "/zones/$ZONE_ID/settings/min_tls_version" '{"value": "1.2"}'
cf_api PATCH "/zones/$ZONE_ID/settings/hsts" '{
    "value": {
        "enabled": true,
        "max_age": 31536000,
        "include_subdomains": true,
        "preload": true
    }
}'
success "SSL настроен"

# 3. Настройка безопасности
log "🛡️  Настройка безопасности..."
cf_api PATCH "/zones/$ZONE_ID/settings/security_level" '{"value": "medium"}'
cf_api PATCH "/zones/$ZONE_ID/settings/browser_check" '{"value": "on"}'
success "Безопасность настроена"

# 4. Настройка производительности
log "⚡ Настройка производительности..."
cf_api PATCH "/zones/$ZONE_ID/settings/cache_level" '{"value": "aggressive"}'
cf_api PATCH "/zones/$ZONE_ID/settings/minify" '{
    "value": {
        "css": "on",
        "html": "on",
        "js": "on"
    }
}'
cf_api PATCH "/zones/$ZONE_ID/settings/brotli" '{"value": "on"}'
success "Производительность настроена"

# 5. Создание Page Rules
log "📄 Создание Page Rules..."

# API bypass rule
cf_api POST "/zones/$ZONE_ID/pagerules" '{
    "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "'$DOMAIN'/api/*"}}],
    "actions": [
        {"id": "cache_level", "value": "bypass"},
        {"id": "security_level", "value": "high"}
    ],
    "priority": 1,
    "status": "active"
}'

# Admin bypass rule
cf_api POST "/zones/$ZONE_ID/pagerules" '{
    "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "'$DOMAIN'/admin/*"}}],
    "actions": [
        {"id": "cache_level", "value": "bypass"},
        {"id": "security_level", "value": "high"},
        {"id": "browser_check", "value": "on"}
    ],
    "priority": 2,
    "status": "active"
}'

# Static files caching
cf_api POST "/zones/$ZONE_ID/pagerules" '{
    "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "'$DOMAIN'/*.css"}}],
    "actions": [
        {"id": "cache_level", "value": "cache_everything"},
        {"id": "edge_cache_ttl", "value": 2592000}
    ],
    "priority": 3,
    "status": "active"
}'

cf_api POST "/zones/$ZONE_ID/pagerules" '{
    "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "'$DOMAIN'/*.js"}}],
    "actions": [
        {"id": "cache_level", "value": "cache_everything"},
        {"id": "edge_cache_ttl", "value": 2592000}
    ],
    "priority": 4,
    "status": "active"
}'

success "Page Rules созданы"

log "🎉 Cloudflare настроен успешно!"
log "🌐 Ваш сайт теперь защищен Cloudflare"
log "📊 Проверьте настройки: https://dash.cloudflare.com"

warning "Важно: Обновите nameservers у регистратора домена на Cloudflare nameservers"

