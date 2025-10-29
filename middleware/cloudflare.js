// Middleware для работы с Cloudflare
const cloudflareIPs = [
    // IPv4 ranges
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22'
];

// Проверка IP адреса Cloudflare
function isCloudflareIP(ip) {
    const ipInt = ipToInt(ip);
    return cloudflareIPs.some(range => {
        const [rangeIP, mask] = range.split('/');
        const rangeInt = ipToInt(rangeIP);
        const maskInt = -1 << (32 - parseInt(mask));
        return (ipInt & maskInt) === (rangeInt & maskInt);
    });
}

function ipToInt(ip) {
    return ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct, 10), 0) >>> 0;
}

// Middleware для получения реального IP через Cloudflare
function cloudflareMiddleware(req, res, next) {
    // Получаем реальный IP клиента
    const cfConnectingIP = req.headers['cf-connecting-ip'];
    const xForwardedFor = req.headers['x-forwarded-for'];
    const xRealIP = req.headers['x-real-ip'];
    
    if (cfConnectingIP) {
        req.clientIP = cfConnectingIP;
    } else if (xForwardedFor) {
        req.clientIP = xForwardedFor.split(',')[0].trim();
    } else if (xRealIP) {
        req.clientIP = xRealIP;
    } else {
        req.clientIP = req.connection.remoteAddress || req.socket.remoteAddress;
    }
    
    // Информация о стране от Cloudflare
    req.country = req.headers['cf-ipcountry'] || 'Unknown';
    req.ray = req.headers['cf-ray'] || 'Unknown';
    
    // Проверяем что запрос идет через Cloudflare (для безопасности)
    const serverIP = req.connection.localAddress || req.socket.localAddress;
    if (process.env.NODE_ENV === 'production' && !isCloudflareIP(serverIP)) {
        console.warn(`Direct access attempt from ${req.clientIP}`);
        // Можно заблокировать прямые подключения:
        // return res.status(403).send('Access denied');
    }
    
    next();
}

// Middleware для блокировки определенных стран
function countryBlockMiddleware(blockedCountries = []) {
    return (req, res, next) => {
        if (blockedCountries.includes(req.country)) {
            console.log(`Blocked request from ${req.country}: ${req.clientIP}`);
            return res.status(403).send('Access denied from your country');
        }
        next();
    };
}

// Middleware для логирования запросов с Cloudflare данными
function cloudflareLogger(req, res, next) {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url} - IP: ${req.clientIP} - Country: ${req.country} - Ray: ${req.ray}`);
    next();
}

module.exports = {
    cloudflareMiddleware,
    countryBlockMiddleware,
    cloudflareLogger,
    isCloudflareIP
};

