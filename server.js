
const fs = require('fs');
const path = require('path');
const DB_DIR = path.join(__dirname, 'database');


// Helper function to load cards
function loadCards() {
    try {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'cards.json')));
    } catch (e) {
        console.error('Error loading cards:', e);
        return [];
    }
}

// Helper function to load packs
function loadPacks() {
    try {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'packs.json')));
    } catch (e) {
        console.error('Error loading packs:', e);
        return [];
    }
}

// Helper function to load transactions
function loadTransactions() {
    try {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'transactions.json')));
    } catch (e) {
        console.error('Error loading transactions:', e);
        return [];
    }
}

function loadItems() {
    try {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'database/items.json')));
    } catch (e) {
        console.error('Error loading items:', e);
        return [];
    }
}

function calculateLevel(xp) {
    const level = Math.floor(xp / 100) + 1;
    const currentLevelXP = (level - 1) * 100;
    const nextLevelXP = level * 100;
    const progressXP = xp - currentLevelXP;
    const progressPercent = (progressXP / 100) * 100;
    
    return {
        level,
        xp,
        currentLevelXP,
        nextLevelXP,
        progressXP,
        progressPercent
    };
}

function addXP(userId, amount, reason) {
    try {
        console.log(`[XP DEBUG] Attempting to add ${amount} XP to user ${userId} for: ${reason}`);
        
        const user = users[userId];
        if (!user) {
            console.error('User not found for XP addition:', userId);
            return 0;
        }
        
        console.log(`[XP DEBUG] User found: ${user.name}, current XP: ${user.xp || 0}`);
        
        // Initialize XP if not exists
        if (!user.xp) {
            user.xp = 0;
            console.log(`[XP DEBUG] Initialized XP to 0 for user ${user.name}`);
        }
        
        // Add XP
        user.xp += amount;
        
        // Log XP gain
        console.log(`[XP DEBUG] User ${user.name} (${userId}) gained ${amount} XP for: ${reason}. Total XP: ${user.xp}`);
        
        // Save user data
        const saveResult = writeJSON(DB.users, users);
        console.log(`[XP DEBUG] Save result:`, saveResult ? 'SUCCESS' : 'FAILED');
        
        return user.xp;
    } catch (error) {
        console.error('Error adding XP:', error);
        return 0;
    }
}
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const helmet = require('helmet');
const { cloudflareMiddleware, countryBlockMiddleware, cloudflareLogger } = require('./middleware/cloudflare');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const csrf = require('csurf');
const compression = require('compression');
const morgan = require('morgan');
const winston = require('winston');

// Production environment check
const isProduction = process.env.NODE_ENV === 'production';

// Logger setup
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nomercy-server' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
    ],
});

// Console logging for development
if (!isProduction) {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

const app = express();

// Trust proxy for production (behind reverse proxy)
if (isProduction) {
    app.set('trust proxy', 1);
}

// Compression middleware
app.use(compression());

// Cloudflare middleware (должен быть рано в цепочке)
app.use(cloudflareMiddleware);
app.use(cloudflareLogger);

// Блокировка определенных стран (опционально)
// app.use(countryBlockMiddleware(['CN', 'RU'])); // Пример блокировки

// Logging middleware
if (isProduction) {
    app.use(morgan('combined', { 
        stream: { write: message => logger.info(message.trim()) }
    }));
} else {
    app.use(morgan('dev'));
}

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https://cdn.discordapp.com", "https://images.unsplash.com"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'self'"],
            // Явно НЕ включаем upgradeInsecureRequests для HTTP
        },
    },
    crossOriginEmbedderPolicy: false,
    hsts: false, // Отключаем HSTS для HTTP
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false
}));

// Rate limiting - stricter in production
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || (isProduction ? 50 : 100),
    message: 'Слишком много запросов с этого IP, попробуйте позже.',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for static files in development
        return !isProduction && req.url.startsWith('/css') || req.url.startsWith('/js') || req.url.startsWith('/images');
    }
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: isProduction ? 10 : 20, // stricter in production
    message: 'Слишком много попыток, попробуйте позже.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);

// CSRF protection will be added after session configuration

// Static files serving
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'devsecret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
        sameSite: 'lax' // CSRF protection
    },
    name: 'nomercy.session',
    rolling: true // Reset expiration on activity
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

// Session middleware to ensure user is always available
app.use((req, res, next) => {
    // If no session user but we have a session, try to restore user
    if (!req.session.user && req.session.passport && req.session.passport.user) {
        req.session.user = req.session.passport.user;
    }
    
    // Ensure session is saved
    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
        }
        next();
    });
});

// CSRF protection disabled for now
// app.use((req, res, next) => {
//     if (req.path.startsWith('/api/')) {
//         return next();
//     }
//     return csrf()(req, res, next);
// });

// Middleware для проверки авторизации
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/discord');
  }
  next();
}

// Middleware для проверки авторизации с JSON ответом
function requireAuthJSON(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  next();
}

// Middleware для валидации входных данных
function validateInput(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      error: 'Некорректные данные', 
      details: errors.array() 
    });
  }
  next();
}

// Middleware для санитизации данных
function sanitizeInput(req, res, next) {
  // Sanitize string inputs
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = validator.escape(req.body[key]);
      }
    }
  }
  next();
}

// Middleware для проверки роли администратора
function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  const user = users[req.session.user.id];
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }
  next();
}

// Middleware для проверки роли модератора
function requireModerator(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  const user = users[req.session.user.id];
  if (!user || (user.role !== 'admin' && user.role !== 'moderator')) {
    return res.status(403).json({ error: 'Требуются права модератора' });
  }
  next();
}

// Security logging middleware
function securityLog(req, res, next) {
  const user = req.session.user ? users[req.session.user.id] : null;
  const logData = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    method: req.method,
    url: req.url,
    userId: user ? user.id : 'anonymous',
    userRole: user ? user.role : 'none'
  };
  
  // Log suspicious activity
  if (req.url.includes('..') || req.url.includes('<script>') || req.url.includes('javascript:')) {
    console.warn('SUSPICIOUS ACTIVITY:', logData);
  }
  
  // Log admin actions
  if (user && (user.role === 'admin' || user.role === 'moderator')) {
    console.log('ADMIN ACTION:', logData);
  }
  
  next();
}

// Apply security logging
app.use(securityLog);

// Discord OAuth Strategy
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID || 'your_client_id',
    clientSecret: process.env.DISCORD_CLIENT_SECRET || 'your_client_secret',
    callbackURL: process.env.DISCORD_CALLBACK_URL || 'http://localhost:3000/auth/discord/callback',
    scope: ['identify', 'email']
}, (accessToken, refreshToken, profile, done) => {
    // Create or update user
    const userId = profile.id;
    const userData = {
        id: userId,
        name: profile.username,
        email: profile.email,
        avatar: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null,
        balance: users[userId]?.balance || 1000,
        ratings: users[userId]?.ratings || [],
        inventory: users[userId]?.inventory || [],
        history: users[userId]?.history || { bought: [], sold: [] },
        role: users[userId]?.role || 'user',
        pityCounter: users[userId]?.pityCounter || 0
    };
    
    users[userId] = userData;
    writeJSON(DB.users, users);
    
    return done(null, userData);
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    try {
        const user = users[id];
        if (user) {
            // Ensure user has all required fields
            user.balance = user.balance || 0;
            user.inventory = user.inventory || [];
            user.history = user.history || { bought: [], sold: [] };
            user.role = user.role || 'user';
            done(null, user);
        } else {
            done(null, false);
        }
    } catch (error) {
        done(error, null);
    }
});

// Ensure uploads folder
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, UPLOAD_DIR)
    },
    filename: function (req, file, cb) {
        // Sanitize filename to prevent path traversal
        const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        const ext = path.extname(sanitizedName);
        cb(null, uuidv4() + ext)
    }
});

// File filter for security
const fileFilter = (req, file, cb) => {
    // Check file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Недопустимый тип файла. Разрешены только изображения.'), false);
    }
};

const upload = multer({ 
    storage,
    fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 6 // Max 6 files
    }
});

// Simple JSON DB helpers
const DB = {
    marketplace: path.join(__dirname, 'marketplace.json'),
    users: path.join(__dirname, 'users.json'),
};

function readJSON(p, def=[]){
    try { return JSON.parse(fs.readFileSync(p)); } catch (e) { return def; }
}
function writeJSON(p, data){ 
    try {
        fs.writeFileSync(p, JSON.stringify(data, null, 2)); 
        console.log('Successfully wrote to:', p);
        return true;
    } catch (error) {
        console.error('Error writing to', p, ':', error);
        return false;
    }
}


// Load data
let marketplace = readJSON(DB.marketplace, []);
let users = readJSON(DB.users, {});

// --- Authentication middleware ---
app.use((req, res, next) => {
    // If user is authenticated via passport, use that
    if (req.user) {
        req.session.user = { id: req.user.id };
    }
    // Don't auto-create demo user - let user choose to login
    next();
});

// Helper: ensure auctions closed if expired (runs on page render)
function expireAuctions() {
    const now = Date.now();
    let changed = false;
    marketplace.forEach(l => {
        if (l.type === 'auction' && l.status === 'open' && l.endsAt) {
            if (now >= l.endsAt) {
                l.status = 'closed';
                // if there is a highestBid, assign to winner
                if (l.highestBid) {
                    const buyerId = l.highestBid.bidder;
                    const seller = users[l.owner] || (users[l.owner] = { id: l.owner, name: l.owner, balance: 0, inventory: [], avatar: null, ratings: [], history: { bought: [], sold: [] } });
                    const buyer = users[buyerId] || (users[buyerId] = { id: buyerId, name: buyerId, balance: 0, inventory: [], avatar: null, ratings: [], history: { bought: [], sold: [] } });
                    // transfer if buyer has enough balance
                    if (buyer.balance >= l.highestBid.amount) {
                        buyer.balance -= l.highestBid.amount;
                        seller.balance = (seller.balance||0) + l.highestBid.amount;
                        buyer.inventory = buyer.inventory || [];
                        buyer.inventory.push({ id: l.id, title: l.title, image: l.images && l.images[0] || null });
                        l.status = 'sold';
                        l.soldTo = buyer.id;
                        seller.history = seller.history || { bought:[], sold:[] };
                        buyer.history = buyer.history || { bought:[], sold:[] };
                        seller.history.sold.push({ id: l.id, title: l.title, price: l.highestBid.amount, when: Date.now(), to: buyer.id });
                        buyer.history.bought.push({ id: l.id, title: l.title, price: l.highestBid.amount, when: Date.now(), from: seller.id });
                    } else {
                        // bidder couldn't pay; mark closed without sale
                        l.status = 'closed';
                    }
                }
                changed = true;
            }
        }
    });
    if (changed) writeJSON(DB.marketplace, marketplace);
}

// Routes
app.get('/', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (currentUser) {
        // Если пользователь авторизован, показываем дашборд
    expireAuctions();
        const balance = currentUser.balance || 0;
        res.render('dashboard', { user: currentUser, balance });
    } else {
        // Если не авторизован, показываем landing page
        res.render('landing');
    }
});

// Marketplace: list view and create form
app.get('/market', requireAuth, (req, res) => {
    expireAuctions();
    // filters: search, type, sort
    let listings = marketplace.slice();
    
    // Filter out sold listings (except permanent ones which stay open)
    listings = listings.filter(l => l.status === 'open' || (l.permanent && l.status !== 'closed'));
    
    // Enrich listings with owner information
    listings = listings.map(listing => {
        const owner = users[listing.owner];
        return {
            ...listing,
            ownerName: owner ? owner.name : 'Неизвестный пользователь',
            ownerAvatar: owner ? owner.avatar : null,
            ownerStatus: owner ? (owner.status || 'Онлайн') : 'Офлайн'
        };
    });
    
    // Sort listings: pinned first, then by creation date (newest first)
    listings.sort((a, b) => {
        // Pinned items always come first
        if (a.pinned && !b.pinned) return -1;
        if (!a.pinned && b.pinned) return 1;
        
        // If both are pinned or both are not pinned, sort by creation date
        return new Date(b.createdAt) - new Date(a.createdAt);
    });
    
    const q = (req.query.search||'').toLowerCase();
    if (q) listings = listings.filter(l => (l.title||'').toLowerCase().includes(q) || (l.description||'').toLowerCase().includes(q));
    if (req.query.type) listings = listings.filter(l => l.type === req.query.type);
    if (req.query.sort === 'price_asc') listings.sort((a,b)=>a.price - b.price);
    if (req.query.sort === 'price_desc') listings.sort((a,b)=>b.price - a.price);
    // pinned items first
    listings.sort((a,b) => (b.pinned?1:0) - (a.pinned?1:0));
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    // load cards and items for market
    const cards = loadCards();
    const items = loadItems();
    res.render('market', { user: currentUser, listings, balance, cards, items });
});

// Create a listing with multiple images upload
app.post('/market/list', 
    requireAuthJSON, 
    strictLimiter,
    sanitizeInput,
    [
        body('title').optional({ checkFalsy: true }).trim().isLength({ min: 1, max: 100 }).withMessage('Название должно быть от 1 до 100 символов'),
        body('description').optional({ checkFalsy: true }).trim().isLength({ min: 1, max: 1000 }).withMessage('Описание должно быть от 1 до 1000 символов'),
        body('price').optional({ checkFalsy: true }).isFloat({ min: 1, max: 1000000 }).withMessage('Цена должна быть от 1 до 1,000,000'),
        body('type').optional({ checkFalsy: true }).isIn(['direct', 'auction', 'permanent']).withMessage('Тип должен быть direct, auction или permanent'),
        body('durationHours').optional({ checkFalsy: true }).isInt({ min: 1, max: 168 }).withMessage('Длительность должна быть от 1 до 168 часов')
    ],
    validateInput,
    upload.array('images', 6), 
    (req, res) => {
    // Установка значений по умолчанию
    const title = req.body.title || 'Товар';
    const description = req.body.description || 'Описание товара';
    const price = parseFloat(req.body.price) || 100;
    const type = req.body.type || 'direct';
    const durationHours = parseInt(req.body.durationHours) || 24;
    const pinned = req.body.pinned;
    
    const owner = req.session.user ? req.session.user.id : null;
    const id = uuidv4();
    const images = (req.files||[]).map(f => '/uploads/' + f.filename);
    const now = Date.now();
    const listing = {
        id, title, description, price: Number(price)||0, owner, images, type: type||'direct', createdAt: now, bids: [], status: 'open',
        highestBid: null,
        permanent: type === 'permanent',
        pinned: pinned === 'true'
    };
    if (type === 'auction') {
        const hrs = Number(durationHours) || 24;
        listing.endsAt = now + hrs*3600*1000;
    }
    
    // Закрепленные лоты добавляются в начало, остальные - в конец
    if (pinned === 'true') {
    marketplace.unshift(listing);
    } else {
        marketplace.push(listing);
    }
    writeJSON(DB.marketplace, marketplace);
    res.redirect('/market');
});

// Place bid on auction
app.post('/market/bid/:id', (req, res) => {
    const id = req.params.id;
    const amount = Number(req.body.amount)||0;
    const listing = marketplace.find(l=>l.id===id && l.type==='auction' && l.status==='open');
    if (!listing) return res.status(404).send('Auction not found or closed');
    const user = req.session.user ? users[req.session.user.id] : null;
    if (!user) return res.status(401).send('Unauthorized');
    const min = listing.highestBid ? listing.highestBid.amount + 1 : (listing.price || 1);
    if (amount < min) return res.status(400).send('Bid too low');
    listing.highestBid = { amount, bidder: user.id, when: Date.now() };
    listing.bids = listing.bids || [];
    listing.bids.push(listing.highestBid);
    writeJSON(DB.marketplace, marketplace);
    res.redirect('/market');
});

// Buy-now action (with guarantor system)
app.post('/market/buy/:id', (req, res) => {
    const id = req.params.id;
    const listing = marketplace.find(l=>l.id===id && l.status==='open' && l.type!=='auction');
    if (!listing) return res.status(404).send('Listing not found or closed');
    const buyer = req.session.user ? users[req.session.user.id] : null;
    if (!buyer) return res.status(401).send('Unauthorized');
    // Prevent buying your own listing
    const sellerId = listing.owner;
    if (sellerId && req.session.user && req.session.user.id === sellerId) {
        return res.status(400).send('You cannot buy your own listing');
    }
    if (buyer.balance < listing.price) return res.status(400).send('Insufficient balance');
    
    // Check if auto transfer is enabled
    if (listing.autoTransfer) {
        // Direct transfer without guarantor
        const seller = users[sellerId];
        if (!seller) return res.status(404).send('Seller not found');
        
        // Transfer money
    buyer.balance -= listing.price;
        seller.balance += listing.price;
        
        // Add XP for purchase
        addXP(buyer.id, 10, 'покупка в маркете');
        addXP(seller.id, 15, 'продажа в маркете');
        
        // Transfer card to buyer
    buyer.inventory = buyer.inventory || [];
        buyer.inventory.push({
            id: listing.cardData.id,
            name: listing.cardData.name,
            rarity: listing.cardData.rarity,
            image: listing.cardData.image,
            obtainedAt: Date.now()
        });
        
        // Update history
        buyer.history = buyer.history || { bought: [], sold: [] };
        seller.history = seller.history || { bought: [], sold: [] };
        
        buyer.history.bought.push({
            id: listing.id,
            item: listing.title,
            price: listing.price,
            seller: seller.name,
            date: new Date().toISOString()
        });
        
        seller.history.sold.push({
            id: listing.id,
            item: listing.title,
            price: listing.price,
            buyer: buyer.name,
            date: new Date().toISOString()
        });
        
        // Mark listing as sold (but keep it if permanent)
        if (listing.permanent) {
            // For permanent listings, keep them active but track the sale
            listing.lastSoldTo = buyer.id;
            listing.lastSoldAt = new Date().toISOString();
            listing.totalSales = (listing.totalSales || 0) + 1;
            // Keep status as 'open' so it remains available for purchase
        } else {
    listing.status = 'sold';
            listing.buyer = buyer.id;
            listing.soldAt = new Date().toISOString();
        }
        
        // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
        
        return res.redirect('/market?message=Purchase completed successfully! Card transferred to your collection.');
    }
    
    // Original guarantor system for non-auto listings
    const transactionId = uuidv4();
    const transaction = {
        id: transactionId,
        listingId: id,
        buyerId: buyer.id,
        sellerId: sellerId,
        amount: listing.price,
        status: 'pending_guarantor',
        createdAt: Date.now(),
        buyerConfirmed: false,
        sellerConfirmed: false,
        guarantorApproved: false,
        guarantorId: null
    };
    
    // Reserve buyer's money (don't transfer yet)
    buyer.balance -= listing.price;
    buyer.reservedBalance = (buyer.reservedBalance || 0) + listing.price;
    
    // Mark listing as pending guarantor
    listing.status = 'pending_guarantor';
    listing.transactionId = transactionId;
    listing.buyer = buyer.id;
    
    // Save transaction
    let transactions = [];
    try {
        transactions = JSON.parse(fs.readFileSync(path.join(__dirname, 'transactions.json')));
    } catch (e) {
        transactions = [];
    }
    transactions.push(transaction);
    fs.writeFileSync(path.join(__dirname, 'transactions.json'), JSON.stringify(transactions, null, 2));
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.redirect('/market?message=Purchase initiated. Waiting for guarantor approval.');
});

// Profile view and rating, avatar upload
app.get('/profile/:id', requireAuth, (req, res) => {
    const id = req.params.id;
    const person = users[id];
    if (!person) return res.status(404).send('User not found');
    // compute average rating
    const avg = (person.ratings && person.ratings.length) ? (person.ratings.reduce((a,b)=>a+b,0)/person.ratings.length) : null;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    res.render('profile', { user: currentUser, person, avg, balance });
});

app.post('/profile/:id/rate', (req, res) => {
    const id = req.params.id;
    const score = Math.max(1, Math.min(5, Number(req.body.score)||1));
    // Prevent rating yourself
    if (req.session.user && req.session.user.id === id) {
        return res.status(400).send('You cannot rate yourself');
    }
    const person = users[id];
    if (!person) return res.status(404).send('User not found');
    person.ratings = person.ratings || [];
    person.ratings.push(score);
    writeJSON(DB.users, users);
    res.redirect('/profile/' + id);
});

app.post('/profile/:id/avatar', upload.single('avatar'), (req, res) => {
    const id = req.params.id;
    const person = users[id];
    if (!person) return res.status(404).send('User not found');
    if (req.file) {
        person.avatar = '/uploads/' + req.file.filename;
        writeJSON(DB.users, users);
    }
    res.redirect('/profile/' + id);
});

// Simple API endpoints
app.get('/api/marketplace', (req, res) => res.json({ marketplace }));
app.get('/api/users', (req, res) => res.json({ users }));

// API for user listings
app.get('/api/market/listings', (req, res) => {
    try {
        // Enrich listings with owner and buyer information
        const enrichedListings = marketplace.map(listing => {
            const owner = users[listing.owner];
            const buyer = listing.buyer ? users[listing.buyer] : null;
            
            return {
                ...listing,
                ownerName: owner ? owner.name : 'Неизвестный пользователь',
                buyerName: buyer ? buyer.name : null
            };
        });
        
        res.json({ 
            success: true, 
            listings: enrichedListings 
        });
    } catch (error) {
        console.error('Error loading listings:', error);
        res.json({ 
            success: false, 
            error: 'Failed to load listings' 
        });
    }
});

// Admin pin/unpin listing
app.post('/api/admin/pin-listing/:id', requireAuth, requireAdmin, (req, res) => {
    try {
        const listingId = req.params.id;
        const { pinned } = req.body;
        
        const listingIndex = marketplace.findIndex(l => l.id === listingId);
        if (listingIndex === -1) {
            return res.status(404).json({ success: false, error: 'Listing not found' });
        }
        
        const listing = marketplace[listingIndex];
        
        // Update pinned status
        listing.pinned = pinned === true || pinned === 'true';
        
        // Remove from current position
        marketplace.splice(listingIndex, 1);
        
        // Add to appropriate position (pinned items go to the beginning)
        if (listing.pinned) {
            marketplace.unshift(listing);
        } else {
            marketplace.push(listing);
        }
        
        // Save changes
        writeJSON(DB.marketplace, marketplace);
        
        res.json({ 
            success: true, 
            message: listing.pinned ? 'Лот закреплен' : 'Лот откреплен' 
        });
    } catch (error) {
        console.error('Error pinning/unpinning listing:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update listing' 
        });
    }
});

// Messenger route
app.get('/messenger', requireAuth, (req, res) => {
    const currentUser = users[req.session.user.id];
    res.render('messenger', { 
        user: currentUser,
        title: 'Мессенджер'
    });
});

// Messenger API endpoints
app.get('/api/messenger/chats', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const chats = loadChats();
        
        // Filter chats for current user and enrich with user data
        const userChats = chats
            .filter(chat => chat.participants.includes(currentUserId))
            .map(chat => {
                const otherUserId = chat.participants.find(id => id !== currentUserId);
                const otherUser = users[otherUserId];
                
                return {
                    id: chat.id,
                    otherUser: {
                        id: otherUserId,
                        name: otherUser ? otherUser.name : 'Неизвестный пользователь',
                        avatar: otherUser ? otherUser.avatar : null
                    },
                    lastMessage: chat.lastMessage,
                    lastMessageTime: chat.lastMessageTime,
                    unreadCount: chat.unreadCount || 0,
                    hasUnread: (chat.unreadCount || 0) > 0
                };
            })
            .sort((a, b) => new Date(b.lastMessageTime || 0) - new Date(a.lastMessageTime || 0));
        
        res.json({ success: true, chats: userChats });
    } catch (error) {
        console.error('Error loading chats:', error);
        res.status(500).json({ success: false, error: 'Failed to load chats' });
    }
});

app.get('/api/messenger/chat/:id', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const chatId = req.params.id;
        const chats = loadChats();
        
        const chat = chats.find(c => c.id === chatId);
        if (!chat || !chat.participants.includes(currentUserId)) {
            return res.status(404).json({ success: false, error: 'Chat not found' });
        }
        
        const otherUserId = chat.participants.find(id => id !== currentUserId);
        const otherUser = users[otherUserId];
        
        res.json({
            success: true,
            chat: {
                id: chat.id,
                otherUser: {
                    id: otherUserId,
                    name: otherUser ? otherUser.name : 'Неизвестный пользователь',
                    avatar: otherUser ? otherUser.avatar : null
                }
            }
        });
    } catch (error) {
        console.error('Error loading chat:', error);
        res.status(500).json({ success: false, error: 'Failed to load chat' });
    }
});

app.get('/api/messenger/messages/:chatId', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const chatId = req.params.chatId;
        const chats = loadChats();
        
        const chat = chats.find(c => c.id === chatId);
        if (!chat || !chat.participants.includes(currentUserId)) {
            return res.status(404).json({ success: false, error: 'Chat not found' });
        }
        
        const messages = loadMessages();
        const chatMessages = messages
            .filter(msg => msg.chatId === chatId)
            .map(msg => ({
                ...msg,
                isOwn: msg.senderId === currentUserId
            }))
            .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
        
        res.json({ success: true, messages: chatMessages });
    } catch (error) {
        console.error('Error loading messages:', error);
        res.status(500).json({ success: false, error: 'Failed to load messages' });
    }
});

app.post('/api/messenger/send', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const { chatId, content } = req.body;
        
        if (!chatId || !content || content.trim().length === 0) {
            return res.status(400).json({ success: false, error: 'Chat ID and content are required' });
        }
        
        const chats = loadChats();
        const chat = chats.find(c => c.id === chatId);
        if (!chat || !chat.participants.includes(currentUserId)) {
            return res.status(404).json({ success: false, error: 'Chat not found' });
        }
        
        const messages = loadMessages();
        const newMessage = {
            id: Date.now().toString(),
            chatId: chatId,
            senderId: currentUserId,
            content: content.trim(),
            createdAt: new Date().toISOString()
        };
        
        messages.push(newMessage);
        saveMessages(messages);
        
        // Update chat last message
        chat.lastMessage = content.trim();
        chat.lastMessageTime = new Date().toISOString();
        saveChats(chats);
        
        res.json({ success: true, message: newMessage });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ success: false, error: 'Failed to send message' });
    }
});

app.get('/api/messenger/search-users', requireAuth, (req, res) => {
    try {
        const query = req.query.q;
        const currentUserId = req.session.user.id;
        
        if (!query || query.length < 2) {
            return res.json({ success: true, users: [] });
        }
        
        const searchResults = Object.values(users)
            .filter(user => 
                user.id !== currentUserId && 
                user.name.toLowerCase().includes(query.toLowerCase())
            )
            .slice(0, 10)
            .map(user => ({
                id: user.id,
                name: user.name,
                avatar: user.avatar
            }));
        
        res.json({ success: true, users: searchResults });
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({ success: false, error: 'Failed to search users' });
    }
});

app.post('/api/messenger/create-chat', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const { recipientId } = req.body;
        
        if (!recipientId || recipientId === currentUserId) {
            return res.status(400).json({ success: false, error: 'Invalid recipient' });
        }
        
        if (!users[recipientId]) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const chats = loadChats();
        
        // Check if chat already exists
        const existingChat = chats.find(chat => 
            chat.participants.includes(currentUserId) && 
            chat.participants.includes(recipientId)
        );
        
        if (existingChat) {
            return res.json({ success: true, chatId: existingChat.id });
        }
        
        // Create new chat
        const newChat = {
            id: Date.now().toString(),
            participants: [currentUserId, recipientId],
            createdAt: new Date().toISOString(),
            lastMessage: null,
            lastMessageTime: null
        };
        
        chats.push(newChat);
        saveChats(chats);
        
        res.json({ success: true, chatId: newChat.id });
    } catch (error) {
        console.error('Error creating chat:', error);
        res.status(500).json({ success: false, error: 'Failed to create chat' });
    }
});

app.get('/api/messenger/unread-count', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const chats = loadChats();
        
        // Count unread messages across all user's chats
        let totalUnread = 0;
        chats.forEach(chat => {
            if (chat.participants.includes(currentUserId)) {
                totalUnread += chat.unreadCount || 0;
            }
        });
        
        res.json({ success: true, unreadCount: totalUnread });
    } catch (error) {
        console.error('Error getting unread count:', error);
        res.status(500).json({ success: false, error: 'Failed to get unread count' });
    }
});

// Admin endpoints for user management
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    try {
        console.log('🔍 Admin users API called by:', req.session.user?.id);
        console.log('📊 Total users in database:', Object.keys(users).length);
        
        const usersList = Object.values(users).map(user => ({
            id: user.id,
            name: user.name,
            avatar: user.avatar,
            role: user.role || 'user',
            balance: user.balance || 0,
            inventory: user.inventory || []
        }));
        
        console.log('✅ Returning users list:', usersList.length, 'users');
        res.json({ success: true, users: usersList });
    } catch (error) {
        console.error('❌ Error loading users:', error);
        res.status(500).json({ success: false, error: 'Failed to load users' });
    }
});

app.post('/api/admin/change-role', requireAuth, requireAdmin, (req, res) => {
    try {
        const { userId, role } = req.body;
        
        if (!userId || !role) {
            return res.status(400).json({ success: false, error: 'User ID and role are required' });
        }
        
        if (!['user', 'moderator', 'admin'].includes(role)) {
            return res.status(400).json({ success: false, error: 'Invalid role' });
        }
        
        const user = users[userId];
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        user.role = role;
        writeJSON(DB.users, users);
        
        console.log(`Admin ${req.session.user.id} changed role of user ${userId} to ${role}`);
        
        res.json({ success: true, message: `User role changed to ${role}` });
    } catch (error) {
        console.error('Error changing user role:', error);
        res.status(500).json({ success: false, error: 'Failed to change user role' });
    }
});

app.post('/api/messenger/transfer', requireAuth, (req, res) => {
    try {
        const currentUserId = req.session.user.id;
        const { chatId, amount, message } = req.body;
        
        if (!chatId || !amount || amount <= 0) {
            return res.status(400).json({ success: false, error: 'Chat ID and valid amount are required' });
        }
        
        const chats = loadChats();
        const chat = chats.find(c => c.id === chatId);
        if (!chat || !chat.participants.includes(currentUserId)) {
            return res.status(404).json({ success: false, error: 'Chat not found' });
        }
        
        const currentUser = users[currentUserId];
        if (!currentUser || currentUser.balance < amount) {
            return res.status(400).json({ success: false, error: 'Insufficient balance' });
        }
        
        // Find recipient
        const recipientId = chat.participants.find(id => id !== currentUserId);
        const recipient = users[recipientId];
        if (!recipient) {
            return res.status(404).json({ success: false, error: 'Recipient not found' });
        }
        
        // Transfer coins
        currentUser.balance -= amount;
        recipient.balance = (recipient.balance || 0) + amount;
        
        // Create transfer message
        const messages = loadMessages();
        const transferMessage = {
            id: Date.now().toString(),
            chatId: chatId,
            senderId: currentUserId,
            content: `💰 Перевод ${amount} NMCoin${message ? ` - ${message}` : ''}`,
            type: 'transfer',
            transferData: {
                amount: amount,
                message: message,
                recipientId: recipientId
            },
            createdAt: new Date().toISOString()
        };
        
        messages.push(transferMessage);
        saveMessages(messages);
        
        // Update chat last message
        chat.lastMessage = `💰 Перевод ${amount} NMCoin`;
        chat.lastMessageTime = new Date().toISOString();
        saveChats(chats);
        
        // Save user data
        writeJSON(DB.users, users);
        
        res.json({ success: true, message: 'Transfer completed successfully' });
    } catch (error) {
        console.error('Error transferring coins:', error);
        res.status(500).json({ success: false, error: 'Failed to transfer coins' });
    }
});

// Demo admin login - quick switch to admin account for testing
app.get('/auth/admin', (req, res) => {
    const adminId = 'admin_demo';
    if (!users[adminId]) {
        users[adminId] = { id: adminId, name: 'DemoAdmin', balance: 10000, ratings: [], inventory: [], avatar: null, history:{bought:[],sold:[]}, role: 'admin', pityCounter: 0 };
        writeJSON(DB.users, users);
    }
    req.session.user = { id: adminId };
    res.redirect('/market');
});



// Discord OAuth routes
app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    }
);

// Reset all user balances to 0
app.get('/admin/reset-coins', requireAuth, requireAdmin, (req, res) => {
    
    // Reset all user balances to 0
    for (let userId in users) {
        users[userId].balance = 0;
        users[userId].reservedBalance = 0;
    }
    
    writeJSON(DB.users, users);
    res.json({ success: true, message: 'All user balances reset to 0' });
});

// Clear all marketplace listings
app.get('/admin/clear-listings', requireAuth, requireAdmin, (req, res) => {
    
    // Clear all marketplace listings
    marketplace.length = 0;
    writeJSON(DB.marketplace, marketplace);
    res.json({ success: true, message: 'All marketplace listings cleared' });
});


// Admin login page
app.get('/logadmin', (req, res) => {
    res.render('logadmin', { error: null });
});

// Admin login handler
app.post('/logadmin', (req, res) => {
    const { password } = req.body;
    const adminPassword = 'MercyMMO!2';
    
    if (password === adminPassword) {
        const adminId = 'admin_user';
        if (!users[adminId]) {
            users[adminId] = { 
                id: adminId, 
                name: 'Admin User', 
                balance: 10000, 
                ratings: [], 
                inventory: [], 
                avatar: null, 
                history: { bought: [], sold: [] }, 
                role: 'admin',
                pityCounter: 0
            };
        writeJSON(DB.users, users);
    }
        req.session.user = { id: adminId };
        res.redirect('/admin');
    } else {
        res.render('logadmin', { error: 'Неверный пароль. Попробуйте снова.' });
    }
});

// News page
app.get('/news', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    const page = parseInt(req.query.page) || 1;
    const limit = 6;
    
    // Load news from file
    let newsData = [];
    try {
        newsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'news.json')));
    } catch (e) {
        // Create empty news file if it doesn't exist
        newsData = [];
        fs.writeFileSync(path.join(__dirname, 'news.json'), JSON.stringify(newsData, null, 2));
    }
    
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedNews = newsData.slice(startIndex, endIndex);
    const totalPages = Math.ceil(newsData.length / limit);
    
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    res.render('news', { 
        user: currentUser, 
        news: paginatedNews, 
        currentPage: page, 
        totalPages: totalPages,
        balance: balance
    });
});

// Single news article
app.get('/news/:id', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    const articleId = req.params.id;
    
    let newsData = [];
    try {
        newsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'news.json')));
    } catch (e) {
        return res.status(404).send('News not found');
    }
    
    const article = newsData.find(n => n.id === articleId);
    if (!article) {
        return res.status(404).send('Article not found');
    }
    
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    res.render('news-article', { 
        user: currentUser, 
        article: article,
        balance: balance
    });
});

// Quests system
app.get('/quests', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).render('login-required', { message: 'Необходимо войти в систему' });
    }
    
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    
    // Daily quest logic
    const today = new Date().toDateString();
    const lastDaily = currentUser.lastDailyQuest || null;
    const canClaimDaily = lastDaily !== today;
    
    // Monthly bonus logic
    const currentMonth = new Date().getMonth();
    const currentYear = new Date().getFullYear();
    const lastMonthly = currentUser.lastMonthlyBonus || null;
    const canClaimMonthly = !lastMonthly || 
        (new Date(lastMonthly).getMonth() !== currentMonth || new Date(lastMonthly).getFullYear() !== currentYear);
    
    res.render('quests', { 
        user: currentUser, 
        balance: balance,
        canClaimDaily: canClaimDaily,
        canClaimMonthly: canClaimMonthly,
        lastDailyQuest: lastDaily,
        lastMonthlyBonus: lastMonthly
    });
});

// Claim daily quest
app.post('/quests/daily', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).send('Unauthorized');
    }
    
    const today = new Date().toDateString();
    const lastDaily = currentUser.lastDailyQuest || null;
    
    if (lastDaily === today) {
        return res.status(400).send('Daily quest already claimed today');
    }
    
    // Calculate reward (10 coins + double each day)
    const streak = currentUser.dailyStreak || 0;
    const reward = 10 * Math.pow(2, streak);
    
    currentUser.balance = (currentUser.balance || 0) + reward;
    currentUser.lastDailyQuest = today;
    currentUser.dailyStreak = streak + 1;
    
    writeJSON(DB.users, users);
    res.json({ success: true, reward: reward, newBalance: currentUser.balance });
});

// Claim monthly bonus
app.post('/quests/monthly', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).send('Unauthorized');
    }
    
    const currentMonth = new Date().getMonth();
    const currentYear = new Date().getFullYear();
    const lastMonthly = currentUser.lastMonthlyBonus || null;
    
    if (lastMonthly && 
        new Date(lastMonthly).getMonth() === currentMonth && 
        new Date(lastMonthly).getFullYear() === currentYear) {
        return res.status(400).send('Monthly bonus already claimed this month');
    }
    
    const reward = 500;
    currentUser.balance = (currentUser.balance || 0) + reward;
    currentUser.lastMonthlyBonus = new Date().toISOString();
    
    writeJSON(DB.users, users);
    res.json({ success: true, reward: reward, newBalance: currentUser.balance });
});

// Games page
app.get('/games', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).render('login-required', { message: 'Необходимо войти в систему' });
    }
    
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    res.render('games', { user: currentUser, balance: balance });
});

// Update balance from games
app.post('/games/update-balance', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    const { amount } = req.body;
    const changeAmount = parseInt(amount) || 0;
    
    if (changeAmount < 0 && Math.abs(changeAmount) > currentUser.balance) {
        return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    currentUser.balance = (currentUser.balance || 0) + changeAmount;
    writeJSON(DB.users, users);
    
    res.json({ success: true, newBalance: currentUser.balance });
});

// Simple logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
    res.redirect('/');
    });
});


// Cards route (renders cards.ejs)
app.get('/cards', requireAuth, (req, res) => {
    const currentUser = users[req.session.user?.id] || null;
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    // load cards.json directly
    const cards = loadCards();
    res.render('cards', { user: currentUser, cards, balance });
});

// Collection route - user's inventory

// Admin route
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
    const currentUser = users[req.session.user?.id] || null;
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    // load data for admin
    const itemsData = loadItems();
    const items = Array.isArray(itemsData) ? itemsData : Object.values(itemsData);
    const cards = loadCards();
    const packs = loadPacks();
    const transactions = loadTransactions();
    res.render('admin', { user: currentUser, items, cards, packs, transactions, balance });
});

// Admin card management
app.post('/admin/cards/add', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const { id, name, rarity, image, collection } = req.body;
    
    if (!id || !name || !rarity || !collection) {
        return res.status(400).send('Missing required fields');
    }
    
    // Check if card already exists
    const cards = loadCards();
    
    if (cards.find(c => c.id === id)) {
        return res.status(400).send('Card with this ID already exists');
    }
    
    const newCard = {
        id: id,
        name: name,
        rarity: rarity,
        image: image || null,
        collection: collection
    };
    
    cards.push(newCard);
    fs.writeFileSync(path.join(__dirname, 'cards.json'), JSON.stringify(cards, null, 2));
    
    res.redirect('/admin?tab=cards&message=Card added successfully');
});

app.post('/admin/cards/delete', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const { id } = req.body;
    
    if (!id) {
        return res.status(400).send('Card ID required');
    }
    
    const cards = loadCards();
    
    const cardIndex = cards.findIndex(c => c.id === id);
    if (cardIndex === -1) {
        return res.status(404).send('Card not found');
    }
    
    cards.splice(cardIndex, 1);
    fs.writeFileSync(path.join(__dirname, 'cards.json'), JSON.stringify(cards, null, 2));
    
    res.redirect('/admin?tab=cards&message=Card deleted successfully');
});

// Admin pack management
app.post('/admin/packs/add', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const { id, name, price, count } = req.body;
    
    if (!id || !name || !price || !count) {
        return res.status(400).send('Missing required fields');
    }
    
    let packs = [];
    try { packs = JSON.parse(fs.readFileSync(path.join(__dirname,'packs.json'))); } catch (e) { packs = []; }
    
    // Check if pack already exists
    if (packs.find(p => p.id === id)) {
        return res.status(400).send('Pack with this ID already exists');
    }
    
    const newPack = {
        id: id,
        name: name,
        price: parseInt(price),
        count: parseInt(count),
        contents: []
    };
    
    packs.push(newPack);
    fs.writeFileSync(path.join(__dirname, 'packs.json'), JSON.stringify(packs, null, 2));
    
    res.redirect('/admin?tab=packs&message=Pack created successfully');
});

app.post('/admin/packs/delete', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const { id } = req.body;
    
    if (!id) {
        return res.status(400).send('Pack ID required');
    }
    
    let packs = [];
    try { packs = JSON.parse(fs.readFileSync(path.join(__dirname,'packs.json'))); } catch (e) { packs = []; }
    
    const packIndex = packs.findIndex(p => p.id === id);
    if (packIndex === -1) {
        return res.status(404).send('Pack not found');
    }
    
    packs.splice(packIndex, 1);
    fs.writeFileSync(path.join(__dirname, 'packs.json'), JSON.stringify(packs, null, 2));
    
    res.redirect('/admin?tab=packs&message=Pack deleted successfully');
});

app.post('/admin/packs/addcard', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const { packId, cardId, weight } = req.body;
    
    if (!packId || !cardId || !weight) {
        return res.status(400).send('Missing required fields');
    }
    
    const packs = loadPacks();
    const cards = loadCards();
    
    const pack = packs.find(p => p.id === packId);
    if (!pack) {
        return res.status(404).send('Pack not found');
    }
    
    const card = cards.find(c => c.id === cardId);
    if (!card) {
        return res.status(404).send('Card not found');
    }
    
    // Check if card already in pack
    if (pack.contents.find(c => c.cardId === cardId)) {
        return res.status(400).send('Card already in pack');
    }
    
    pack.contents.push({
        cardId: cardId,
        weight: parseInt(weight)
    });
    
    fs.writeFileSync(path.join(__dirname, 'packs.json'), JSON.stringify(packs, null, 2));
    
    res.redirect('/admin?tab=packs&message=Card added to pack successfully');
});

// Test route
app.get('/api/test', (req, res) => {
    res.json({ success: true, message: 'Server is working' });
});

// Gacha System
app.post('/api/gacha/pull', 
    requireAuthJSON, 
    strictLimiter,
    sanitizeInput,
    [
        body('type').isIn(['single', 'ten', 'legendary']).withMessage('Некорректный тип гача'),
        body('collection').optional().isString().withMessage('Некорректная коллекция')
    ],
    validateInput,
    (req, res) => {
    console.log('=== GACHA REQUEST ===');
    console.log('Gacha request received:', req.body);
    console.log('Session user:', req.session.user);
    console.log('Request headers:', req.headers);
    
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        console.log('No current user found');
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    console.log('Current user:', currentUser);
    
    const { type, collection = 'all' } = req.body;
    
    // Load collections
    let collections = {};
    try {
        collections = JSON.parse(fs.readFileSync(path.join(__dirname, 'collections.json')));
    } catch (e) {
        collections = {};
    }
    
    // Calculate costs based on collection
    let baseCosts = {
        'single': 50,
        'ten': 450,
        'legendary': 6000
    };
    
    // Apply collection multiplier
    let costMultiplier = 1;
    if (collection !== 'all' && collections[collection]) {
        costMultiplier = 1.5; // 50% more expensive for specific collections
    }
    
    const costs = {};
    for (const [gachaType, baseCost] of Object.entries(baseCosts)) {
        costs[gachaType] = Math.floor(baseCost * costMultiplier);
    }
    
    const cost = costs[type];
    if (!cost) {
        return res.status(400).json({ success: false, error: 'Invalid gacha type' });
    }
    
    if (currentUser.balance < cost) {
        return res.status(400).json({ success: false, error: 'Insufficient balance' });
    }
    
    // Initialize pity system
    currentUser.pityCounter = currentUser.pityCounter || 0;
    currentUser.pityCounter += type === 'ten' ? 10 : 1;
    
    // Auto-save pity counter immediately
    writeJSON(DB.users, users);
    console.log(`Pity counter updated: ${currentUser.pityCounter} for user ${currentUser.id}`);
    
    // Load cards
    let cards = [];
    try { 
        cards = JSON.parse(fs.readFileSync(path.join(__dirname, 'cards.json'))); 
        console.log('Loaded cards:', cards.length);
    } catch (e) { 
        console.error('Error loading cards:', e);
        cards = []; 
    }
    
    // Filter cards by collection if specified
    if (collection !== 'all' && collections[collection] && collections[collection].cards) {
        const collectionCardIds = collections[collection].cards;
        cards = cards.filter(card => collectionCardIds.includes(card.id));
        console.log('Filtered cards for collection:', cards.length);
    }
    
    if (cards.length === 0) {
        console.error('No cards available for collection:', collection);
        return res.status(400).json({ success: false, error: 'No cards available for this collection' });
    }
    
    // Perform gacha
    let results = [];
    
    // Check pity system (80 pulls = guaranteed legendary)
    if (currentUser.pityCounter >= 80) {
        console.log('Pity system triggered! Guaranteed legendary card!');
        try {
            if (type === 'ten') {
                results = [];
                for (let i = 0; i < 9; i++) {
                    const card = getRandomCard(cards, 'ten');
                    if (card) results.push(card);
                }
                // Guaranteed legendary for 10th card
                const legendaryCard = getRandomCard(cards, 'legendary');
                if (legendaryCard) results.push(legendaryCard);
            } else {
                const legendaryCard = getRandomCard(cards, 'legendary');
                if (legendaryCard) results = [legendaryCard];
            }
        } catch (error) {
            console.error('Error in pity system:', error);
            return res.status(500).json({ success: false, error: 'Failed to generate legendary card' });
        }
        currentUser.pityCounter = 0; // Reset pity counter
        // Auto-save pity counter reset
        writeJSON(DB.users, users);
        console.log(`Pity counter reset to 0 for user ${currentUser.id} - legendary card guaranteed!`);
    } else if (type === 'legendary') {
        // Premium gacha - only legendary cards
        try {
            const card = getRandomCard(cards, 'legendary');
            if (card) results = [card];
        } catch (error) {
            console.error('Error in legendary gacha:', error);
            return res.status(500).json({ success: false, error: 'Failed to generate legendary card' });
        }
    } else if (type === 'single') {
        try {
            const card = getRandomCard(cards, 'single');
            if (card) results = [card];
        } catch (error) {
            console.error('Error in single gacha:', error);
            return res.status(500).json({ success: false, error: 'Failed to generate card' });
        }
    } else if (type === 'ten') {
        try {
            results = [];
            for (let i = 0; i < 9; i++) {
                const card = getRandomCard(cards, 'ten');
                if (card) results.push(card);
            }
            // Guaranteed rare or better for 10th card
            const guaranteedCard = getRandomCard(cards, 'ten_guaranteed');
            if (guaranteedCard) results.push(guaranteedCard);
        } catch (error) {
            console.error('Error in ten gacha:', error);
            return res.status(500).json({ success: false, error: 'Failed to generate cards' });
        }
    }
    
    // Check if we got valid results
    if (!results || results.length === 0 || results.some(card => !card)) {
        console.error('Invalid gacha results:', results);
        console.error('Cards available:', cards.length);
        console.error('Collection:', collection);
        return res.status(500).json({ success: false, error: 'Failed to generate cards' });
    }
    
    // Deduct cost
    currentUser.balance -= cost;
    
    // Add XP for gacha pull
    const xpAmount = type === 'ten' ? 20 : 5;
    addXP(currentUser.id, xpAmount, `гача ${type === 'ten' ? '10 круток' : '1 крутка'}`);
    
    // Add cards to inventory
    currentUser.inventory = currentUser.inventory || [];
    results.forEach(card => {
        if (card) {
            currentUser.inventory.push({
                id: card.id,
                name: card.name,
                rarity: card.rarity,
                image: card.image,
                obtainedAt: Date.now()
            });
        }
    });
    
    // Final save - balance, inventory, XP, and any remaining changes
    writeJSON(DB.users, users);
    
    res.json({
        success: true,
        cards: results,
        balance: currentUser.balance,
        pityCounter: currentUser.pityCounter
    });
});

function getRandomCard(cards, type) {
    console.log('getRandomCard called with:', { cardsLength: cards?.length, type });
    
    const rates = {
        'single': { common: 60, uncommon: 25, rare: 12, epic: 2.5, legendary: 0.5 },
        'ten': { common: 50, uncommon: 30, rare: 15, epic: 4, legendary: 1 },
        'ten_guaranteed': { common: 0, uncommon: 0, rare: 70, epic: 25, legendary: 5 },
        'premium': { common: 0, uncommon: 0, rare: 0, epic: 80, legendary: 20 },
        'legendary': { common: 0, uncommon: 0, rare: 0, epic: 0, legendary: 100 }
    };
    
    const rate = rates[type];
    if (!rate) {
        console.error('Unknown gacha type:', type);
        if (cards && cards.length > 0) {
            return cards[Math.floor(Math.random() * cards.length)];
        }
        return null;
    }
    
    const random = Math.random() * 100;
    
    let targetRarity = 'common';
    let cumulative = 0;
    
    try {
        for (const [rarity, chance] of Object.entries(rate)) {
            cumulative += chance;
            if (random <= cumulative) {
                targetRarity = rarity;
                break;
            }
        }
    } catch (error) {
        console.error('Error in rate calculation:', error);
        console.error('Rate object:', rate);
        targetRarity = 'common'; // Fallback
    }
    
    // Check if cards array is valid
    if (!cards || cards.length === 0) {
        console.error('No cards available');
        return null;
    }
    
    // Filter cards by rarity
    const availableCards = cards.filter(card => card.rarity === targetRarity);
    
    if (availableCards.length === 0) {
        // Fallback to any card if no cards of target rarity
        return cards[Math.floor(Math.random() * cards.length)];
    }
    
    return availableCards[Math.floor(Math.random() * availableCards.length)];
}

// Get user's cards
app.get('/api/user/cards', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    const userCards = currentUser.inventory || [];
    res.json({
        success: true,
        cards: userCards
    });
});

// Get all available cards
app.get('/api/cards', (req, res) => {
    try {
        const allCards = JSON.parse(fs.readFileSync(path.join(__dirname, 'cards.json')));
        res.json({ success: true, cards: allCards });
    } catch (error) {
        console.error('Error loading cards:', error);
        res.status(500).json({ success: false, error: 'Failed to load cards' });
    }
});

// Sell card from collection
app.post('/api/cards/sell', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    const { cardId, price } = req.body;
    
    if (!cardId || !price || price <= 0) {
        return res.status(400).json({ success: false, error: 'Invalid card ID or price' });
    }
    
    // Find card in user's inventory
    const cardIndex = currentUser.inventory.findIndex(card => card.id === cardId);
    if (cardIndex === -1) {
        return res.status(404).json({ success: false, error: 'Card not found in your collection' });
    }
    
    const card = currentUser.inventory[cardIndex];
    
    // Remove card from inventory
    currentUser.inventory.splice(cardIndex, 1);
    
    // Add to marketplace
    const listingId = Date.now().toString();
    const listing = {
        id: listingId,
        title: `Продажа карты: ${card.name}`,
        description: `Карта редкости: ${card.rarity}`,
        price: parseInt(price),
        type: 'direct',
        owner: currentUser.id,
        ownerName: currentUser.name,
        ownerAvatar: currentUser.avatar,
        cardData: card,
        createdAt: new Date().toISOString(),
        status: 'active',
        autoTransfer: true  // Автоматическая передача
    };
    
    marketplace.push(listing);
    
    // Add XP for creating listing
    addXP(owner, 8, 'создание лота в маркете');
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Card listed for sale successfully',
        listingId: listingId
    });
});

// Create auction for card
app.post('/api/cards/auction', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    const { cardId, startingPrice, duration } = req.body;
    
    if (!cardId || !startingPrice || startingPrice <= 0) {
        return res.status(400).json({ success: false, error: 'Invalid card ID or starting price' });
    }
    
    // Find card in user's inventory
    const cardIndex = currentUser.inventory.findIndex(card => card.id === cardId);
    if (cardIndex === -1) {
        return res.status(404).json({ success: false, error: 'Card not found in your collection' });
    }
    
    const card = currentUser.inventory[cardIndex];
    
    // Remove card from inventory
    currentUser.inventory.splice(cardIndex, 1);
    
    // Calculate auction end time
    const auctionDuration = parseInt(duration) || 24; // Default 24 hours
    const endTime = new Date(Date.now() + auctionDuration * 60 * 60 * 1000);
    
    // Add to marketplace as auction
    const listingId = Date.now().toString();
    const listing = {
        id: listingId,
        title: `Аукцион карты: ${card.name}`,
        description: `Карта редкости: ${card.rarity}. Аукцион длится ${auctionDuration} часов`,
        price: parseInt(startingPrice),
        currentBid: parseInt(startingPrice),
        type: 'auction',
        owner: currentUser.id,
        ownerName: currentUser.name,
        ownerAvatar: currentUser.avatar,
        cardData: card,
        createdAt: new Date().toISOString(),
        endTime: endTime.toISOString(),
        status: 'active',
        autoTransfer: true,
        bids: []
    };
    
    marketplace.push(listing);
    
    // Add XP for creating listing
    addXP(owner, 8, 'создание лота в маркете');
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Auction created successfully',
        listingId: listingId,
        endTime: endTime.toISOString()
    });
});

// Get user collections progress
app.get('/api/user/collections', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    // Define collections
    const collections = {
        'launch_2025': {
            name: 'Запуск 2025',
            description: 'Первая коллекция карт',
            cards: ['c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'c10'],
            reward: 1000
        }
    };
    
    // Calculate progress for each collection
    const userCards = currentUser.inventory || [];
    const userCardIds = userCards.map(card => card.id);
    
    const progress = {};
    for (const [collectionId, collection] of Object.entries(collections)) {
        const ownedCards = collection.cards.filter(cardId => userCardIds.includes(cardId));
        const uniqueOwnedCards = [...new Set(ownedCards)];
        const percentage = Math.round((uniqueOwnedCards.length / collection.cards.length) * 100);
        
        progress[collectionId] = {
            ...collection,
            ownedCards: uniqueOwnedCards,
            totalCards: collection.cards.length,
            percentage: percentage,
            completed: percentage === 100
        };
    }
    
    res.json({ success: true, collections: progress });
});

// Recycle duplicate cards
app.post('/api/cards/recycle', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    const { cardIds } = req.body;
    
    if (!cardIds || !Array.isArray(cardIds) || cardIds.length === 0) {
        return res.status(400).json({ success: false, error: 'Invalid card IDs' });
    }
    
    // Define recycling values
    const recyclingValues = {
        'common': 10,
        'uncommon': 15,
        'rare': 25,
        'epic': 50,
        'legendary': 100
    };
    
    let totalCoins = 0;
    const recycledCards = [];
    
    // Process each card
    for (const cardId of cardIds) {
        const cardIndex = currentUser.inventory.findIndex(card => card.id === cardId);
        if (cardIndex !== -1) {
            const card = currentUser.inventory[cardIndex];
            const coinValue = recyclingValues[card.rarity] || 10;
            
            totalCoins += coinValue;
            recycledCards.push({
                id: card.id,
                name: card.name,
                rarity: card.rarity,
                coins: coinValue
            });
            
            // Remove card from inventory
            currentUser.inventory.splice(cardIndex, 1);
        }
    }
    
    if (totalCoins === 0) {
        return res.status(400).json({ success: false, error: 'No valid cards to recycle' });
    }
    
    // Add coins to user balance
    currentUser.balance = (currentUser.balance || 0) + totalCoins;
    
    // Save changes
    writeJSON(DB.users, users);
    
    res.json({ 
        success: true, 
        message: `Recycled ${recycledCards.length} cards for ${totalCoins} NMCoin`,
        totalCoins: totalCoins,
        recycledCards: recycledCards,
        newBalance: currentUser.balance
    });
});

// Delete listing (only by owner)
app.post('/api/market/delete/:id', (req, res) => {
    const listingId = req.params.id;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    // Find listing
    const listingIndex = marketplace.findIndex(l => l.id === listingId);
    if (listingIndex === -1) {
        return res.status(404).json({ success: false, error: 'Listing not found' });
    }
    
    const listing = marketplace[listingIndex];
    
    // Check if user is the owner
    if (listing.owner !== currentUser.id) {
        return res.status(403).json({ success: false, error: 'You can only delete your own listings' });
    }
    
    // Check if listing is not sold
    if (listing.status === 'sold') {
        return res.status(400).json({ success: false, error: 'Cannot delete sold listings' });
    }
    
    // Return card to owner's inventory if it's a card listing
    if (listing.cardData) {
        currentUser.inventory = currentUser.inventory || [];
        currentUser.inventory.push({
            id: listing.cardData.id,
            name: listing.cardData.name,
            rarity: listing.cardData.rarity,
            image: listing.cardData.image,
            obtainedAt: Date.now()
        });
    }
    
    // Mark listing as sold instead of removing
    marketplace[listingIndex].status = 'sold';
    marketplace[listingIndex].soldAt = Date.now();
    marketplace[listingIndex].buyer = buyer.id;
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Listing deleted successfully'
    });
});

// Get pending transactions for admin approval
app.get('/api/admin/pending-transactions', requireAuth, requireModerator, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'moderator')) {
        return res.status(403).json({ success: false, error: 'Admin or moderator access required' });
    }
    
    // Find transactions that need admin approval
    const pendingTransactions = marketplace.filter(listing => 
        listing.status === 'pending_guarantor' && listing.guarantor
    );
    
    res.json({ 
        success: true, 
        transactions: pendingTransactions
    });
});

// Approve transaction
app.post('/api/admin/approve-transaction/:id', (req, res) => {
    const transactionId = req.params.id;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'moderator')) {
        return res.status(403).json({ success: false, error: 'Admin or moderator access required' });
    }
    
    // Find transaction
    const listing = marketplace.find(l => l.id === transactionId);
    if (!listing) {
        return res.status(404).json({ success: false, error: 'Transaction not found' });
    }
    
    if (listing.status !== 'pending_guarantor') {
        return res.status(400).json({ success: false, error: 'Transaction is not pending approval' });
    }
    
    // Get buyer and seller
    const buyer = users[listing.buyer];
    const seller = users[listing.owner];
    
    if (!buyer || !seller) {
        return res.status(404).json({ success: false, error: 'Buyer or seller not found' });
    }
    
    // Transfer money from guarantor to seller
    seller.balance = (seller.balance || 0) + listing.price;
    
    // Transfer item to buyer (if it's a card)
    if (listing.cardData) {
        buyer.inventory = buyer.inventory || [];
        buyer.inventory.push({
            id: listing.cardData.id,
            name: listing.cardData.name,
            rarity: listing.cardData.rarity,
            image: listing.cardData.image,
            obtainedAt: Date.now()
        });
    }
    
    // Update history
    buyer.history = buyer.history || { bought: [], sold: [] };
    seller.history = seller.history || { bought: [], sold: [] };
    
    buyer.history.bought.push({
        id: listing.id,
        item: listing.title,
        price: listing.price,
        seller: seller.name,
        date: new Date().toISOString()
    });
    
    seller.history.sold.push({
        id: listing.id,
        item: listing.title,
        price: listing.price,
        buyer: buyer.name,
        date: new Date().toISOString()
    });
    
    // Mark transaction as completed
    listing.status = 'sold';
    listing.soldAt = new Date().toISOString();
    listing.approvedBy = currentUser.id;
    listing.approvedAt = new Date().toISOString();
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Transaction approved successfully'
    });
});

// Reject transaction
app.post('/api/admin/reject-transaction/:id', (req, res) => {
    const transactionId = req.params.id;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'moderator')) {
        return res.status(403).json({ success: false, error: 'Admin or moderator access required' });
    }
    
    // Find transaction
    const listing = marketplace.find(l => l.id === transactionId);
    if (!listing) {
        return res.status(404).json({ success: false, error: 'Transaction not found' });
    }
    
    if (listing.status !== 'pending_guarantor') {
        return res.status(400).json({ success: false, error: 'Transaction is not pending approval' });
    }
    
    // Get buyer and seller
    const buyer = users[listing.buyer];
    const seller = users[listing.owner];
    
    if (!buyer || !seller) {
        return res.status(404).json({ success: false, error: 'Buyer or seller not found' });
    }
    
    // Return money to buyer
    buyer.balance = (buyer.balance || 0) + listing.price;
    
    // Return item to seller (if it's a card)
    if (listing.cardData) {
        seller.inventory = seller.inventory || [];
        seller.inventory.push({
            id: listing.cardData.id,
            name: listing.cardData.name,
            rarity: listing.cardData.rarity,
            image: listing.cardData.image,
            obtainedAt: Date.now()
        });
    }
    
    // Mark transaction as rejected
    listing.status = 'rejected';
    listing.rejectedBy = currentUser.id;
    listing.rejectedAt = new Date().toISOString();
    listing.rejectionReason = req.body.reason || 'Transaction rejected by admin';
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Transaction rejected successfully'
    });
});

// Moderator panel route
app.get('/moderator', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || currentUser.role !== 'moderator') {
        return res.status(403).send('Moderator access required');
    }
    
    res.render('moderator', { 
        user: currentUser,
        message: req.query.message 
    });
});

// Moderator news management
app.get('/api/moderator/news', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || currentUser.role !== 'moderator') {
        return res.status(403).json({ success: false, error: 'Moderator access required' });
    }
    
    // Load news from file
    try {
        const news = JSON.parse(fs.readFileSync(path.join(__dirname, 'news.json')));
        res.json({ success: true, news: news });
    } catch (error) {
        res.json({ success: true, news: [] });
    }
});

// Admin news creation
app.post('/admin/news/create', requireAdmin, (req, res) => {
    const { title, category, excerpt, content } = req.body;
    const currentUser = users[req.session.user.id];
    
    if (!title || !category || !excerpt || !content) {
        return res.redirect('/news?error=Все поля обязательны для заполнения');
    }
    
    try {
        // Load existing news
        let newsData = [];
        try {
            newsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'news.json')));
        } catch (error) {
            newsData = [];
        }
        
        // Create category name mapping
        const categoryNames = {
            'announcements': 'Объявления',
            'updates': 'Обновления', 
            'events': 'События',
            'security': 'Безопасность',
            'market': 'Маркет'
        };
        
        // Add new article
        const article = {
            id: Date.now().toString(),
            title: title,
            excerpt: excerpt,
            content: content,
            category: category,
            categoryName: categoryNames[category] || category,
            author: currentUser.name || 'Администрация',
            date: new Date().toISOString(),
            views: 0,
            image: null
        };
        
        newsData.unshift(article);
        
        // Save news
        fs.writeFileSync(path.join(__dirname, 'news.json'), JSON.stringify(newsData, null, 2));
        
        res.redirect('/news?success=Новость успешно создана');
    } catch (error) {
        console.error('Error creating news:', error);
        res.redirect('/news?error=Ошибка при создании новости');
    }
});

app.post('/moderator/news/add', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || currentUser.role !== 'moderator') {
        return res.status(403).send('Moderator access required');
    }
    
    const { title, category, summary, content } = req.body;
    
    try {
        // Load existing news
        let news = [];
        try {
            news = JSON.parse(fs.readFileSync(path.join(__dirname, 'news.json')));
        } catch (error) {
            news = [];
        }
        
        // Add new article
        const article = {
            id: Date.now().toString(),
            title: title,
            category: category,
            summary: summary,
            content: content,
            author: currentUser.name,
            authorId: currentUser.id,
            createdAt: new Date().toISOString(),
            views: 0
        };
        
        news.unshift(article);
        
        // Save news
        fs.writeFileSync(path.join(__dirname, 'news.json'), JSON.stringify(news, null, 2));
        
        res.redirect('/moderator?message=News article created successfully');
    } catch (error) {
        console.error('Error creating news:', error);
        res.redirect('/moderator?message=Error creating news article');
    }
});

app.post('/api/moderator/news/delete/:id', (req, res) => {
    const newsId = req.params.id;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || currentUser.role !== 'moderator') {
        return res.status(403).json({ success: false, error: 'Moderator access required' });
    }
    
    try {
        // Load existing news
        let news = [];
        try {
            news = JSON.parse(fs.readFileSync(path.join(__dirname, 'news.json')));
        } catch (error) {
            return res.status(404).json({ success: false, error: 'News not found' });
        }
        
        // Remove article
        const articleIndex = news.findIndex(article => article.id === newsId);
        if (articleIndex === -1) {
            return res.status(404).json({ success: false, error: 'News article not found' });
        }
        
        news.splice(articleIndex, 1);
        
        // Save news
        fs.writeFileSync(path.join(__dirname, 'news.json'), JSON.stringify(news, null, 2));
        
        res.json({ success: true, message: 'News article deleted successfully' });
    } catch (error) {
        console.error('Error deleting news:', error);
        res.status(500).json({ success: false, error: 'Error deleting news article' });
    }
});

// Admin collections management
app.get('/api/admin/collections', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Admin access required' });
    }
    
    // Load collections from file or return empty array
    try {
        const collections = JSON.parse(fs.readFileSync(path.join(__dirname, 'collections.json')));
        res.json({ success: true, collections: collections });
    } catch (error) {
        res.json({ success: true, collections: [] });
    }
});

app.post('/admin/collections/add', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Admin access required');
    }
    
    const { id, name, description, reward } = req.body;
    
    try {
        // Load existing collections
        let collections = [];
        try {
            collections = JSON.parse(fs.readFileSync(path.join(__dirname, 'collections.json')));
        } catch (error) {
            collections = [];
        }
        
        // Add new collection
        collections.push({
            id: id,
            name: name,
            description: description,
            reward: parseInt(reward),
            cards: [],
            createdAt: new Date().toISOString()
        });
        
        // Save collections
        fs.writeFileSync(path.join(__dirname, 'collections.json'), JSON.stringify(collections, null, 2));
        
        res.redirect('/admin?message=Collection created successfully');
    } catch (error) {
        console.error('Error creating collection:', error);
        res.redirect('/admin?message=Error creating collection');
    }
});

// Admin delete listing
app.post('/api/admin/delete-listing/:id', requireAuth, requireAdmin, (req, res) => {
    const listingId = req.params.id;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'moderator')) {
        return res.status(403).json({ success: false, error: 'Admin or moderator access required' });
    }
    
    // Find listing
    const listingIndex = marketplace.findIndex(l => l.id === listingId);
    if (listingIndex === -1) {
        return res.status(404).json({ success: false, error: 'Listing not found' });
    }
    
    const listing = marketplace[listingIndex];
    
    // Return card to owner's inventory if it's a card listing
    if (listing.cardData && listing.owner) {
        const owner = users[listing.owner];
        if (owner) {
            owner.inventory = owner.inventory || [];
            owner.inventory.push({
                id: listing.cardData.id,
                name: listing.cardData.name,
                rarity: listing.cardData.rarity,
                image: listing.cardData.image,
                obtainedAt: Date.now()
            });
        }
    }
    
    // Remove listing from marketplace
    marketplace.splice(listingIndex, 1);
    
    // Save changes
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Listing deleted successfully by admin'
    });
});

// Admin close listing
app.post('/api/admin/close-listing/:id', requireAuth, requireAdmin, (req, res) => {
    const listingId = req.params.id;
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    
    if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'moderator')) {
        return res.status(403).json({ success: false, error: 'Admin or moderator access required' });
    }
    
    // Find listing
    const listing = marketplace.find(l => l.id === listingId);
    if (!listing) {
        return res.status(404).json({ success: false, error: 'Listing not found' });
    }
    
    // Close listing
    listing.status = 'closed';
    listing.closedBy = currentUser.id;
    listing.closedAt = new Date().toISOString();
    
    // Save changes
    writeJSON(DB.marketplace, marketplace);
    
    res.json({ 
        success: true, 
        message: 'Listing closed successfully by admin'
    });
});

// Market messages
app.get('/api/market/messages/:listingId', (req, res) => {
    const listingId = req.params.listingId;
    
    // Load messages from file
    let messages = [];
    try {
        const messagesData = JSON.parse(fs.readFileSync(path.join(__dirname, 'messages.json')));
        messages = messagesData[listingId] || [];
    } catch (e) {
        messages = [];
    }
    
    res.json({
        success: true,
        messages: messages
    });
});

app.post('/market/message/:listingId', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    const listingId = req.params.listingId;
    const { message } = req.body;
    
    if (!message || message.trim().length === 0) {
        return res.status(400).json({ success: false, error: 'Message is required' });
    }
    
    // Load existing messages
    let messagesData = {};
    try {
        messagesData = JSON.parse(fs.readFileSync(path.join(__dirname, 'messages.json')));
    } catch (e) {
        messagesData = {};
    }
    
    // Add new message
    if (!messagesData[listingId]) {
        messagesData[listingId] = [];
    }
    
    messagesData[listingId].push({
        id: Date.now().toString(),
        author: currentUser.name,
        text: message.trim(),
        timestamp: Date.now()
    });
    
    // Save messages
    fs.writeFileSync(path.join(__dirname, 'messages.json'), JSON.stringify(messagesData, null, 2));
    
    res.redirect(`/market?message=Message sent`);
});

// Admin transaction management
app.post('/admin/transaction/:id/approve', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const transactionId = req.params.id;
    let transactions = [];
    try {
        transactions = JSON.parse(fs.readFileSync(path.join(__dirname, 'transactions.json')));
    } catch (e) {
        return res.status(404).send('Transactions not found');
    }
    
    const transaction = transactions.find(t => t.id === transactionId);
    if (!transaction) {
        return res.status(404).send('Transaction not found');
    }
    
    if (transaction.status !== 'pending_guarantor') {
        return res.status(400).send('Transaction not in pending state');
    }
    
    // Approve transaction
    transaction.status = 'approved';
    transaction.guarantorApproved = true;
    transaction.guarantorId = currentUser.id;
    transaction.approvedAt = Date.now();
    
    // Complete the transaction
    const buyer = users[transaction.buyerId];
    const seller = users[transaction.sellerId];
    const listing = marketplace.find(l => l.id === transaction.listingId);
    
    if (buyer && seller && listing) {
        // Transfer money from reserved to seller
        buyer.reservedBalance = (buyer.reservedBalance || 0) - transaction.amount;
        seller.balance = (seller.balance || 0) + transaction.amount;
        
        // Transfer item to buyer
        buyer.inventory = buyer.inventory || [];
        buyer.inventory.push({ 
            id: listing.id, 
            title: listing.title, 
            image: listing.images && listing.images[0] || null 
        });
        
        // Update history
        seller.history = seller.history || { bought: [], sold: [] };
        buyer.history = buyer.history || { bought: [], sold: [] };
        seller.history.sold.push({ 
            id: listing.id, 
            title: listing.title, 
            price: transaction.amount, 
            when: Date.now(), 
            to: buyer.id 
        });
        buyer.history.bought.push({ 
            id: listing.id, 
            title: listing.title, 
            price: transaction.amount, 
            when: Date.now(), 
            from: seller.id 
        });
        
        // Mark listing as sold
        listing.status = 'sold';
        listing.soldTo = buyer.id;
        listing.soldAt = Date.now();
    }
    
    // Save changes
    fs.writeFileSync(path.join(__dirname, 'transactions.json'), JSON.stringify(transactions, null, 2));
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.redirect('/admin?tab=transactions&message=Transaction approved successfully');
});

app.post('/admin/transaction/:id/reject', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const transactionId = req.params.id;
    let transactions = [];
    try {
        transactions = JSON.parse(fs.readFileSync(path.join(__dirname, 'transactions.json')));
    } catch (e) {
        return res.status(404).send('Transactions not found');
    }
    
    const transaction = transactions.find(t => t.id === transactionId);
    if (!transaction) {
        return res.status(404).send('Transaction not found');
    }
    
    if (transaction.status !== 'pending_guarantor') {
        return res.status(400).send('Transaction not in pending state');
    }
    
    // Reject transaction
    transaction.status = 'rejected';
    transaction.guarantorApproved = false;
    transaction.guarantorId = currentUser.id;
    transaction.rejectedAt = Date.now();
    
    // Return money to buyer
    const buyer = users[transaction.buyerId];
    if (buyer) {
        buyer.balance = (buyer.balance || 0) + transaction.amount;
        buyer.reservedBalance = (buyer.reservedBalance || 0) - transaction.amount;
    }
    
    // Reopen listing
    const listing = marketplace.find(l => l.id === transaction.listingId);
    if (listing) {
        listing.status = 'open';
        delete listing.transactionId;
        delete listing.buyer;
    }
    
    // Save changes
    fs.writeFileSync(path.join(__dirname, 'transactions.json'), JSON.stringify(transactions, null, 2));
    writeJSON(DB.users, users);
    writeJSON(DB.marketplace, marketplace);
    
    res.redirect('/admin?tab=transactions&message=Transaction rejected');
});

// Admin coin management
app.post('/admin/give-coins', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }
    
    const { amount, userId } = req.body;
    const coins = parseInt(amount) || 0;
    const targetUserId = userId || currentUser.id;
    
    if (coins <= 0) {
        return res.status(400).send('Invalid amount');
    }
    
    if (!users[targetUserId]) {
        return res.status(400).send('User not found');
    }
    
    try {
        console.log('Giving coins:', coins, 'to user:', targetUserId);
        console.log('Current balance:', users[targetUserId].balance);
        
        users[targetUserId].balance = (users[targetUserId].balance || 0) + coins;
        console.log('New balance:', users[targetUserId].balance);
        
        writeJSON(DB.users, users);
        console.log('Successfully saved users data');
        
        res.json({ success: true, newBalance: users[targetUserId].balance });
    } catch (error) {
        console.error('Error giving coins:', error);
        res.status(500).json({ success: false, error: 'Failed to give coins: ' + error.message });
    }
});

// Route: admin can pin/unpin listings (pin = show on top and marked)
app.post('/admin/pin/:id', (req, res) => {
    const uid = req.session.user ? req.session.user.id : null;
    if (!uid) return res.status(401).send('Unauthorized');
    const me = users[uid];
    if (!me || me.role !== 'admin') return res.status(403).send('Forbidden');
    const id = req.params.id;
    const listing = marketplace.find(l => l.id === id);
    if (!listing) return res.status(404).send('Listing not found');
    listing.pinned = !listing.pinned;
    // reorder: pinned first
    marketplace.sort((a,b) => (b.pinned?1:0) - (a.pinned?1:0));
    writeJSON(DB.marketplace, marketplace);
    res.redirect('/market');
});

// Trades / swaps: propose, accept, decline
app.post('/trade/propose', (req, res) => {
    const from = req.session.user ? req.session.user.id : null;
    if (!from) return res.status(401).send('Unauthorized');
    const { to, offeredIds, wantedIds } = req.body; // arrays of listing ids or inventory ids
    const trade = { id: uuidv4(), from, to, offered: offeredIds||[], wanted: wantedIds||[], status: 'pending', createdAt: Date.now() };
    // store trades in a simple trades array inside marketplace file (or separate)
    marketplace._trades = marketplace._trades || [];
    marketplace._trades.push(trade);
    writeJSON(DB.marketplace, marketplace);
    res.redirect('/profile/' + to);
});

app.post('/trade/respond/:id', (req, res) => {
    const uid = req.session.user ? req.session.user.id : null;
    if (!uid) return res.status(401).send('Unauthorized');
    const tradeId = req.params.id;
    const action = req.body.action; // accept / decline
    marketplace._trades = marketplace._trades || [];
    const trade = marketplace._trades.find(t=>t.id===tradeId);
    if (!trade) return res.status(404).send('Trade not found');
    if (trade.to !== uid && trade.from !== uid) return res.status(403).send('Forbidden');
    if (action === 'accept' && trade.to === uid) {
        // do a simple swap: transfer offered items to 'to' and wanted items to 'from'
        const fromUser = users[trade.from];
        const toUser = users[trade.to];
        // naive transfer based on ids present in inventory arrays (no deep check)
        fromUser.inventory = fromUser.inventory || [];
        toUser.inventory = toUser.inventory || [];
        // move offered -> toUser
        trade.offered.forEach(oid => {
            const idx = fromUser.inventory.findIndex(i=>i.id===oid);
            if (idx>=0) {
                const itm = fromUser.inventory.splice(idx,1)[0];
                toUser.inventory.push(itm);
            }
        });
        // move wanted -> fromUser
        trade.wanted.forEach(oid => {
            const idx = toUser.inventory.findIndex(i=>i.id===oid);
            if (idx>=0) {
                const itm = toUser.inventory.splice(idx,1)[0];
                fromUser.inventory.push(itm);
            }
        });
        trade.status = 'accepted';
        writeJSON(DB.users, users);
        writeJSON(DB.marketplace, marketplace);
        res.redirect('/profile/' + trade.from);
    } else {
        trade.status = 'declined';
        writeJSON(DB.marketplace, marketplace);
        res.redirect('/profile/' + uid);
    }
});

// Reviews with text
app.post('/profile/:id/review', (req, res) => {
    const id = req.params.id;
    const person = users[id];
    const from = req.session.user ? req.session.user.id : null;
    if (!from) return res.status(401).send('Unauthorized');
    if (!person) return res.status(404).send('User not found');
    const { score, text } = req.body;
    person.reviews = person.reviews || [];
    person.reviews.push({ from, score: Number(score)||5, text: text||'', when: Date.now() });
    // also push to ratings for compatibility
    person.ratings = person.ratings || [];
    person.ratings.push(Number(score)||5);
    
    // Add XP for leaving review
    addXP(from, 5, 'оставление отзыва');
    
    writeJSON(DB.users, users);
    res.redirect('/profile/' + id);
});


// Shop route
app.get('/shop', (req, res) => {
    const currentUser = users[req.session.user?.id] || null;
    const balance = currentUser ? (currentUser.balance || 0) : 0;
    let items = [];
    try { items = JSON.parse(fs.readFileSync(path.join(__dirname,'shopitems.json'))); } catch (e) { items = []; }
    res.render('shop', { user: currentUser, items, balance });
});

// Achievements route
app.get('/achievements', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    if (!currentUser) {
        return res.redirect('/');
    }
    
    const levelData = calculateLevel(currentUser.xp || 0);
    res.render('achievements', { 
        user: currentUser, 
        levelData,
        balance: currentUser.balance 
    });
});

// FAQ route
app.get('/faq', requireAuth, (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    res.render('faq', { 
        user: currentUser,
        balance: currentUser ? currentUser.balance : 0
    });
});

// Rules route
app.get('/rules', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    res.render('rules', { 
        user: currentUser,
        balance: currentUser ? currentUser.balance : 0
    });
});

// Support route
app.get('/support', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    res.render('support', { 
        user: currentUser,
        balance: currentUser ? currentUser.balance : 0
    });
});

// API Documentation route
app.get('/api', (req, res) => {
    const currentUser = req.session.user ? users[req.session.user.id] : null;
    res.render('api', { 
        user: currentUser,
        balance: currentUser ? currentUser.balance : 0
    });
});

// Support ticket system
function loadSupportTickets() {
    try {
        const data = fs.readFileSync('./support-tickets.json', 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error loading support tickets:', error);
        return [];
    }
}

function loadChats() {
    try {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'chats.json')));
    } catch (error) {
        console.error('Error loading chats:', error);
        return [];
    }
}

function saveChats(chats) {
    try {
        fs.writeFileSync(path.join(__dirname, 'chats.json'), JSON.stringify(chats, null, 2));
        console.log('Successfully wrote to: chats.json');
        return true;
    } catch (error) {
        console.error('Error saving chats:', error);
        return false;
    }
}

function loadMessages() {
    try {
        return JSON.parse(fs.readFileSync(path.join(__dirname, 'chat-messages.json')));
    } catch (error) {
        console.error('Error loading messages:', error);
        return [];
    }
}

function saveMessages(messages) {
    try {
        fs.writeFileSync(path.join(__dirname, 'chat-messages.json'), JSON.stringify(messages, null, 2));
        console.log('Successfully wrote to: chat-messages.json');
        return true;
    } catch (error) {
        console.error('Error saving messages:', error);
        return false;
    }
}

function saveSupportTickets(tickets) {
    try {
        fs.writeFileSync('./support-tickets.json', JSON.stringify(tickets, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving support tickets:', error);
        return false;
    }
}

// Create support ticket
app.post('/api/support/create', requireAuth, (req, res) => {
    try {
        const { subject, message } = req.body;
        const currentUser = req.session.user;
        
        if (!subject || !message) {
            return res.json({ success: false, error: 'Тема и сообщение обязательны' });
        }
        
        const tickets = loadSupportTickets();
        const newTicket = {
            id: Date.now().toString(),
            userId: currentUser.id,
            userName: currentUser.name,
            subject,
            message,
            status: 'open',
            createdAt: new Date().toISOString(),
            response: null,
            responseAt: null
        };
        
        tickets.push(newTicket);
        
        if (saveSupportTickets(tickets)) {
            logger.info(`New support ticket created: ${newTicket.id} by ${currentUser.name}`);
            res.json({ success: true, ticketId: newTicket.id });
        } else {
            res.json({ success: false, error: 'Ошибка сохранения обращения' });
        }
    } catch (error) {
        logger.error('Error creating support ticket:', error);
        res.json({ success: false, error: 'Внутренняя ошибка сервера' });
    }
});

// Get user's support tickets
app.get('/api/support/tickets', requireAuth, (req, res) => {
    try {
        const currentUser = req.session.user;
        const tickets = loadSupportTickets();
        const userTickets = tickets.filter(ticket => ticket.userId === currentUser.id);
        
        res.json({ success: true, tickets: userTickets });
    } catch (error) {
        logger.error('Error loading support tickets:', error);
        res.json({ success: false, error: 'Ошибка загрузки обращений' });
    }
});

// Admin: Get all support tickets
app.get('/api/admin/support/tickets', requireAuth, requireAdmin, (req, res) => {
    try {
        const tickets = loadSupportTickets();
        res.json({ success: true, tickets });
    } catch (error) {
        logger.error('Error loading all support tickets:', error);
        res.json({ success: false, error: 'Ошибка загрузки обращений' });
    }
});

// Admin: Respond to support ticket
app.post('/api/admin/support/respond', requireAuth, requireAdmin, (req, res) => {
    try {
        const { ticketId, response, status } = req.body;
        
        if (!ticketId || !response) {
            return res.json({ success: false, error: 'ID тикета и ответ обязательны' });
        }
        
        const tickets = loadSupportTickets();
        const ticketIndex = tickets.findIndex(ticket => ticket.id === ticketId);
        
        if (ticketIndex === -1) {
            return res.json({ success: false, error: 'Обращение не найдено' });
        }
        
        tickets[ticketIndex].response = response;
        tickets[ticketIndex].responseAt = new Date().toISOString();
        tickets[ticketIndex].status = status || 'in_progress';
        
        if (saveSupportTickets(tickets)) {
            logger.info(`Support ticket ${ticketId} responded by admin`);
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Ошибка сохранения ответа' });
        }
    } catch (error) {
        logger.error('Error responding to support ticket:', error);
        res.json({ success: false, error: 'Внутренняя ошибка сервера' });
    }
});
// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    
    if (isProduction) {
        res.status(500).json({ 
            success: false, 
            error: 'Внутренняя ошибка сервера' 
        });
    } else {
        res.status(500).json({ 
            success: false, 
            error: err.message,
            stack: err.stack 
        });
    }
});

// 404 handler - должен быть последним
app.use((req, res) => {
    // Handle API routes with JSON response
    if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
        return res.status(404).json({ error: 'Route not found' });
    }
    
    // For all other routes, render 404 page
    res.status(404).render('404', { 
        user: req.session?.user ? users[req.session.user.id] : null,
        title: 'Страница не найдена'
    });
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1');

// create http server + socket.io for realtime features
const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);

// Simple in-memory chat rooms (for demo)
io.on('connection', (socket) => {
  console.log('Socket connected', socket.id);
  socket.on('joinRoom', (room) => { socket.join(room); });
  socket.on('leaveRoom', (room) => { socket.leave(room); });
  socket.on('message', (data) => {
    // data: { room, from, text }
    io.to(data.room).emit('message', { from: data.from, text: data.text, when: Date.now() });
  });
});

// 404 handler removed - using the one above

// Start server with graceful shutdown
server.listen(PORT, HOST, () => {
    const message = `Server started on http://${HOST}:${PORT}`;
    console.log(message);
    logger.info(message);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    
    server.close(() => {
        logger.info('HTTP server closed.');
        
        // Close database connections if any
        // Close other resources
        
        logger.info('Graceful shutdown completed.');
        process.exit(0);
    });
    
    // Force close after 30 seconds
    setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 30000);
};

// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception:', err);
    gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    gracefulShutdown('unhandledRejection');
});
