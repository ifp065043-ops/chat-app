const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');
const fs         = require('fs');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const mongoose   = require('mongoose');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const createDOMPurify = require('dompurify');
const { JSDOM }  = require('jsdom');
require('dotenv').config();
const { createClient } = require('redis');

// على بعض إعدادات Windows يفشل Node في استعلام SRV لـ mongodb+srv (querySrv ECONNREFUSED)
// بينما يعمل الحل عبر خوادم DNS عامة. عطّل بـ MONGO_SKIP_DNS_FIX=1 إن كانت شبكتك تمنع ذلك.
const dns = require('dns');
const _mongoUriEnv = process.env.MONGO_URI || '';
if (
    process.platform === 'win32' &&
    /^mongodb\+srv:\/\//i.test(_mongoUriEnv) &&
    !/^(1|true|yes)$/i.test(String(process.env.MONGO_SKIP_DNS_FIX || '').trim())
) {
    dns.setServers(['8.8.8.8', '1.1.1.1']);
}

// ================= DOMPurify للسيرفر =================
const window    = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// ================= متغيرات البيئة =================
const MONGO_URI  = _mongoUriEnv || 'mongodb://localhost:27017/chatapp';

function mongoUriForLog(uri) {
    if (!uri || typeof uri !== 'string') return '[hidden]';
    return uri.replace(/\/\/([^:]+):([^@]*)@/, '//$1:***@');
}
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_IN_ENV_FILE';
const JWT_EXPIRE = '7d';

/** مدة الحظر الافتراضية عند استدعاء /api/admin/ban-month (30 يوماً) */
const BAN_MONTH_MS = 30 * 24 * 60 * 60 * 1000;

/** إن كان 1/true: لا يُسمح بتسجيل الدخول قبل تأكيد البريد (يُنصح في الإنتاج) */
function requireEmailVerifiedForLogin() {
    return /^(1|true|yes)$/i.test(String(process.env.REQUIRE_EMAIL_VERIFIED || '').trim());
}

const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
const usingDefaultJwtSecret = JWT_SECRET === 'CHANGE_THIS_SECRET_IN_ENV_FILE' || JWT_SECRET === 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_STRING';

// ================= Anti brute-force (in-memory) =================
// ملاحظة: هذا يحمي عملية login على سيرفر واحد. عند التوزيع/التوسعة يفضّل Redis.
const loginAttempts = new Map(); // key -> { n, firstAt, blockedUntil }
const ipAbuse = new Map(); // ip -> { score, firstAt, blockedUntil }

function getClientIp(req) {
    // Express يحسب req.ip مع trust proxy. نستخدمه إن توفر.
    const ip = (req.ip || '').toString();
    return ip || String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'ip:unknown';
}

function isIpBlockedLocal(ip) {
    const key = String(ip || '').trim() || 'ip:unknown';
    const row = ipAbuse.get(key);
    if (!row) return false;
    return row.blockedUntil && row.blockedUntil > Date.now();
}

async function isIpBlockedRedis(ip) {
    if (!redisClient) return false;
    const key = String(ip || '').trim() || 'ip:unknown';
    try {
        const v = await redisClient.get(`ip:block:${key}`);
        return !!v;
    } catch {
        return false;
    }
}

async function addIpAbuseRedis(ip, points) {
    if (!redisClient) return;
    const key = String(ip || '').trim() || 'ip:unknown';
    const now = Date.now();
    const windowMs = 10 * 60 * 1000;
    const blockMs = 10 * 60 * 1000;
    const scoreToBlock = 120;
    const scoreKey = `ip:abuse:${key}`;
    const blockKey = `ip:block:${key}`;
    try {
        // score يتصفّر تلقائياً عبر EX (window)
        const n = await redisClient.incrBy(scoreKey, Math.max(1, Number(points) || 1));
        await redisClient.expire(scoreKey, Math.ceil(windowMs / 1000));
        if (n >= scoreToBlock) {
            await redisClient.set(blockKey, String(now + blockMs), { EX: Math.ceil(blockMs / 1000) });
        }
    } catch (e) {
        console.error('Redis abuse update:', e?.message || e);
    }
}

function addIpAbuseLocal(ip, points) {
    const key = String(ip || '').trim() || 'ip:unknown';
    const now = Date.now();
    const windowMs = 10 * 60 * 1000;
    const blockMs = 10 * 60 * 1000;
    const scoreToBlock = 120;
    const row = ipAbuse.get(key) || { score: 0, firstAt: now, blockedUntil: 0 };
    if (now - row.firstAt > windowMs) {
        row.score = 0;
        row.firstAt = now;
        row.blockedUntil = 0;
    }
    row.score += Math.max(1, Number(points) || 1);
    if (row.score >= scoreToBlock) {
        row.blockedUntil = now + blockMs;
    }
    ipAbuse.set(key, row);
    return row;
}

function clearIpAbuse(ip) {
    const key = String(ip || '').trim() || 'ip:unknown';
    ipAbuse.delete(key);
}

function attemptKey(req, username) {
    return `${getClientIp(req)}|${String(username || '').toLowerCase()}`;
}
function isBlockedLogin(req, username) {
    const k = attemptKey(req, username);
    const row = loginAttempts.get(k);
    if (!row) return false;
    return row.blockedUntil && row.blockedUntil > Date.now();
}
function noteLoginFail(req, username) {
    const k = attemptKey(req, username);
    const ip = getClientIp(req);
    // نقاط على مستوى IP حتى لو غيّر أسماء المستخدمين
    addIpAbuseLocal(ip, 8);
    // Fire-and-forget (لا ننتظر Redis حتى لا يؤثر على زمن الاستجابة)
    void addIpAbuseRedis(ip, 8);
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const maxFails = 8;
    const blockMs = 15 * 60 * 1000;
    const row = loginAttempts.get(k) || { n: 0, firstAt: now, blockedUntil: 0 };
    if (now - row.firstAt > windowMs) {
        row.n = 0;
        row.firstAt = now;
        row.blockedUntil = 0;
    }
    row.n++;
    if (row.n >= maxFails) row.blockedUntil = now + blockMs;
    loginAttempts.set(k, row);
}
function noteLoginSuccess(req, username) {
    const k = attemptKey(req, username);
    loginAttempts.delete(k);
    // لا نمسح سجل IP مباشرة؛ نجاح واحد لا يعني أن السلوك العام سليم
}

if (usingDefaultJwtSecret) {
    const msg = '⚠️  تحذير: يجب تعيين JWT_SECRET في ملف .env قبل النشر للإنتاج!';
    if (isProd) {
        console.error(msg);
        process.exit(1);
    } else {
        console.warn(msg);
    }
}

// ================= الاتصال بـ MongoDB =================
async function connectMongoWithFallback() {
    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ MongoDB متصل:', mongoUriForLog(MONGO_URI));
        return;
    } catch (err) {
        console.error('❌ خطأ MongoDB:', err);
    }

    // Fallback محلي (مفيد عند مشاكل Atlas whitelist / DNS / شبكة)
    const localUri = 'mongodb://127.0.0.1:27017/chatapp';
    try {
        await mongoose.connect(localUri);
        console.log('✅ MongoDB متصل (fallback):', mongoUriForLog(localUri));
    } catch (err2) {
        console.error('❌ فشل MongoDB fallback:', err2);
    }
}
connectMongoWithFallback();

// ================= Redis (اختياري) =================
// إذا عيّنت REDIS_URL سيتم استخدامه لحظر IP بشكل موزّع (يفيد مع تعدد النسخ/إعادة التشغيل)
const REDIS_URL = String(process.env.REDIS_URL || '').trim();
let redisClient = null;

async function initRedis() {
    if (!REDIS_URL) return;
    try {
        redisClient = createClient({ url: REDIS_URL });
        redisClient.on('error', (err) => {
            console.error('Redis error:', err?.message || err);
        });
        await redisClient.connect();
        console.log('✅ Redis متصل');
    } catch (e) {
        console.error('❌ فشل اتصال Redis:', e?.message || e);
        redisClient = null;
    }
}
initRedis();

// ================= نموذج المستخدم =================
const userSchema = new mongoose.Schema({
    username:  { type: String, required: true, unique: true, trim: true, maxlength: 20 },
    password:  { type: String, required: true },
    email:     { type: String, default: '', trim: true, lowercase: true, maxlength: 254 },
    emailVerified: { type: Boolean, default: false },
    emailVerifyTokenHash: { type: String, default: '' },
    emailVerifyExpiresAt: { type: Date, default: null },
    gender:    { type: String, enum: ['male', 'female', 'other'], default: 'male' },
    avatar:    { type: String, default: null },
    bio:       { type: String, maxlength: 150, default: '' },
    country:   { type: String, default: '' },
    age:       { type: Number, min: 1, max: 120, default: null },
    createdAt: { type: Date, default: Date.now },
    lastSeen:  { type: Date, default: Date.now },
    /** حظر مؤقت: ينتهي تلقائياً عندما يصبح banExpiresAt <= الآن */
    banExpiresAt: { type: Date, default: null },
    /** حظر دائم (لا ينتهي تلقائياً) */
    permanentlyBanned: { type: Boolean, default: false },
    banReason:    { type: String, maxlength: 500, default: '' },
    /** يُزاد عند «تسجيل الخروج من كل الأجهزة» لإبطال JWT القديمة */
    tokenVersion: { type: Number, default: 0, min: 0 }
});

const User = mongoose.model('User', userSchema);

// ================= Audit Log =================
const auditSchema = new mongoose.Schema({
    action: { type: String, required: true, maxlength: 60 },
    actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    actorUsername: { type: String, default: '', maxlength: 40 },
    targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    targetUsername: { type: String, default: '', maxlength: 40 },
    ip: { type: String, default: '', maxlength: 120 },
    userAgent: { type: String, default: '', maxlength: 260 },
    meta: { type: Object, default: {} },
    createdAt: { type: Date, default: Date.now }
});

const AuditLog = mongoose.model('AuditLog', auditSchema);

async function writeAudit(req, { action, actorUserId, actorUsername, targetUserId, targetUsername, meta }) {
    try {
        await AuditLog.create({
            action,
            actorUserId: actorUserId || null,
            actorUsername: String(actorUsername || ''),
            targetUserId: targetUserId || null,
            targetUsername: String(targetUsername || ''),
            ip: getClientIp(req),
            userAgent: String(req.headers['user-agent'] || '').slice(0, 260),
            meta: meta || {}
        });
    } catch (e) {
        console.error('AuditLog error:', e?.message || e);
    }
}

function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const e = email.trim().toLowerCase();
    if (e.length < 5 || e.length > 254) return false;
    // validation بسيطة مناسبة للتطبيق (ليس RFC كامل)
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
}

async function getMailTransport() {
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '', 10);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    const from = process.env.MAIL_FROM || user || 'no-reply@example.com';
    if (host && user && pass && Number.isFinite(port)) {
        const transporter = nodemailer.createTransport({
            host,
            port,
            secure: port === 465,
            auth: { user, pass }
        });
        return { transporter, from };
    }
    // وضع التطوير: Ethereal (يعطي Preview URL)
    const testAcc = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
        host: testAcc.smtp.host,
        port: testAcc.smtp.port,
        secure: testAcc.smtp.secure,
        auth: { user: testAcc.user, pass: testAcc.pass }
    });
    return { transporter, from: `chat-app <${testAcc.user}>` };
}

function sha256Hex(s) {
    return crypto.createHash('sha256').update(String(s || '')).digest('hex');
}

// ================= Express =================
const app    = express();
const server = http.createServer(app);

// تقليل المعلومات المُسرّبة عن التقنية
app.disable('x-powered-by');

// عند التشغيل خلف Proxy (Render/Railway/Nginx) هذا ضروري لتعامل صحيح مع HTTPS/IP
if (String(process.env.NODE_ENV || '').toLowerCase() === 'production') {
    app.set('trust proxy', 1);
}

app.use(express.json({ limit: '1mb' }));

// ================= CSRF (Double-Submit) + Origin checks =================
function newCsrfToken() {
    return crypto.randomBytes(24).toString('hex');
}

function getExpectedOrigin(req) {
    const host = req.headers.host;
    if (!host) return '';
    const protoHeader = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    const proto = (req.protocol && String(req.protocol).toLowerCase()) || protoHeader || 'http';
    return `${proto}://${host}`;
}

function parseAllowedOrigins() {
    const raw = String(process.env.ALLOWED_ORIGINS || '').trim();
    if (!raw) return [];
    return raw
        .split(/[,;]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => s.replace(/\/+$/, '')); // remove trailing slashes
}

const ALLOWED_ORIGINS = parseAllowedOrigins();

function originInAllowList(origin) {
    if (!origin) return false;
    const o = String(origin).trim().replace(/\/+$/, '');
    if (!o) return false;
    return ALLOWED_ORIGINS.includes(o);
}

function sameOriginOk(req) {
    const origin = String(req.headers.origin || '').trim();
    const referer = String(req.headers.referer || '').trim();
    const expected = getExpectedOrigin(req);
    // إذا تم تحديد ALLOWED_ORIGINS، نستخدمه بدل "نفس الأصل" لأنه أدق في النشر
    if (ALLOWED_ORIGINS.length) {
        if (origin) return originInAllowList(origin);
        if (referer) return ALLOWED_ORIGINS.some((o) => referer.startsWith(o + '/'));
        return true;
    }
    if (!expected) return true;
    if (origin) return origin === expected;
    if (referer) return referer.startsWith(expected + '/');
    return true;
}

function ensureCsrfCookie(req, res) {
    const cookies = parseCookies(req.headers.cookie || '');
    const current = cookies.csrfToken;
    if (current && typeof current === 'string' && current.length >= 20) return current;
    const token = newCsrfToken();
    const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
    res.cookie('csrfToken', token, {
        httpOnly: false,
        secure: isProd,
        // CSRF cookie لا يحتاج أن يُرسل في سياقات cross-site
        sameSite: 'strict',
        path: '/'
    });
    return token;
}

function requireCsrf(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS')
        return next();

    if (!sameOriginOk(req)) {
        return res.status(403).json({ error: 'CSRF blocked (bad origin)' });
    }

    const cookies = parseCookies(req.headers.cookie || '');
    const cookieToken = String(cookies.csrfToken || '');
    const headerToken = String(req.headers['x-csrf-token'] || '');
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        return res.status(403).json({ error: 'CSRF token missing/invalid' });
    }
    next();
}

// نضمن وجود csrfToken للواجهة دائماً
app.use((req, res, next) => {
    ensureCsrfCookie(req, res);
    next();
});

// متغير يحقن في الواجهة (بدون أسرار)
app.get('/config.js', (req, res) => {
    res.type('application/javascript');
    const cid = String(process.env.GOOGLE_CLIENT_ID || '');
    res.send(`window.__GOOGLE_CLIENT_ID__ = ${JSON.stringify(cid)};`);
});

// ================= Helmet =================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // لا نستخدم inline scripts في الواجهة، فإزالة 'unsafe-inline' تقلل مخاطر XSS
            scriptSrc:  ["'self'", "https://cdn.jsdelivr.net"],
            // تم نقل inline styles إلى ملفات CSS لتشديد CSP
            styleSrc:   ["'self'"],
            // نسمح بتغيير style attributes ديناميكياً عبر JS (مثل فتح/إغلاق المودالات وتموضع القوائم)
            // بدون السماح بوسوم <style> أو تحميل CSS من خارج المشروع.
            styleSrcAttr: ["'unsafe-inline'"],
            imgSrc:     ["'self'", "data:", "blob:", "https:", "https://flagcdn.com"],
            mediaSrc:   ["'self'", "data:", "blob:", "https://assets.mixkit.co"],
            connectSrc: ["'self'", "ws:", "wss:", "https://cdn.jsdelivr.net"],
            workerSrc: ["'self'", 'blob:'],
        },
    },
}));

// ================= Rate Limiting =================
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 50,
    message: { error: 'Too many requests, please try again later.' }
});
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    message: { error: 'Too many login attempts, please try again later.' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);
app.use('/socket.io', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ================= CORS (نفس الأصل فقط حالياً) =================
app.use((req, res, next) => {
    const origin = String(req.headers.origin || '').trim();
    if (!origin) return next();
    if (!sameOriginOk(req)) return res.status(403).send('Blocked by CORS');
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// ================= الملفات الثابتة =================
const publicDir = path.join(__dirname, 'public');
const staticDir = fs.existsSync(publicDir) ? publicDir : __dirname;

// لا تسمح بنشر admin.html في الإنتاج (النسخة الحالية تعتمد على localStorage وكلمة مرور ثابتة)
app.get('/admin.html', (req, res, next) => {
    const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
    if (isProd) return res.status(404).send('Not Found');
    next();
});

app.use(express.static(staticDir));

// ================= دوال مساعدة =================
function sanitizeText(text) {
    if (!text) return '';
    let cleaned = DOMPurify.sanitize(text, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    cleaned = cleaned.replace(/[<>{}`$]/g, '');
    if (cleaned.length > 500) cleaned = cleaned.substring(0, 500);
    return cleaned;
}

function sanitizeUsername(username) {
    if (!username) return '';
    let cleaned = username.replace(/[^a-zA-Z0-9\u0600-\u06FF_]/g, '');
    cleaned = cleaned.trim();
    if (cleaned.length > 20) cleaned = cleaned.substring(0, 20);
    return cleaned;
}

function isValidImageType(base64String) {
    if (!base64String) return false;
    const matches = base64String.match(/^data:([^;]+);/);
    if (!matches) return false;
    return ['image/jpeg','image/png','image/gif','image/webp'].includes(matches[1]);
}

/** روابط GIF من نطاقات CDN معروفة فقط (أضف نطاقك بعد رفع الملفات لخادمك) */
function isValidGifStickerUrl(url) {
    if (!url || typeof url !== 'string' || url.length > 2500) return false;
    try {
        const u = new URL(url);
        if (u.protocol !== 'https:') return false;
        const h = u.hostname.toLowerCase();
        if (h === 'i.giphy.com' || h === 'media.giphy.com') return true;
        if (/^media[0-9]+\.giphy\.com$/.test(h)) return true;
        if (h === 'media.tenor.com' || h === 'c.tenor.com') return true;
        return false;
    } catch {
        return false;
    }
}

function isValidAudioType(base64String) {
    if (!base64String) return false;
    const matches = base64String.match(/^data:([^;]+);/);
    if (!matches) return false;
    return ['audio/webm','audio/ogg','audio/mpeg','audio/mp4','audio/wav'].includes(matches[1]);
}

function sanitizeAvatarDataUrl(dataUrl) {
    if (!dataUrl) return null;
    const s = String(dataUrl);
    if (!s.startsWith('data:image/')) return null;
    if (s.length > 350_000) return null;
    if (!isValidImageType(s)) return null;
    return s;
}

/** غلاف أوسع — JPEG/PNG/WebP فقط لتقليل الحجم */
function isValidCoverType(base64String) {
    if (!base64String) return false;
    const matches = base64String.match(/^data:([^;]+);/);
    if (!matches) return false;
    return ['image/jpeg', 'image/png', 'image/webp'].includes(matches[1]);
}

function sanitizeCoverDataUrl(dataUrl) {
    if (!dataUrl) return null;
    const s = String(dataUrl);
    if (!s.startsWith('data:image/')) return null;
    if (s.length > 700_000) return null;
    if (!isValidCoverType(s)) return null;
    return s;
}

const badWordsList = [
    'fuck','shit','bitch','asshole','damn','crap',
    'sex','porn','nude','naked','fucking','wtf',
    'stfu','omfg','goddamn','bastard','dick','cock'
];

function filterBadWords(text) {
    if (!text) return text;
    let filtered = text;
    badWordsList.forEach(word => {
        const regex = new RegExp(word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        filtered = filtered.replace(regex, '***');
    });
    return filtered;
}

function normalizePrivateImages(value) {
    const v = (value || 'everyone').toLowerCase();
    if (v === 'friends' || v === 'nobody') return v;
    return 'everyone';
}

function findSocketByUsername(username) {
    const target = sanitizeUsername(username).toLowerCase();
    for (const s of io.sockets.sockets.values()) {
        if (s.data?.username?.toLowerCase() === target) return s;
    }
    return null;
}

function parseCookies(cookieHeader) {
    const out = {};
    if (!cookieHeader) return out;
    cookieHeader.split(';').forEach((part) => {
        const idx = part.indexOf('=');
        if (idx <= 0) return;
        const key = part.slice(0, idx).trim();
        const val = part.slice(idx + 1).trim();
        if (!key) return;
        out[key] = decodeURIComponent(val);
    });
    return out;
}

function getTokenFromRequest(req) {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
    const cookies = parseCookies(req.headers.cookie || '');
    return cookies.authToken || null;
}

function signUserJwt(userDoc) {
    const id = userDoc._id || userDoc.id;
    const tv = userDoc.tokenVersion != null ? userDoc.tokenVersion : 0;
    return jwt.sign(
        { id, username: userDoc.username, tv },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRE }
    );
}

function setAuthCookie(res, token) {
    const maxAgeMs = 7 * 24 * 60 * 60 * 1000;
    res.cookie('authToken', token, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        path: '/',
        maxAge: maxAgeMs
    });
}

async function verifyToken(req, res, next) {
    const token = getTokenFromRequest(req);
    if (!token)
        return res.status(401).json({ error: 'غير مصرح' });
    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
    } catch {
        return res.status(401).json({ error: 'جلسة منتهية، يرجى تسجيل الدخول مجدداً' });
    }
    try {
        const u = await User.findById(decoded.id).select('banExpiresAt banReason tokenVersion permanentlyBanned');
        if (!u)
            return res.status(401).json({ error: 'غير مصرح' });
        const tvDb = u.tokenVersion != null ? u.tokenVersion : 0;
        const tvJwt = decoded.tv != null ? decoded.tv : 0;
        if (tvJwt !== tvDb) {
            return res.status(401).json({
                error: 'انتهت الجلسة، يرجى تسجيل الدخول مجدداً',
                code: 'session_revoked'
            });
        }
        const now = new Date();
        if (u.permanentlyBanned) {
            return res.status(403).json({
                error: 'حسابك محظور دائماً.',
                code: 'account_banned_permanent',
                banReason: u.banReason || ''
            });
        }
        if (u.banExpiresAt && u.banExpiresAt <= now) {
            u.banExpiresAt = null;
            u.banReason = '';
            await u.save();
        } else if (u.banExpiresAt && u.banExpiresAt > now) {
            return res.status(403).json({
                error: 'حسابك محظور مؤقتاً حتى انتهاء مدة الحظر.',
                code: 'account_banned',
                bannedUntil: u.banExpiresAt.toISOString(),
                banReason: u.banReason || ''
            });
        }
    } catch (e) {
        console.error('verifyToken ban check:', e);
        return res.status(500).json({ error: 'خطأ في السيرفر' });
    }
    next();
}

/** قائمة احتياط عندما لا يوجد GIPHY_API_KEY أو فشل الطلب — معرّفات ثابتة + رابط i.giphy.com */
const DEFAULT_GIF_IDS = [
    'l0MYC0LajqoPoEADC', 'g9582DNuQppxC', 'ICOgUNjpvO0PC', '26ufdipQqU2lhNA4g', '3o7abKhOpu0NwenH3O',
    'xTiTnqUxyBBSQU2Sj6', 'l0HlNQ03J5JxX6lva', '26BRvOYThfA6CdTNQ', '3o7aD2saalBwwftBIY',
    'MoWy9eEFSfMSJDBOlC', '13CoXDjaCcik0g', '5GoVLqeAOo6PK', 'l3q2K5jinAlChoCLS',
    '3oz8xIsdbV8OB3MOcM', 'yJFeycNHJxZjhutfP8', '3o7bu3XilJ5BOiSGQ', '3o7TKSjRrfIPjeiM2A',
    'xT9IgG50Fb7Mi0prBC', 'xT4uQulxzU39HRPb6o', '3ornka9rIrKbleeWdO', 'l1J9EdzfOSgfyueLm',
    '3oEjI6SIIHBdVxXI1y', '10UUe8ZkL9kWjKICDs', 'l0MYK5fxmPYssagfK', 'gV1oRSJURBXQA',
    '3oKIPkKyhmUWuvdSpO', 'LmNwrBhejkK9EFZi5UC', 'KDOutU5alkEjYI1OhJ', '4LTBas36MaNihEoUO6',
    'Zw3oBUuOlDJaHspPQG', 'd3mlE7uhX8KFgEmY', '8TweEdaxOcuqQ6Up3C', 'ceHKRKRP6deFiKGpZL',
    'WwCdWnuvYrKXHxjEr4', 'LOEt9F2SajxuAhXTQh', '1NKtnZo5HZ6C9A7SZy', '9J7tdYltWyXIhGX80I',
    'SqMKZGY1Lf7mo', 'mGK0gKMZU9200', 'o0vwzuFwCGAFO', 'AGskxwVyGTtZS'
];

/** رابط GIF قصير يعمل عادة أفضل من مسارات media/…/giphy-downsized */
function giphyIGifUrl(id) {
    return `https://i.giphy.com/${id}.gif`;
}

function gifsFromDefaultIds(limit) {
    const ids = DEFAULT_GIF_IDS.slice(0, limit);
    return ids.map((id) => {
        const u = giphyIGifUrl(id);
        return {
            id,
            thumb: u,
            url: u
        };
    });
}

function safeGifSearchQuery(q) {
    if (!q || typeof q !== 'string') return '';
    const trimmed = q.trim().slice(0, 100);
    let out = '';
    for (let i = 0; i < trimmed.length; i++) {
        const c = trimmed.charCodeAt(i);
        if (c <= 0x08) continue;
        if (c === 0x0b || c === 0x0c) continue;
        if (c >= 0x0e && c <= 0x1f) continue;
        if (c === 0x7f) continue;
        out += trimmed[i];
    }
    return out;
}

// ================= API Routes =================

/** GIF من الموقع: مع GIPHY_API_KEY يُجلب من Giphy؛ وإلا القائمة المحلية */
app.get('/api/gifs', async (req, res) => {
    const limit = Math.min(50, Math.max(1, parseInt(String(req.query.limit || '40'), 10) || 40));
    const q = safeGifSearchQuery(req.query.q || '');
    const apiKey = (process.env.GIPHY_API_KEY || '').trim();

    if (!apiKey) {
        return res.json({ source: 'local', gifs: gifsFromDefaultIds(limit) });
    }

    try {
        const params = new URLSearchParams({
            api_key: apiKey,
            limit: String(limit),
            rating: 'g'
        });
        if (q) {
            params.set('q', q);
            params.set('lang', 'ar');
        }
        const path = q
            ? `https://api.giphy.com/v1/gifs/search?${params}`
            : `https://api.giphy.com/v1/gifs/trending?${params}`;
        const r = await fetch(path);
        if (!r.ok) {
            console.warn('Giphy HTTP', r.status);
            return res.json({ source: 'local', gifs: gifsFromDefaultIds(limit) });
        }
        const body = await r.json();
        const rows = Array.isArray(body.data) ? body.data : [];
        const gifs = rows.map((item) => {
            const id = item.id;
            if (!id) return null;
            const thumb =
                item.images?.downsized?.url ||
                item.images?.fixed_width_small?.url ||
                item.images?.fixed_height_small?.url ||
                item.images?.preview_gif?.url ||
                '';
            let url = item.images?.original?.url || '';
            if (!url || /\.mp4($|\?)/i.test(url) || !isValidGifStickerUrl(url)) {
                url = giphyIGifUrl(id);
            }
            if (!isValidGifStickerUrl(url)) url = giphyIGifUrl(id);
            if (!isValidGifStickerUrl(url)) return null;
            let thumbUrl = thumb && /^https:\/\//i.test(thumb) && !/\.mp4($|\?)/i.test(thumb) ? thumb : '';
            if (!thumbUrl || !isValidGifStickerUrl(thumbUrl)) thumbUrl = giphyIGifUrl(id);
            return {
                id,
                thumb: thumbUrl,
                url
            };
        }).filter(Boolean);
        if (!gifs.length) {
            return res.json({ source: 'local', gifs: gifsFromDefaultIds(limit) });
        }
        return res.json({ source: 'giphy', gifs });
    } catch (e) {
        console.warn('Giphy fetch error', e.message || e);
        return res.json({ source: 'local', gifs: gifsFromDefaultIds(limit) });
    }
});

// تسجيل حساب جديد
app.post('/api/auth/register', async (req, res) => {
    try {
        const username = sanitizeUsername(req.body.username || '');
        const password = (req.body.password || '').trim();
        const gender   = sanitizeText(req.body.gender) || 'male';
        const emailRaw = String(req.body.email || '').trim();
        const email = emailRaw ? emailRaw.toLowerCase() : '';

        if (!username || username.length < 3)
            return res.status(400).json({ error: 'الاسم يجب أن يكون 3 أحرف على الأقل' });
        if (!password || password.length < 6)
            return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
        if (!email || !isValidEmail(email))
            return res.status(400).json({ error: 'أدخل بريد إلكتروني صحيح' });

        const exists = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
        if (exists) return res.status(409).json({ error: 'هذا الاسم مستخدم بالفعل' });
        const emailExists = await User.findOne({ email });
        if (emailExists) return res.status(409).json({ error: 'هذا البريد مستخدم بالفعل' });

        const hash = await bcrypt.hash(password, 12);
        const verifyToken = crypto.randomBytes(24).toString('hex');
        const user = await User.create({
            username,
            password: hash,
            gender,
            email,
            emailVerified: false,
            emailVerifyTokenHash: sha256Hex(verifyToken),
            emailVerifyExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24h
        });

        const origin = (req.headers.origin && String(req.headers.origin)) || `http://${req.headers.host}`;
        const verifyUrl = `${origin}/verify-email.html?token=${encodeURIComponent(verifyToken)}`;
        let previewUrl = '';
        try {
            const { transporter, from } = await getMailTransport();
            const info = await transporter.sendMail({
                from,
                to: email,
                subject: 'تأكيد البريد الإلكتروني',
                html: `<div style="font-family:Arial,sans-serif;line-height:1.7"><h2>تأكيد البريد الإلكتروني</h2><p>اضغط الرابط لتفعيل حسابك:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>ينتهي الرابط خلال 24 ساعة.</p></div>`
            });
            previewUrl = nodemailer.getTestMessageUrl(info) || '';
        } catch (e) {
            console.error('Email send error:', e?.message || e);
        }

        const token = signUserJwt(user);
        setAuthCookie(res, token);
        res.status(201).json({
            token,
            user: { username: user.username, gender: user.gender, avatar: null, email: user.email, emailVerified: user.emailVerified },
            emailPreviewUrl: previewUrl
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const token = String(req.body.token || '').trim();
        if (!token || token.length < 16) return res.status(400).json({ ok: false, error: 'Invalid token' });
        const tokenHash = sha256Hex(token);
        const user = await User.findOne({
            emailVerifyTokenHash: tokenHash,
            emailVerifyExpiresAt: { $gt: new Date() }
        });
        if (!user) return res.status(400).json({ ok: false, error: 'Token expired or invalid' });
        user.emailVerified = true;
        user.emailVerifyTokenHash = '';
        user.emailVerifyExpiresAt = null;
        await user.save();
        res.json({ ok: true });
    } catch (e) {
        console.error('verify-email error', e);
        res.status(500).json({ ok: false, error: 'Server error' });
    }
});

// تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
    try {
        const username = sanitizeUsername(req.body.username || '');
        const password = (req.body.password || '').trim();

        if (!username || !password)
            return res.status(400).json({ error: 'أدخل الاسم وكلمة المرور' });

        const ip = getClientIp(req);
        if (isIpBlockedLocal(ip) || await isIpBlockedRedis(ip)) {
            return res.status(429).json({
                error: 'محاولات كثيرة. حاول لاحقاً.',
                code: 'ip_temporarily_blocked'
            });
        }

        if (isBlockedLogin(req, username)) {
            return res.status(429).json({
                error: 'محاولات كثيرة. حاول لاحقاً.',
                code: 'too_many_attempts'
            });
        }

        const user = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
        if (!user) {
            noteLoginFail(req, username);
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            noteLoginFail(req, username);
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        const now = new Date();
        if (user.banExpiresAt && user.banExpiresAt <= now) {
            user.banExpiresAt = null;
            user.banReason = '';
            await user.save();
        }
        if (user.banExpiresAt && user.banExpiresAt > now) {
            return res.status(403).json({
                error: 'حسابك محظور مؤقتاً حتى انتهاء مدة الحظر.',
                code: 'account_banned',
                bannedUntil: user.banExpiresAt.toISOString(),
                banReason: user.banReason || ''
            });
        }

        if (requireEmailVerifiedForLogin() && !user.emailVerified) {
            return res.status(403).json({
                error: 'يرجى تأكيد البريد الإلكتروني قبل تسجيل الدخول.',
                code: 'email_not_verified'
            });
        }

        await User.findByIdAndUpdate(user._id, { lastSeen: new Date() });

        noteLoginSuccess(req, username);
        const token = signUserJwt(user);
        setAuthCookie(res, token);
        res.json({ token, user: { username: user.username, gender: user.gender, avatar: user.avatar, bio: user.bio } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

// التحقق من التوكن
app.get('/api/auth/verify', verifyToken, (req, res) => {
    res.json({ valid: true, username: req.user.username });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        path: '/'
    });
    res.json({ ok: true });
});

/** إبطال جميع الجلسات (JWT) للمستخدم الحالي */
app.post('/api/auth/logout-all', requireCsrf, verifyToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { $inc: { tokenVersion: 1 } });
        await writeAudit(req, {
            action: 'auth_logout_all',
            actorUserId: req.user.id,
            actorUsername: req.user.username,
            targetUserId: req.user.id,
            targetUsername: req.user.username,
            meta: {}
        });
        res.clearCookie('authToken', {
            httpOnly: true,
            secure: isProd,
            sameSite: 'lax',
            path: '/'
        });
        res.json({ ok: true });
    } catch (e) {
        console.error('logout-all:', e);
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

// التحقق من توفر الاسم
app.get('/api/auth/check-nickname/:nick', (req, res) => {
    const nick = sanitizeUsername(req.params.nick || '');
    if (!nick) return res.json({ available: false });
    let taken = false;
    for (const [, usersMap] of roomUsersList) {
        for (const u of usersMap.values()) {
            if (u.username.toLowerCase() === nick.toLowerCase()) { taken = true; break; }
        }
        if (taken) break;
    }
    res.json({ available: !taken });
});

// ================= Socket.IO =================
const io = new Server(server, {
    maxHttpBufferSize: 6 * 1024 * 1024,
    pingTimeout: 60000, pingInterval: 25000,
    transports: ['websocket', 'polling'],
    allowRequest: (req, callback) => {
        (async () => {
            try {
                const ip =
                    String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
                    String(req.socket?.remoteAddress || '').trim() ||
                    'ip:unknown';

                if (isIpBlockedLocal(ip) || await isIpBlockedRedis(ip)) return callback('forbidden', false);

                const origin = String(req.headers.origin || '').trim();
                if (!origin) return callback(null, true);
                if (ALLOWED_ORIGINS.length) {
                    return callback(originInAllowList(origin) ? null : 'forbidden', originInAllowList(origin));
                }
                const host = req.headers.host;
                if (!host) return callback('forbidden', false);
                const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase() || 'http';
                const expected = `${proto}://${host}`;
                if (origin !== expected) return callback('forbidden', false);
                return callback(null, true);
            } catch {
                return callback('forbidden', false);
            }
        })();
    }
});

const roomUsersList = new Map();

// ================= Bots (Room + Private) =================
const botRegistry = new Map(); // usernameLower -> bot
const botConversations = new Map(); // key "human|bot" -> { startedAt, humanMsgs, botMsgs }
const randomBotRegistry = []; // 50 شخصيات للمطابقة العشوائية
const randomBotConversations = new Map(); // socket.id -> { bot, humanMsgs, botMsgs }

function hasArabic(text) {
    return /[\u0600-\u06FF]/.test(String(text || ''));
}

function dialectForRoom(room) {
    const r = String(room || '').toLowerCase();
    if (r.includes('morocco')) return { code: 'ma', labelAr: 'المغرب', labelEn: 'Morocco' };
    if (r.includes('syria')) return { code: 'sy', labelAr: 'سوريا', labelEn: 'Syria' };
    if (r.includes('egypt')) return { code: 'eg', labelAr: 'مصر', labelEn: 'Egypt' };
    if (r.includes('saudi')) return { code: 'sa', labelAr: 'السعودية', labelEn: 'Saudi' };
    if (r.includes('uae') || r.includes('qatar') || r.includes('bahrain')) return { code: 'gulf', labelAr: 'الخليج', labelEn: 'Gulf' };
    if (r.includes('palestine')) return { code: 'ps', labelAr: 'فلسطين', labelEn: 'Palestine' };
    if (r.includes('lebanon')) return { code: 'lb', labelAr: 'لبنان', labelEn: 'Lebanon' };
    if (r.includes('algeria')) return { code: 'dz', labelAr: 'الجزائر', labelEn: 'Algeria' };
    if (r.includes('tunisia')) return { code: 'tn', labelAr: 'تونس', labelEn: 'Tunisia' };
    if (r.includes('levant')) return { code: 'levant', labelAr: 'الشام', labelEn: 'Levant' };
    if (r.includes('north africa')) return { code: 'na', labelAr: 'شمال أفريقيا', labelEn: 'North Africa' };
    if (r.includes('gulf region')) return { code: 'gulf', labelAr: 'الخليج', labelEn: 'Gulf' };
    if (r.includes('girls only')) return { code: 'girls', labelAr: 'بنات', labelEn: 'Girls' };
    return { code: 'ar', labelAr: 'المنطقة', labelEn: 'Region' };
}

const DIALECT_PACKS = {
    ma: {
        male: ['آش خبارك؟', 'لاباس عليك؟', 'شنو كتدير دابا؟', 'واش كلشي مزيان؟', 'حشومة هكا 😄'],
        female: ['آش خبارك؟', 'لاباس؟', 'شنو الأخبار؟', 'واش كتسمعني مزيان؟', 'ههه زوينة 😄'],
        room: ['سلام', 'لاباس؟', 'شنو كاين؟', 'واش كاين شي واحد؟'],
        qShort: ['شنو كتقصد؟', 'حكي ليا أكثر؟', 'واش بصح؟', 'علاش؟']
    },
    sy: {
        male: ['شلونك؟', 'شو عم تعمل هلق؟', 'اي تمام… كمل.', 'ولا يهمك، فهمان.', 'اي والله'],
        female: ['شلونك؟', 'شو صاير معك؟', 'تمام… كمل', 'ولا يهمك', 'اي فهمتك'],
        room: ['مرحبا', 'شلونكن؟', 'شو الأخبار؟', 'في حدا هون؟'],
        qShort: ['شو قصدك؟', 'شو يعني؟', 'ليش؟', 'و بعدين؟']
    },
    eg: {
        male: ['إزيك؟', 'عامل إيه؟', 'تمام… كمل.', 'ماشي… طب وبعدين؟', 'حلو ده'],
        female: ['إزيك؟', 'عاملة إيه؟', 'تمام… كمل', 'طيب قوليلي', 'حلو أوي'],
        room: ['أهلا', 'إزيكم؟', 'فيه حد؟', 'عاملين إيه؟'],
        qShort: ['قصدك إيه؟', 'يعني إيه؟', 'ليه؟', 'وبعدين؟']
    },
    gulf: {
        male: ['هلا والله', 'شلونك؟', 'تمام… كمل', 'عطني تفاصيل أكثر', 'زين'],
        female: ['هلا', 'شلونك؟', 'تمام… كمل', 'قوليلي أكثر', 'زين'],
        room: ['هلا', 'وش الأخبار؟', 'في أحد؟', 'هلا والله'],
        qShort: ['وش تقصد؟', 'ليش؟', 'وش صار؟', 'وبعدين؟']
    },
    ar: {
        male: ['تمام، فهمت عليك. كمل.', 'اوكي… وضّح لي أكثر.', 'ممتاز، وش صار بعدها؟', 'خلك معي'],
        female: ['تمام فهمتك. كمل', 'اوكي… ممكن توضح؟', 'ممتاز، وش صار بعدها؟', 'خلينا خطوة خطوة'],
        room: ['هلا', 'في أحد؟', 'كيفكم؟', 'مساء الخير'],
        qShort: ['وش تقصد؟', 'طيب ليش؟', 'وبعدين؟', 'يعني؟']
    }
};

function clampText(s, maxLen) {
    const t = String(s || '').trim();
    if (t.length <= maxLen) return t;
    return t.slice(0, maxLen).trim();
}

function shortFollowUp(dialect, ar) {
    if (!ar) return choice(['Why?', 'How?', 'Then?', 'What do you mean?']);
    const d = String(dialect || 'ar');
    const pack = DIALECT_PACKS[d] || DIALECT_PACKS.ar;
    return choice(pack.qShort || DIALECT_PACKS.ar.qShort);
}

function casualizeArabic(dialect, text) {
    // إزالة مفردات فصحى/رسمية شائعة واستبدالها بلهجي بسيط
    let t = String(text || '');
    const map = [
        [/لو سمحت/gu, 'بليز'],
        [/يرجى/gu, 'بليز'],
        [/خلّينا|خلينا/gu, 'خلّنا'],
        [/محترمين/gu, 'محترمين شوي'],
        [/تقريباً/gu, 'تقريباً'],
        [/أهلاً/gu, 'هلا'],
        [/من المنطقة/gu, 'من هالجهة']
    ];
    for (const [re, rep] of map) t = t.replace(re, rep);
    // لهجة سورية: "شو" بدل "وش"
    if (dialect === 'sy') t = t.replace(/\bوش\b/gu, 'شو');
    // لهجة مغربية: "شنو" بدل "وش"
    if (dialect === 'ma') t = t.replace(/\bوش\b/gu, 'شنو');
    return t;
}

const BOT_PERSONAS = {
    friendly: { emojiP: 0.35, shortP: 0.55, skipInstantP: 0.14, skipAfterP: 0.26, afterMin: 4, afterMax: 8 },
    shy:      { emojiP: 0.22, shortP: 0.75, skipInstantP: 0.22, skipAfterP: 0.30, afterMin: 3, afterMax: 6 },
    serious:  { emojiP: 0.10, shortP: 0.45, skipInstantP: 0.10, skipAfterP: 0.20, afterMin: 5, afterMax: 9 },
    sarcastic:{ emojiP: 0.18, shortP: 0.55, skipInstantP: 0.20, skipAfterP: 0.22, afterMin: 4, afterMax: 7 },
    flirty:   { emojiP: 0.45, shortP: 0.50, skipInstantP: 0.12, skipAfterP: 0.18, afterMin: 6, afterMax: 10 }
};

function pickPersona(gender) {
    // خفف "flirty" للإناث حتى لا يصبح مزعجاً
    const pool = gender === 'female'
        ? ['friendly','friendly','shy','serious','sarcastic','flirty']
        : ['friendly','friendly','serious','sarcastic','flirty','shy'];
    return choice(pool);
}

function analyzeMsg(text) {
    const t = String(text || '').trim().toLowerCase();
    const ar = hasArabic(t);
    const intents = new Set();
    if (!t) return { ar, intents: Array.from(intents), isQuestion: false, wants: null, keywords: [] };
    const isQuestion = /\?/.test(t) || (ar ? /(ليش|كيف|شو|متى|وين|قديش|مين)\b/.test(t) : /\b(what|why|how|who|where|when)\b/.test(t));
    if (isQuestion) intents.add('question');
    if (ar ? /(سلام|مرحبا|هلا|أهلا)/.test(t) : /\b(hi|hello|hey)\b/.test(t)) intents.add('greet');
    if (ar ? /(اسمك|مين انت|من انت)/.test(t) : /\b(your name|who are you)\b/.test(t)) intents.add('who');
    if (ar ? /(من وين|من أي بلد|من اي بلد|منين)/.test(t) : /\b(where are you from)\b/.test(t)) intents.add('where');
    if (ar ? /(كم عمرك|عمرك|سنك)/.test(t) : /\b(how old|your age)\b/.test(t)) intents.add('age');
    if (ar ? /(احبك|حبيبي|حبيبتي|قلبي)/.test(t) : /\b(i love you|love you)\b/.test(t)) intents.add('flirt');
    if (ar ? /(ملل|طفشان|زهقان)/.test(t) : /\b(bored)\b/.test(t)) intents.add('bored');
    if (/(\*\*\*|fuck|shit|bitch|asshole|wtf)/i.test(t)) intents.add('rude');
    // كلمات مفتاحية بسيطة (آخر 2-3 كلمات غير قصيرة)
    const words = t.replace(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/).filter(Boolean);
    const keywords = words.filter((w) => w.length >= 4).slice(-3);
    return { ar, intents: Array.from(intents), isQuestion, keywords };
}

function personaWrap(personaId, ar, text) {
    const p = BOT_PERSONAS[personaId] || BOT_PERSONAS.friendly;
    const extrasAr = ['🙂','..','تمام','طيب'];
    const extrasEn = ['🙂','..','OK','sure'];
    const extra = choice(ar ? extrasAr : extrasEn);
    if (Math.random() < p.shortP) return text;
    return Math.random() < p.emojiP ? `${text} ${extra}` : text;
}

function botAwareReply(bot, userText, dialect, personaId) {
    const a = analyzeMsg(userText);
    const d = String(dialect || bot.dialect || 'ar');
    const pack = DIALECT_PACKS[d] || DIALECT_PACKS.ar;
    const male = bot.gender !== 'female';
    const ar = a.ar;

    // ردود واعية حسب النية
    if (a.intents.includes('rude')) {
        const r = ar
            ? (male ? 'لا يا صاحبي… خلّنا محترمين شوي.' : 'بليز… خلّنا محترمين شوي.')
            : (male ? 'Hey… let’s be respectful.' : 'Please… be respectful.');
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, r) : r);
    }
    if (a.intents.includes('greet') && !a.intents.includes('question')) {
        const g = ar ? choice(pack.room || DIALECT_PACKS.ar.room) : choice(['Hi', 'Hey', 'Hello']);
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, g) : g);
    }
    if (a.intents.includes('who')) {
        const r = ar
            ? `أنا ${bot.username} 🙂`
            : `I'm ${bot.username}.`;
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, r) : r);
    }
    if (a.intents.includes('age')) {
        const age = bot.age || randInt(19, 33);
        bot.age = age;
        const r = ar ? `عمري ${age}.` : `I'm around ${age}.`;
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, r) : r);
    }
    if (a.intents.includes('where')) {
        const who =
            d === 'ma' ? (ar ? 'المغرب' : 'Morocco') :
                d === 'sy' ? (ar ? 'سوريا' : 'Syria') :
                    d === 'eg' ? (ar ? 'مصر' : 'Egypt') :
                        d === 'gulf' ? (ar ? 'الخليج' : 'Gulf') :
                            (ar ? 'المنطقة' : 'the region');
        const r = ar ? `أنا من ${who}.` : `I'm from ${who}.`;
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, r) : r);
    }
    if (a.intents.includes('bored')) {
        const r = ar
            ? (male ? 'طيب… وش تحب تسوي؟' : 'طيب… وش تحبين تسوين؟')
            : 'Okay—what are you into?';
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, r) : r);
    }
    if (a.intents.includes('flirt')) {
        const r = ar
            ? (male ? 'هههه قوي 😄 طيب قولي عنك شوي.' : 'هههه لطيف 🙂 طيب قولي عنك شوي.')
            : 'Haha 🙂 tell me about you.';
        return personaWrap(personaId, ar, ar ? casualizeArabic(d, r) : r);
    }

    // fallback: لهجة + متابعة على كلمات المفتاح
    let base = botReplyText(bot, userText, { dialect: d });
    if (ar) base = casualizeArabic(d, base);
    // لا نسأل كثير: سؤال واحد قصير فقط عند وجود كلمة مفتاحية أو سؤال من المستخدم
    const shouldAsk = (a.isQuestion || (a.keywords && a.keywords.length)) && Math.random() < 0.22;
    if (shouldAsk) {
        const follow = shortFollowUp(d, ar);
        const merged = clampText(`${base} ${follow}`, 90);
        return personaWrap(personaId, ar, merged);
    }
    return personaWrap(personaId, ar, clampText(base, 90));
}

function dialectForRandomRegion(region) {
    const r = String(region || '').toLowerCase();
    // region في random = 'all' أو قيمة مخصصة من الواجهة (قد تكون بلد/إقليم)
    if (r === 'ma' || r.includes('morocco')) return 'ma';
    if (r === 'sy' || r.includes('syria')) return 'sy';
    if (r === 'eg' || r.includes('egypt')) return 'eg';
    if (r === 'sa' || r.includes('saudi')) return 'gulf';
    if (r.includes('gulf')) return 'gulf';
    if (r.includes('north_africa') || r.includes('north africa') || r === 'dz' || r === 'tn') return 'ma';
    if (r.includes('levant') || r === 'lb' || r === 'ps' || r === 'jo') return 'sy';
    return 'ar';
}

function initRandomBots() {
    if (randomBotRegistry.length) return;
    const maleNames = ['Omar','Yousef','Khaled','Hassan','Sami','Nader','Tariq','Adel','Fares','Hamza','Ziad','Karim','Bilal','Anas','Badr','Rami','Majd','Iyad','Saad','Hani'];
    const femaleNames = ['Sara','Lina','Nour','Huda','Maya','Aya','Reem','Rana','Farah','Jana','Mariam','Salma','Rita','Dina','Yara','Laila','Hiba','Ruba','Sahar','Noha'];
    const dialects = ['ma', 'sy', 'eg', 'gulf', 'ar'];
    const seen = new Set();
    while (randomBotRegistry.length < 50) {
        const gender = Math.random() < 0.5 ? 'female' : 'male';
        const base = gender === 'female' ? choice(femaleNames) : choice(maleNames);
        const tag = randInt(10, 999);
        const username = `${base}${tag}`;
        const key = username.toLowerCase();
        if (seen.has(key) || botRegistry.has(key)) continue;
        seen.add(key);
        const dialect = choice(dialects);
        const color = gender === 'female' ? '#ff69b4' : '#00d2ff';
        const avatar = svgAvatarDataUrl(base[0], gender === 'female' ? '#db2777' : '#0284c7');
        const persona = pickPersona(gender);
        randomBotRegistry.push({ username, gender, dialect, color, avatar, persona });
    }
}

function randomBotReplyText(bot, userText, dialect) {
    // نفس منطق الرد لكن بتأخير أقل + لهجة محددة
    return botReplyText(
        { ...bot, dialect: dialect || bot.dialect || 'ar' },
        userText,
        { dialect: dialect || bot.dialect || 'ar' }
    );
}

function randomBotPickBehavior(bot) {
    // سلوكيات بشرية: بعضهم يطير فوراً، بعضهم بعد عدة رسائل، وبعضهم يكمل
    // نسب بسيطة ويمكن تعديلها لاحقاً
    const r = Math.random();
    const persona = BOT_PERSONAS[bot.persona] || BOT_PERSONAS.friendly;
    const instantP = persona.skipInstantP;
    const afterP = persona.skipAfterP;
    if (r < instantP) {
        return { kind: 'instant_skip', delayMs: randInt(800, 2200) };
    }
    if (r < instantP + afterP) {
        return {
            kind: 'skip_after_msgs',
            // بعد 4–8 رسائل (المجموع) ثم يطير
            afterTotalMsgs: randInt(persona.afterMin, persona.afterMax),
            delayMs: randInt(1200, 3500)
        };
    }
    return { kind: 'normal' };
}

function endRandomBotSession(socket, reason = 'partner_skipped') {
    if (!socket?.randomBot) return;
    // استخدم randomEndSession كي ننظف الحالة صح
    randomEndSession(socket, reason === 'partner_skipped' ? 'skip' : reason);
    // randomEndSession (للبوت) يرسل randomSessionEnded {reason}
    // نريد أن يشعر المستخدم أنه "الشريك تخطى"
    try {
        socket.emit('randomSessionEnded', { reason: 'partner_skipped' });
    } catch {
        /* ignore */
    }
}

function maybeTriggerRandomBotSkip(socket) {
    const st = randomBotConversations.get(socket.id);
    if (!st || !socket.randomBot) return;
    const b = st.behavior;
    if (!b) return;
    if (b.kind === 'skip_after_msgs') {
        const total = (st.humanMsgs || 0) + (st.botMsgs || 0);
        if (total >= b.afterTotalMsgs && !st.skipScheduled) {
            st.skipScheduled = true;
            setTimeout(() => endRandomBotSession(socket, 'partner_skipped'), b.delayMs || 1500);
        }
    }
}

function scheduleRandomBotReply(socket, userText) {
    const st = randomBotConversations.get(socket.id);
    if (!st || !st.bot) return;
    st.humanMsgs++;
    const first = st.botMsgs === 0;
    let delaySec;
    if (first) {
        // في المطابقة العشوائية: لا يتأخر كثيراً
        delaySec = randInt(3, 8);
    } else {
        delaySec = randInt(1, 4);
        if ((st.humanMsgs + st.botMsgs) % 6 === 0) delaySec += 5; // توقف قصير بعد كل ~6 رسائل
    }
    const dialect = st.dialect || st.bot.dialect || 'ar';
    const reply = botAwareReply(st.bot, userText, dialect, st.bot.persona || 'friendly');
    setTimeout(() => {
        // ربما انتهت الجلسة أثناء الانتظار
        if (!socket.randomBot || !randomBotConversations.has(socket.id)) return;
        st.botMsgs++;
        socket.emit('randomChatMessage', {
            from: st.bot.username,
            text: reply,
            time: new Date().toLocaleTimeString()
        });
        maybeTriggerRandomBotSkip(socket);
    }, delaySec * 1000);
    maybeTriggerRandomBotSkip(socket);
}

function randInt(min, max) {
    const a = Math.ceil(min);
    const b = Math.floor(max);
    return Math.floor(Math.random() * (b - a + 1)) + a;
}

function choice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function svgAvatarDataUrl(letter, bg) {
    const safeLetter = String(letter || '?').slice(0, 2).toUpperCase();
    const fill = String(bg || '#334155');
    const svg =
        `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96">` +
        `<defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1">` +
        `<stop offset="0" stop-color="${fill}"/><stop offset="1" stop-color="#0b1220"/></linearGradient></defs>` +
        `<circle cx="48" cy="48" r="46" fill="url(#g)"/>` +
        `<text x="48" y="56" text-anchor="middle" font-family="Segoe UI, Arial" font-size="34" font-weight="800" fill="#fff">${safeLetter}</text>` +
        `</svg>`;
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function botId(username) {
    return `bot:${String(username).toLowerCase()}`;
}

function getRoomMap(room) {
    const r = String(room || '').trim();
    if (!r) return null;
    if (!roomUsersList.has(r)) roomUsersList.set(r, new Map());
    return roomUsersList.get(r);
}

function emitRoomUpdates(room) {
    const m = roomUsersList.get(room);
    if (!m) return;
    io.to(room).emit('updateUserList', Array.from(m.values()));
    // احسب العدد من خريطة الغرفة (يشمل البوتات + السوكيتات)
    io.to(room).emit('updateUserCount', m.size || 0);
}

function botJoinRoom(bot, room) {
    const cleanRoom = sanitizeText(room);
    if (!cleanRoom) return;
    // لا تدخل غرفة البنات إلا إن كانت أنثى
    if (cleanRoom === 'Girls Only' && bot.gender !== 'female') return;
    // اترك الغرفة السابقة
    if (bot.room && roomUsersList.has(bot.room)) {
        const prev = roomUsersList.get(bot.room);
        prev.delete(botId(bot.username));
        emitRoomUpdates(bot.room);
    }
    bot.room = cleanRoom;
    bot.dialect = dialectForRoom(cleanRoom).code;
    const m = getRoomMap(cleanRoom);
    m.set(botId(bot.username), {
        id: botId(bot.username),
        username: bot.username,
        gender: bot.gender,
        color: bot.color,
        allowPrivateChat: true,
        allowPrivateImages: 'everyone',
        avatar: bot.avatar,
        coverPhoto: null,
        authType: 'bot'
    });
    // رسالة نظام خفيفة (بدون إزعاج)
    io.to(cleanRoom).emit('message', {
        username: 'System',
        text: `👋 انضم ${bot.username} إلى الغرفة`,
        type: 'text',
        color: '#00d2ff',
        isSystem: true,
        time: new Date().toLocaleTimeString()
    });
    emitRoomUpdates(cleanRoom);
}

function botSayInRoom(bot, text) {
    if (!bot.room) return;
    const cleanText = filterBadWords(sanitizeText(text));
    if (!cleanText.trim()) return;
    io.to(bot.room).emit('message', {
        username: bot.username,
        text: cleanText,
        media: null,
        type: 'text',
        color: bot.color,
        avatar: bot.avatar,
        coverPhoto: null,
        isSystem: false,
        time: new Date().toLocaleTimeString()
    });
}

function getOrInitBotConv(human, botName) {
    const k = `${String(human).toLowerCase()}|${String(botName).toLowerCase()}`;
    let s = botConversations.get(k);
    if (!s) {
        s = { startedAt: Date.now(), humanMsgs: 0, botMsgs: 0, history: [] };
        botConversations.set(k, s);
    }
    return { key: k, state: s };
}

function botReplyText(bot, userText, ctx = {}) {
    const ar = hasArabic(userText);
    const male = bot.gender !== 'female';
    const d = String(ctx.dialect || bot.dialect || 'ar');
    const pack = DIALECT_PACKS[d] || DIALECT_PACKS.ar;
    const baseArMale = pack.male || DIALECT_PACKS.ar.male;
    const baseArFemale = pack.female || DIALECT_PACKS.ar.female;
    const baseEnMale = [
        'Got it. Tell me more.',
        'Okay… can you clarify a bit?',
        'Alright. What happened next?',
        'Makes sense. Let’s go step by step.',
        'I’m with you.'
    ];
    const baseEnFemale = [
        'Got you. Tell me more.',
        'Okay… can you explain a bit?',
        'Alright. What happened next?',
        'Makes sense. Let’s take it step by step.',
        'I’m here with you.'
    ];
    const pool = ar ? (male ? baseArMale : baseArFemale) : (male ? baseEnMale : baseEnFemale);
    // ردود صغيرة فيها “أسئلة” لتحفيز الحوار
    const extra = ar
        ? ['🙂', '...', '✅', 'طيب', 'تمام']
        : ['🙂', '...', 'OK', 'Sure', 'Alright'];
    const t = choice(pool);
    // أحياناً أضف ملحق بسيط
    return Math.random() < 0.35 ? `${t} ${choice(extra)}` : t;
}

function scheduleBotPrivateReply({ fromSocket, bot, toUsername, userText }) {
    const { state } = getOrInitBotConv(toUsername, bot.username);
    state.humanMsgs++;
    state.history.push({ from: toUsername, text: userText, at: Date.now() });
    if (state.history.length > 12) state.history.splice(0, state.history.length - 12);

    const first = state.botMsgs === 0;
    let delaySec;
    if (first) {
        // أول رد: تأخير واقعي 10–30 ثانية
        delaySec = choice([10, 15, 30, 12, 18, 22, 26]);
    } else {
        // بقية الردود: 2–8 ثواني
        delaySec = randInt(2, 8);
        // بعد “حوالي 6 رسائل” أضف توقف 10 ثواني
        if ((state.botMsgs + state.humanMsgs) % 6 === 0) delaySec += 10;
    }

    const humanRoomDialect = dialectForRoom(fromSocket?.data?.room || '').code;
    // أول رسالة: عرّف البوت نفسه بشكل طبيعي حسب غرفة المستخدم
    const shouldIntro = first && Math.random() < 0.75;
    const identity =
        shouldIntro && hasArabic(userText)
            ? (() => {
                const d = humanRoomDialect || bot.dialect || 'ar';
                const who =
                    d === 'ma' ? 'مغربي' :
                        d === 'sy' ? 'سوري' :
                            d === 'eg' ? 'مصري' :
                                d === 'gulf' ? 'خليجي' :
                                    'من المنطقة';
                const verb = bot.gender === 'female' ? 'أنا' : 'أنا';
                return `${verb} ${who} 🙂`;
            })()
            : '';
    const replyCore = botAwareReply(
        bot,
        userText,
        humanRoomDialect || bot.dialect,
        bot.persona || 'friendly'
    );
    const reply = identity ? `${identity}\n${replyCore}` : replyCore;
    setTimeout(() => {
        state.botMsgs++;
        state.history.push({ from: bot.username, text: reply, at: Date.now() });
        if (state.history.length > 12) state.history.splice(0, state.history.length - 12);
        const payload = {
            from: bot.username,
            to: toUsername,
            text: reply,
            media: null,
            type: 'text',
            color: bot.color,
            avatar: bot.avatar,
            coverPhoto: null,
            time: new Date().toLocaleTimeString()
        };
        // أرسل للمستخدم فقط (لأن البوت لا يملك socket)
        fromSocket.emit('privateMessage', payload);
    }, delaySec * 1000);
}

function initBots() {
    const BOT_COUNT = Math.min(200, Math.max(10, parseInt(String(process.env.BOT_COUNT || '80'), 10) || 80));
    const maleNames = ['Omar','Yousef','Khaled','Hassan','Sami','Nader','Tariq','Adel','Fares','Hamza','Ziad','Karim','Bilal','Anas','Badr'];
    const femaleNames = ['Sara','Lina','Nour','Huda','Maya','Aya','Reem','Rana','Farah','Jana','Mariam','Salma','Rita','Dina','Yara'];
    const rooms = [
        'Morocco','Saudi Arabia','Egypt','Palestine','Lebanon','Algeria','Tunisia','Bahrain','Qatar','UAE','Syria',
        'Gulf Region','North Africa','Levant','Girls Only'
    ];

    for (let i = 0; i < BOT_COUNT; i++) {
        const gender = Math.random() < 0.45 ? 'female' : 'male';
        const base = gender === 'female' ? choice(femaleNames) : choice(maleNames);
        const tag = randInt(10, 999);
        const username = `${base}${tag}`;
        const uKey = username.toLowerCase();
        if (botRegistry.has(uKey)) { i--; continue; }
        const color = gender === 'female' ? '#ff69b4' : '#00d2ff';
        const avatar = svgAvatarDataUrl(base[0], gender === 'female' ? '#db2777' : '#0284c7');
        const persona = pickPersona(gender);
        const bot = { username, gender, color, avatar, room: '', dialect: 'ar', persona, age: null };
        botRegistry.set(uKey, bot);
        botJoinRoom(bot, choice(rooms));
    }

    // تنقّل دوري ورسائل خفيفة
    setInterval(() => {
        const bots = Array.from(botRegistry.values());
        if (!bots.length) return;
        const bot = choice(bots);
        const moveChance = 0.55;
        const sayChance = 0.35;
        const rooms = [
            'Morocco','Saudi Arabia','Egypt','Palestine','Lebanon','Algeria','Tunisia','Bahrain','Qatar','UAE','Syria',
            'Gulf Region','North Africa','Levant','Girls Only'
        ];

        if (Math.random() < moveChance) {
            botJoinRoom(bot, choice(rooms));
        } else if (Math.random() < sayChance) {
            const d = bot.dialect || dialectForRoom(bot.room).code;
            const pack = DIALECT_PACKS[d] || DIALECT_PACKS.ar;
            const msg = choice(pack.room || DIALECT_PACKS.ar.room);
            botSayInRoom(bot, msg);
        }
    }, randInt(45_000, 90_000));
}

/** انتظار مطابقة عشوائية (نص فقط في الطور الأول) */
const randomWaitList = [];

function randomPrefsCompatible(a, b) {
    const aWant = a.want || 'any';
    const bWant = b.want || 'any';
    const aGender = a.gender === 'female' ? 'female' : a.gender === 'other' ? 'other' : 'male';
    const bGender = b.gender === 'female' ? 'female' : b.gender === 'other' ? 'other' : 'male';
    const aOk = aWant === 'any' || aWant === bGender;
    const bOk = bWant === 'any' || bWant === aGender;
    return aOk && bOk;
}

function randomRegionOk(a, b) {
    const ra = String(a.region || 'all').toLowerCase();
    const rb = String(b.region || 'all').toLowerCase();
    if (ra === 'all' || rb === 'all') return true;
    return ra === rb;
}

function randomLeaveWait(socket) {
    const i = randomWaitList.findIndex((x) => x.socket.id === socket.id);
    if (i >= 0) randomWaitList.splice(i, 1);
    if (!socket.randomPartner) delete socket.randomMeta;
}

function randomEndSession(socket, reason) {
    // جلسة مع بوت (بدون شريك socket)
    if (socket.randomBot) {
        delete socket.randomPairRoom;
        delete socket.randomBot;
        delete socket.randomMeta;
        randomBotConversations.delete(socket.id);
        try {
            socket.emit('randomSessionEnded', { reason });
        } catch {
            /* disconnected */
        }
        return;
    }
    const partner = socket.randomPartner;
    if (!partner) return;
    const roomName = socket.randomPairRoom;
    if (roomName) {
        socket.leave(roomName);
        partner.leave(roomName);
    }
    delete socket.randomPairRoom;
    delete partner.randomPairRoom;
    delete socket.randomPartner;
    delete partner.randomPartner;
    delete socket.randomMeta;
    delete partner.randomMeta;
    try {
        socket.emit('randomSessionEnded', { reason });
        partner.emit('randomSessionEnded', { reason: reason === 'skip' ? 'partner_skipped' : reason });
    } catch {
        /* disconnected */
    }
}

function randomCleanupDisconnect(socket) {
    randomLeaveWait(socket);
    if (socket.randomBot) {
        delete socket.randomPairRoom;
        delete socket.randomBot;
        delete socket.randomMeta;
        randomBotConversations.delete(socket.id);
        return;
    }
    if (socket.randomPartner) {
        const partner = socket.randomPartner;
        const roomName = socket.randomPairRoom;
        if (roomName) {
            try {
                socket.leave(roomName);
                partner.leave(roomName);
            } catch {
                /* ignore */
            }
        }
        delete socket.randomPairRoom;
        delete partner.randomPairRoom;
        delete socket.randomPartner;
        delete partner.randomPartner;
        delete partner.randomMeta;
        try {
            partner.emit('randomSessionEnded', { reason: 'disconnect' });
        } catch {
            /* ignore */
        }
    }
    delete socket.randomMeta;
}

// التحقق من JWT عند الاتصال (+ رفض الحسابات المحظورة مؤقتاً)
io.use(async (socket, next) => {
    const tokenFromAuth = socket.handshake.auth?.token;
    const cookies = parseCookies(socket.handshake.headers?.cookie || '');
    const token = tokenFromAuth || cookies.authToken || null;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const u = await User.findById(decoded.id).select('banExpiresAt banReason tokenVersion permanentlyBanned');
            if (!u) {
                socket.data.verified = false;
                socket.data.authType = 'guest';
            } else {
                const now = new Date();
                if (u.permanentlyBanned) {
                    return next(new Error('ACCOUNT_BANNED_PERMANENT'));
                }
                const tvDb = u.tokenVersion != null ? u.tokenVersion : 0;
                const tvJwt = decoded.tv != null ? decoded.tv : 0;
                if (tvJwt !== tvDb)
                    return next(new Error('SESSION_REVOKED'));
                if (u.banExpiresAt && u.banExpiresAt <= now) {
                    u.banExpiresAt = null;
                    u.banReason = '';
                    await u.save();
                } else if (u.banExpiresAt && u.banExpiresAt > now) {
                    return next(new Error('ACCOUNT_BANNED'));
                }
                socket.data.verified = true;
                socket.data.userId   = decoded.id;
                socket.data.username = decoded.username;
                socket.data.authType = 'member';
            }
        } catch {
            socket.data.verified = false;
            socket.data.authType = 'guest';
        }
    } else {
        socket.data.verified = false;
        socket.data.authType = 'guest';
    }
    next();
});

function parseAdminUsernames() {
    const raw = process.env.ADMIN_USERNAMES || '';
    return raw.split(/[,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
}

async function requireAdmin(req, res, next) {
    const admins = parseAdminUsernames();
    if (!admins.length) {
        return res.status(503).json({
            error: 'إدارة الحظر غير مُفعّلة: عيّن ADMIN_USERNAMES في ملف البيئة (.env)'
        });
    }
    const uname = String(req.user.username || '').toLowerCase();
    if (!admins.includes(uname))
        return res.status(403).json({ error: 'غير مصرّح' });
    next();
}

/** حظر مستخدم لمدة شهر (30 يوماً) — يتطلب أن يكون طالب الطلب مذكوراً في ADMIN_USERNAMES */
app.post('/api/admin/ban-month', requireCsrf, verifyToken, requireAdmin, async (req, res) => {
    try {
        const target = sanitizeUsername(req.body.username || req.body.targetUsername || '');
        const reason = sanitizeText(req.body.reason || '').slice(0, 500);
        if (!target)
            return res.status(400).json({ error: 'أدخل اسم المستخدم' });
        if (target.toLowerCase() === String(req.user.username || '').toLowerCase())
            return res.status(400).json({ error: 'لا يمكنك حظر حسابك' });
        const until = new Date(Date.now() + BAN_MONTH_MS);
        const user = await User.findOneAndUpdate(
            { username: { $regex: new RegExp(`^${target}$`, 'i') } },
            { $set: { banExpiresAt: until, banReason: reason || 'انتهاك قواعد المجتمع', permanentlyBanned: false } },
            { new: true }
        );
        if (!user)
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        await writeAudit(req, {
            action: 'admin_ban_month',
            actorUserId: req.user.id,
            actorUsername: req.user.username,
            targetUserId: user._id,
            targetUsername: user.username,
            meta: { until: until.toISOString(), reason: reason || '' }
        });
        for (const s of io.sockets.sockets.values()) {
            if (s.data?.userId && String(s.data.userId) === String(user._id)) {
                try { s.disconnect(true); } catch { /* ignore */ }
            }
        }
        res.json({ ok: true, bannedUntil: until.toISOString(), username: user.username });
    } catch (err) {
        console.error('admin ban-month:', err);
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

/** حظر دائم لمستخدم */
app.post('/api/admin/ban-permanent', requireCsrf, verifyToken, requireAdmin, async (req, res) => {
    try {
        const target = sanitizeUsername(req.body.username || req.body.targetUsername || '');
        const reason = sanitizeText(req.body.reason || '').slice(0, 500);
        if (!target)
            return res.status(400).json({ error: 'أدخل اسم المستخدم' });
        if (target.toLowerCase() === String(req.user.username || '').toLowerCase())
            return res.status(400).json({ error: 'لا يمكنك حظر حسابك' });

        const user = await User.findOneAndUpdate(
            { username: { $regex: new RegExp(`^${target}$`, 'i') } },
            { $set: { permanentlyBanned: true, banExpiresAt: null, banReason: reason || 'انتهاك قواعد المجتمع' } },
            { new: true }
        );
        if (!user)
            return res.status(404).json({ error: 'المستخدم غير موجود' });

        await writeAudit(req, {
            action: 'admin_ban_permanent',
            actorUserId: req.user.id,
            actorUsername: req.user.username,
            targetUserId: user._id,
            targetUsername: user.username,
            meta: { reason: reason || '' }
        });

        for (const s of io.sockets.sockets.values()) {
            if (s.data?.userId && String(s.data.userId) === String(user._id)) {
                try { s.disconnect(true); } catch { /* ignore */ }
            }
        }
        res.json({ ok: true, username: user.username });
    } catch (err) {
        console.error('admin ban-permanent:', err);
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

/** إلغاء حظر مستخدم */
app.post('/api/admin/unban', requireCsrf, verifyToken, requireAdmin, async (req, res) => {
    try {
        const target = sanitizeUsername(req.body.username || req.body.targetUsername || '');
        if (!target)
            return res.status(400).json({ error: 'أدخل اسم المستخدم' });
        const user = await User.findOneAndUpdate(
            { username: { $regex: new RegExp(`^${target}$`, 'i') } },
            { $set: { banExpiresAt: null, banReason: '', permanentlyBanned: false } },
            { new: true }
        );
        if (!user)
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        await writeAudit(req, {
            action: 'admin_unban',
            actorUserId: req.user.id,
            actorUsername: req.user.username,
            targetUserId: user._id,
            targetUsername: user.username,
            meta: {}
        });
        res.json({ ok: true, username: user.username });
    } catch (err) {
        console.error('admin unban:', err);
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

io.on('connection', (socket) => {
    console.log(`🔌 ${socket.id} | ${socket.data.authType} | ${socket.data.username || 'ضيف'}`);

    const socketIp =
        String(socket.handshake.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
        String(socket.handshake.address || '').trim() ||
        'ip:unknown';

    // المنع الفعلي يتم أيضاً في allowRequest (يشمل Redis). هنا نتحقق من الذاكرة كطبقة إضافية.
    if (isIpBlockedLocal(socketIp)) {
        try { socket.disconnect(true); } catch { /* ignore */ }
        return;
    }

    // Rate limit بسيط لكل socket (لتقليل السبام والاستغلال)
    const rl = new Map();
    let overLimitStrikes = 0;
    function hit(key, limit, windowMs) {
        const now = Date.now();
        const cur = rl.get(key) || { n: 0, t: now };
        if (now - cur.t > windowMs) { cur.n = 0; cur.t = now; }
        cur.n++;
        rl.set(key, cur);
        if (cur.n <= limit) return true;

        // تجاوز الحدود = نقاط إساءة + احتمال فصل
        overLimitStrikes++;
        addIpAbuseLocal(socketIp, 12);
        void addIpAbuseRedis(socketIp, 12);
        if (overLimitStrikes >= 12 || isIpBlockedLocal(socketIp)) {
            try { socket.disconnect(true); } catch { /* ignore */ }
        }
        return false;
    }

    socket.on('checkNickname', (nickname, callback) => {
        if (!hit('checkNickname', 25, 10_000)) return callback(false);
        const cleanNick = sanitizeUsername(nickname);
        if (!cleanNick) return callback(false);
        let available = true;
        for (const [, usersMap] of roomUsersList) {
            for (const user of usersMap.values()) {
                if (user.username.toLowerCase() === cleanNick.toLowerCase()) { available = false; break; }
            }
            if (!available) break;
        }
        callback(available);
    });

    const GIRLS_ONLY_ROOM = 'Girls Only';

    socket.on('joinRoom', ({ username, room, gender, allowPrivateChat, allowPrivateImages, avatar, coverPhoto }) => {
        if (!hit('joinRoom', 6, 10_000)) return;
        const cleanUsername = socket.data.authType === 'member'
            ? socket.data.username
            : sanitizeUsername(username);
        const cleanRoom    = sanitizeText(room);
        const privateOk    = allowPrivateChat !== false;
        const imagesPolicy = normalizePrivateImages(allowPrivateImages);
        const safeAvatar   = sanitizeAvatarDataUrl(avatar);
        const safeCover    = sanitizeCoverDataUrl(coverPhoto);

        if (!cleanUsername || !cleanRoom) return;

        if (cleanRoom === GIRLS_ONLY_ROOM) {
            const g = gender === 'female' ? 'female' : gender === 'other' ? 'other' : 'male';
            if (g !== 'female') {
                socket.emit('joinRoomDenied', {
                    code: 'girls_only',
                    message: 'هذه الغرفة للنساء فقط. اضبط الجنس «أنثى» في ملفك للدخول.'
                });
                return;
            }
        }

        Array.from(socket.rooms).filter(r => r !== socket.id).forEach(prevRoom => {
            socket.leave(prevRoom);
            if (roomUsersList.has(prevRoom)) {
                roomUsersList.get(prevRoom).delete(socket.id);
                io.to(prevRoom).emit('updateUserList', Array.from(roomUsersList.get(prevRoom).values()));
            }
        });

        socket.join(cleanRoom);
        const userColor = gender === 'female' ? '#ff69b4' : '#00d2ff';
        socket.data = {
            ...socket.data,
            username: cleanUsername, room: cleanRoom, gender, color: userColor,
            allowPrivateChat: privateOk, allowPrivateImages: imagesPolicy,
            avatar: safeAvatar, coverPhoto: safeCover
        };

        if (!roomUsersList.has(cleanRoom)) roomUsersList.set(cleanRoom, new Map());
        roomUsersList.get(cleanRoom).set(socket.id, {
            id: socket.id, username: cleanUsername, gender, color: userColor,
            allowPrivateChat: privateOk, allowPrivateImages: imagesPolicy,
            avatar: safeAvatar, coverPhoto: safeCover, authType: socket.data.authType
        });

        io.to(cleanRoom).emit('message', {
            username: 'System', text: `👋 انضم ${cleanUsername} إلى الغرفة`,
            type: 'text', color: '#00d2ff', isSystem: true, time: new Date().toLocaleTimeString()
        });
        io.to(cleanRoom).emit('updateUserList', Array.from(roomUsersList.get(cleanRoom).values()));
        io.to(cleanRoom).emit('updateUserCount', roomUsersList.get(cleanRoom)?.size || 0);
    });

    socket.on('leaveRoom', () => {
        if (!hit('leaveRoom', 10, 10_000)) return;
        if (!socket.data?.room) return;
        const room = socket.data.room;
        socket.leave(room);
        if (roomUsersList.has(room)) {
            roomUsersList.get(room).delete(socket.id);
            io.to(room).emit('updateUserList', Array.from(roomUsersList.get(room).values()));
            io.to(room).emit('updateUserCount', roomUsersList.get(room)?.size || 0);
            io.to(room).emit('message', {
                username: 'System', text: `👋 غادر ${socket.data.username} الغرفة`,
                type: 'text', color: '#ff6b6b', isSystem: true, time: new Date().toLocaleTimeString()
            });
        }
        delete socket.data.room;
    });

    socket.on('updatePrivacy', ({ allowPrivateChat, allowPrivateImages }) => {
        if (!hit('updatePrivacy', 8, 10_000)) return;
        if (!socket.data) return;
        socket.data.allowPrivateChat   = allowPrivateChat !== false;
        socket.data.allowPrivateImages = normalizePrivateImages(allowPrivateImages);
        const room = socket.data.room;
        if (room && roomUsersList.has(room)) {
            const entry = roomUsersList.get(room).get(socket.id);
            if (entry) { entry.allowPrivateChat = socket.data.allowPrivateChat; entry.allowPrivateImages = socket.data.allowPrivateImages; }
            io.to(room).emit('updateUserList', Array.from(roomUsersList.get(room).values()));
        }
    });

    /** تحديث الصورة الرمزية أو الغلاف أثناء الجلوس في الغرفة */
    socket.on('updateProfileMedia', ({ avatar, coverPhoto }) => {
        if (!hit('updateProfileMedia', 6, 15_000)) return;
        if (!socket.data?.room) return;
        const room = socket.data.room;
        if (avatar !== undefined) socket.data.avatar = sanitizeAvatarDataUrl(avatar);
        if (coverPhoto !== undefined) socket.data.coverPhoto = sanitizeCoverDataUrl(coverPhoto);
        if (!roomUsersList.has(room)) return;
        const entry = roomUsersList.get(room).get(socket.id);
        if (!entry) return;
        entry.avatar = socket.data.avatar || null;
        entry.coverPhoto = socket.data.coverPhoto || null;
        io.to(room).emit('updateUserList', Array.from(roomUsersList.get(room).values()));
    });

    // الأعضاء فقط في الغرفة العامة
    socket.on('chatMessage', (data) => {
        if (!hit('chatMessage', 12, 10_000)) return;
        if (socket.data.authType !== 'member') return;
        const cleanRoom = sanitizeText(data.room || '');
        if (!cleanRoom || !socket.rooms.has(cleanRoom)) return;

        let cleanText = data.text ? sanitizeText(data.text) : '';
        cleanText = filterBadWords(cleanText);

        if (data.type === 'image' && data.media && !isValidImageType(data.media)) return;
        if (data.type === 'gif' && data.media && !isValidGifStickerUrl(data.media)) return;
        if (data.type === 'audio' && data.media && !isValidAudioType(data.media)) return;
        if (data.type === 'text' && (!cleanText || !cleanText.trim())) return;
        if ((data.type === 'image' || data.type === 'audio' || data.type === 'gif') && !data.media) return;

        io.to(cleanRoom).emit('message', {
            username: socket.data.username,
            text:     cleanText,
            media:    (data.type === 'image' || data.type === 'audio' || data.type === 'gif') ? data.media : null,
            type:     data.type || 'text',
            color:    socket.data.color,
            avatar:   socket.data.avatar || null,
            coverPhoto: socket.data.coverPhoto || null,
            isSystem: false,
            time:     new Date().toLocaleTimeString()
        });
    });

    socket.on('privateMessage', (data) => {
        if (!hit('privateMessage', 14, 10_000)) return;
        if (!socket.data?.username) return;
        const fromUsername = socket.data.username;
        const toUsername   = sanitizeUsername(data.toUsername);
        if (!toUsername || toUsername.toLowerCase() === fromUsername.toLowerCase()) {
            socket.emit('privateError', { code: 'invalid', message: 'Invalid recipient' }); return;
        }
        const bot = botRegistry.get(toUsername.toLowerCase());
        if (bot) {
            // البوت لا يستقبل وسائط حالياً (نص فقط)
            const type = 'text';
            let cleanText = data.text ? sanitizeText(data.text) : '';
            cleanText = filterBadWords(cleanText);
            if (!cleanText || !cleanText.trim()) return;

            // اعرض رسالة المستخدم في خيط الخاص (كما لو وصلت للبوت)
            const outgoingPayload = {
                from: fromUsername, to: bot.username, text: cleanText,
                media: null,
                type,
                color: socket.data.color || '#00d2ff',
                avatar: socket.data.avatar || null,
                coverPhoto: socket.data.coverPhoto || null,
                time: new Date().toLocaleTimeString()
            };
            socket.emit('privateMessage', { ...outgoingPayload, outgoing: true });

            // رد البوت بتأخير واقعي
            scheduleBotPrivateReply({
                fromSocket: socket,
                bot,
                toUsername: fromUsername,
                userText: cleanText
            });
            return;
        }

        const target = findSocketByUsername(toUsername);
        if (!target) { socket.emit('privateError', { code: 'offline', message: 'User is offline' }); return; }
        if (target.data.allowPrivateChat === false) { socket.emit('privateError', { code: 'disabled', message: 'This user disabled private chat' }); return; }

        const type =
            data.type === 'image' ? 'image' :
            data.type === 'audio' ? 'audio' :
            data.type === 'gif' ? 'gif' : 'text';
        if (type === 'image' && data.media) {
            if (!isValidImageType(data.media)) return;
            if (target.data.allowPrivateImages === 'nobody') { socket.emit('privateError', { code: 'images_blocked', message: 'This user does not accept private images' }); return; }
        }
        if (type === 'gif' && data.media) {
            if (!isValidGifStickerUrl(data.media)) return;
            if (target.data.allowPrivateImages === 'nobody') { socket.emit('privateError', { code: 'images_blocked', message: 'This user does not accept private images' }); return; }
        }
        if (type === 'audio' && data.media && !isValidAudioType(data.media)) return;

        let cleanText = data.text ? sanitizeText(data.text) : '';
        cleanText = filterBadWords(cleanText);
        if (type === 'text' && (!cleanText || !cleanText.trim())) return;
        if ((type === 'image' || type === 'audio' || type === 'gif') && !data.media) return;

        const payload = {
            from: fromUsername, to: toUsername, text: cleanText,
            media: (type === 'image' || type === 'audio' || type === 'gif') ? data.media : null,
            type, color: socket.data.color || '#00d2ff',
            avatar: socket.data.avatar || null,
            coverPhoto: socket.data.coverPhoto || null,
            time: new Date().toLocaleTimeString()
        };
        target.emit('privateMessage', payload);
        socket.emit('privateMessage', { ...payload, outgoing: true });
    });

    socket.on('typing', ({ username, room, isTyping }) => {
        if (!hit('typing', 30, 10_000)) return;
        const cleanRoom = sanitizeText(room || '');
        if (!cleanRoom || !socket.rooms.has(cleanRoom)) return;
        socket.to(cleanRoom).emit('displayTyping', {
            username: sanitizeText(socket.data?.username || username), isTyping, room: cleanRoom
        });
    });

    // ----- دردشة عشوائية (مطابقة) -----
    socket.on('randomJoinSearch', (payload = {}) => {
        if (!hit('randomJoinSearch', 6, 10_000)) return;
        if (socket.randomPartner || socket.randomBot) {
            socket.emit('randomError', { code: 'in_chat', message: 'End the current chat first (Skip).' });
            return;
        }
        randomLeaveWait(socket);

        const guestNick = sanitizeUsername(payload.username || '');
        const username = socket.data.authType === 'member'
            ? String(socket.data.username || '')
            : guestNick;
        if (!username) {
            socket.emit('randomError', { code: 'no_user', message: 'Nickname required' });
            return;
        }

        const gender = payload.gender === 'female' ? 'female' : payload.gender === 'other' ? 'other' : 'male';
        const want = payload.want === 'male' || payload.want === 'female' ? payload.want : 'any';
        const region = sanitizeText(payload.region || 'all').slice(0, 40).toLowerCase() || 'all';
        const mode = payload.mode === 'voice' ? 'voice' : 'text';

        if (mode === 'voice') {
            socket.emit('randomNotice', { code: 'voice_soon', message: 'Voice chat coming soon — use text for now.' });
            return;
        }

        socket.randomMeta = { username, gender, want, region, mode };

        for (let i = 0; i < randomWaitList.length; i++) {
            const other = randomWaitList[i].socket;
            if (!other.randomMeta || other.id === socket.id) continue;
            if (!randomPrefsCompatible(socket.randomMeta, other.randomMeta)) continue;
            if (!randomRegionOk(socket.randomMeta, other.randomMeta)) continue;

            randomWaitList.splice(i, 1);
            const roomName = `random:${[socket.id, other.id].sort().join('_')}`;
            socket.join(roomName);
            other.join(roomName);
            socket.randomPairRoom = roomName;
            other.randomPairRoom = roomName;
            socket.randomPartner = other;
            other.randomPartner = socket;

            const aNick = socket.data.username || socket.randomMeta.username;
            const bNick = other.data.username || other.randomMeta.username;
            socket.emit('randomMatched', { partner: bNick });
            other.emit('randomMatched', { partner: aNick });
            return;
        }

        // لا يوجد شريك بشري الآن: ابدأ البحث ثم طابق مع بوت بسرعة إن لم يظهر أحد
        randomWaitList.push({ socket });
        socket.emit('randomSearchStarted', { waiting: true });

        initRandomBots();
        const desiredDialect = dialectForRandomRegion(region);
        const wantGender = want === 'male' ? 'male' : want === 'female' ? 'female' : 'any';
        const candidates = randomBotRegistry.filter((b) => {
            if (wantGender !== 'any' && b.gender !== wantGender) return false;
            // إن كان region محدداً: حاول مطابقة اللهجة
            if (region !== 'all' && desiredDialect && b.dialect !== desiredDialect) return false;
            return true;
        });
        const picked = candidates.length ? choice(candidates) : choice(randomBotRegistry);
        const botDelayMs = randInt(1200, 3500);
        setTimeout(() => {
            // إن كان المستخدم تمّت مطابقته ببشري أو ألغى البحث
            if (socket.randomPartner || socket.randomBot) return;
            const stillWaiting = randomWaitList.findIndex((x) => x.socket.id === socket.id);
            if (stillWaiting >= 0) randomWaitList.splice(stillWaiting, 1);

            socket.randomBot = picked;
            socket.randomPairRoom = `randombot:${socket.id}`;
            // حفظ حالة محادثة البوت
            const behavior = randomBotPickBehavior(picked);
            randomBotConversations.set(socket.id, {
                bot: picked,
                dialect: desiredDialect || picked.dialect || 'ar',
                humanMsgs: 0,
                botMsgs: 0,
                behavior,
                skipScheduled: false
            });
            socket.emit('randomMatched', { partner: picked.username });

            // بعض البوتات "تتخطى" فوراً قبل بدء المحادثة
            if (behavior.kind === 'instant_skip') {
                setTimeout(() => endRandomBotSession(socket, 'partner_skipped'), behavior.delayMs || 1200);
            }
        }, botDelayMs);
    });

    socket.on('randomCancelSearch', () => {
        if (!hit('randomCancelSearch', 10, 10_000)) return;
        randomLeaveWait(socket);
        socket.emit('randomSearchStopped', {});
    });

    socket.on('randomSkip', () => {
        if (!hit('randomSkip', 10, 10_000)) return;
        if (socket.randomPartner || socket.randomBot) {
            randomEndSession(socket, 'skip');
        } else {
            randomLeaveWait(socket);
            socket.emit('randomSearchStopped', {});
        }
    });

    socket.on('randomChatMessage', (data) => {
        if (!hit('randomChatMessage', 16, 10_000)) return;
        const text = sanitizeText(data.text || '');
        if (!text.trim()) return;
        const from = socket.data.username || socket.randomMeta?.username || 'User';
        if (socket.randomBot) {
            // المستخدم أرسل للبوت: رد بسرعة وبدون تأخير كبير
            scheduleRandomBotReply(socket, text);
            return;
        }
        if (!socket.randomPartner || !socket.randomPairRoom) return;
        socket.to(socket.randomPairRoom).emit('randomChatMessage', {
            from,
            text,
            time: new Date().toLocaleTimeString()
        });
    });

    socket.on('disconnect', () => {
        randomCleanupDisconnect(socket);
        if (socket.data?.room && roomUsersList.has(socket.data.room)) {
            const room = socket.data.room;
            roomUsersList.get(room).delete(socket.id);
            io.to(room).emit('updateUserList', Array.from(roomUsersList.get(room).values()));
            io.to(room).emit('message', {
                username: 'System', text: `👋 غادر ${socket.data.username} الغرفة`,
                type: 'text', color: '#ff6b6b', isSystem: true, time: new Date().toLocaleTimeString()
            });
            io.to(room).emit('updateUserCount', roomUsersList.get(room)?.size || 0);
        }
    });
});

// ================= تشغيل السيرفر =================
const preferredPort = Number(process.env.PORT) || 3000;
/** للنشر على الحاويات/السحابة: الاستماع على كل الواجهات */
const listenHost = process.env.HOST || '0.0.0.0';
let listenPort = preferredPort;
let readyLogged = false;

function printReady() {
    if (readyLogged) return;
    readyLogged = true;
    const port = server.address()?.port || listenPort;
    const giphyOk = !!(process.env.GIPHY_API_KEY || '').trim();
    const prod = isProd ? ' (production)' : '';
    console.log(`\n🚀 السيرفر يعمل${prod} على المنفذ ${port} — الاستماع: ${listenHost}`);
    console.log(`   محلياً: http://localhost:${port}`);
    console.log(`🛡️  الأمان: Helmet | Rate Limiting | bcrypt | JWT | DOMPurify`);
    console.log(`🗄️  قاعدة البيانات: MongoDB`);
    console.log(
        giphyOk
            ? '🎬 GIF: مفعّل عبر Giphy API (ترند + بحث)'
            : '🎬 GIF: قائمة محلية — أضف GIPHY_API_KEY في ملف .env لتفعيل Giphy'
    );
    console.log('');
}

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE' && listenPort < preferredPort + 10) {
        listenPort++;
        console.warn(`⚠️  المنفذ ${listenPort - 1} مشغول — جاري تجربة ${listenPort}...`);
        setImmediate(() => server.listen(listenPort, listenHost, printReady));
        return;
    }
    console.error(err); process.exit(1);
});

server.listen(listenPort, listenHost, () => {
    printReady();
    // شغّل البوتات بعد جاهزية السيرفر
    try { initBots(); } catch (e) { console.error('initBots error:', e?.message || e); }
});
