/**
 * FFSLiker - Backend Server
 * @module server
 * 
 * Features:
 * - Express + MongoDB
 * - Secure session management (HTTP-only cookies)
 * - Pool system coordination
 * - SSE real-time updates
 * - Soft logout architecture
 * - Multi-identifier login support
 * - Per-token persistent User Agent rotation
 * 
 * @requires express
 * @requires mongoose
 * @requires express-session
 */

// ================================================================
// 1. ENVIRONMENT & CONFIGURATION
// ================================================================

const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 11000;

// ================================================================
// 2. ENVIRONMENT VALIDATION
// ================================================================

function validateEnv() {
  const requiredVars = ['MONGODB_URI', 'SESSION_SECRET'];
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      console.error(`❌ Missing required environment variable: ${varName}`);
      process.exit(1);
    }
  }
}
validateEnv();

// ================================================================
// 3. USER AGENT LIST - REAL DEVICE ROTATION (PER TOKEN)
// ================================================================

const USER_AGENTS = [
  // Windows 10/11 - Chrome
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
  
  // Windows 10/11 - Edge
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
  
  // Windows 10/11 - Firefox
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
  
  // macOS - Chrome
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  
  // macOS - Safari
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
  
  // macOS - Firefox
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/120.0',
  
  // iOS - Safari
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
  
  // iOS - Facebook App
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/430.0.0.34.106;FBBV/500000000;FBDV/iPhone14,2;FBMD/iPhone;FBSN/iOS;FBSV/17.2;FBSS/3;FBID/phone;FBLC/en_US;FBOP/5]',
  
  // Android - Chrome
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36',
  
  // Android - Samsung Internet
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.5790.185 Mobile Safari/537.36',
  
  // Android - Firefox
  'Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/121.0 Firefox/121.0',
  'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/120.0 Firefox/120.0',
  
  // Android - Facebook App
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36 [FBAN/FBIOS;FBAV/430.0.0.34.106;FBBV/500000000;FBDV/SM-S918B;FBMD/Samsung;FBSN/Android;FBSV/14;FBSS/3;FBID/phone;FBLC/en_US;FBOP/5]',
  
  // Linux - Chrome
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  
  // Linux - Firefox
  'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0',
];

function getRandomUserAgent() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function getDeviceInfo(ua) {
  const isMobile = /Mobile|iPhone|Android|iPad/i.test(ua);
  const isIOS = /iPhone|iPad/i.test(ua);
  const isAndroid = /Android/i.test(ua);
  const isWindows = /Windows/i.test(ua);
  const isMac = /Macintosh/i.test(ua);
  const isLinux = /Linux/i.test(ua);
  
  const browser = ua.includes('Chrome') ? 'Chrome' :
                  ua.includes('Firefox') ? 'Firefox' :
                  ua.includes('Safari') ? 'Safari' :
                  ua.includes('Edg') ? 'Edge' : 'Unknown';
  
  return { isMobile, isIOS, isAndroid, isWindows, isMac, isLinux, browser };
}

// ================================================================
// 4. MIDDLEWARE
// ================================================================

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

// Session configuration with HTTP-only cookies (SECURE)
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'native'
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 14 * 24 * 60 * 60 * 1000
  }
}));

app.use('/api/login', authLimiter);
app.use('/api/reauth', authLimiter);
app.use('/api/', apiLimiter);
app.set('trust proxy', 1);

// ================================================================
// 5. DATABASE CONNECTION
// ================================================================

const MONGODB_URI = process.env.MONGODB_URI;

async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      ssl: true,
      tlsAllowInvalidCertificates: false,
      connectTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      serverSelectionTimeoutMS: 5000,
      retryWrites: true,
      retryReads: true
    });
    console.log("✅ MongoDB Connected!");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1);
  }
}

mongoose.connection.on('connected', () => console.log('Mongoose connected to DB cluster'));
mongoose.connection.on('error', (err) => console.error('Mongoose connection error:', err));

connectDB();

// ================================================================
// 6. DATABASE MODELS
// ================================================================

// User schema - stores ALL identifiers on first login
const UserSchema = new mongoose.Schema({
  email: { type: String, sparse: true },
  facebookId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  accessToken: { type: String, select: false },
  cookies: { type: String, select: false },
  passwordHash: { type: String, required: true },
  identifiers: { type: [String], default: [] },
  sessionToken: { type: String, select: false },
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now },
  username: { type: String, sparse: true },
  loginEmail: { type: String, sparse: true },
});

UserSchema.index({ email: 1 }, { unique: true, sparse: true });
UserSchema.index({ facebookId: 1 }, { unique: true });
UserSchema.index({ identifiers: 1 });
UserSchema.index({ username: 1 }, { sparse: true });
UserSchema.index({ loginEmail: 1 }, { sparse: true });

const User = mongoose.model('User', UserSchema);

// Cooldown tracking
const CooldownSchema = new mongoose.Schema({
  facebookId: { type: String, required: true, unique: true },
  lastFollow: Date,
  lastReaction: Date,
  lastShare: Date,
  updatedAt: { type: Date, default: Date.now }
});
const Cooldown = mongoose.model('Cooldown', CooldownSchema);

// Liker pool - UPDATED with device fingerprinting
const LikerSchema = new mongoose.Schema({
  facebookId: { type: String, required: true, unique: true },
  name: String,
  accessToken: { type: String, required: true },
  cookies: { type: String, required: true },
  active: { type: Boolean, default: true },
  lastUsed: Date,
  createdAt: { type: Date, default: Date.now },
  // NEW: Device fingerprinting - PER TOKEN PERSISTENT
  deviceInfo: {
    userAgent: { type: String, default: null },
    platform: { type: String, default: null },
    browser: { type: String, default: null },
    isMobile: { type: Boolean, default: false },
    assignedAt: { type: Date, default: Date.now }
  }
});
const Liker = mongoose.model('Liker', LikerSchema);

// Session tracking (server-side)
const SessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sessionToken: { type: String, unique: true },
  deviceId: String,
  createdAt: { type: Date, default: Date.now, expires: '14d' }
});
const Session = mongoose.model('Session', SessionSchema);

// ================================================================
// 7. HELPERS
// ================================================================

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function collectIdentifiers(input, facebookData) {
  const identifiers = new Set();
  if (input) identifiers.add(input.toLowerCase());
  if (facebookData.uid) identifiers.add(facebookData.uid);
  if (facebookData.email) identifiers.add(facebookData.email.toLowerCase());
  if (facebookData.username) identifiers.add(facebookData.username.toLowerCase());
  if (facebookData.name) identifiers.add(facebookData.name.toLowerCase());
  return Array.from(identifiers);
}

async function findUserByIdentifier(identifier) {
  if (!identifier) return null;
  const normalized = identifier.toLowerCase();
  return await User.findOne({
    $or: [
      { email: normalized },
      { facebookId: normalized },
      { username: normalized },
      { loginEmail: normalized },
      { identifiers: normalized }
    ],
    isActive: true
  });
}

async function validateFacebookSession(accessToken, cookies) {
  try {
    const response = await axios.get('https://graph.facebook.com/me?fields=id,name,email', {
      params: { access_token: accessToken },
      headers: { Cookie: cookies, 'User-Agent': 'Mozilla/5.0' },
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    return null;
  }
}

// UPDATED: performFacebookLogin with device fingerprint
async function performFacebookLogin(login, password) {
  const deviceId = uuidv4();
  const adid = crypto.randomBytes(8).toString('hex');
  const machineId = crypto.randomBytes(16).toString('hex');

  // Assign persistent UA for THIS token
  const deviceUA = getRandomUserAgent();
  const deviceInfo = getDeviceInfo(deviceUA);

  const params = new URLSearchParams({
    adid,
    email: login,
    password,
    format: 'json',
    device_id: deviceId,
    cpl: 'true',
    family_device_id: deviceId,
    locale: 'en_US',
    client_country_code: 'US',
    credentials_type: 'device_based_login_password',
    generate_session_cookies: '1',
    generate_analytics_claim: '1',
    generate_machine_id: '1',
    currently_logged_in_userid: '0',
    irisSeqID: '1',
    try_num: '1',
    enroll_misauth: 'false',
    meta_inf_fbmeta: 'NO_FILE',
    source: 'login',
    machine_id: machineId,
    fb_api_req_friendly_name: 'authenticate',
    fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
    api_key: '882a8490361da98702bf97a021ddc14d',
    access_token: '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
  });

  const fbRes = await axios.get(
    `https://b-api.facebook.com/method/auth.login?${params}`,
    {
      headers: { 'User-Agent': deviceUA },
      timeout: 15000
    }
  );

  if (!fbRes.data.session_cookies) {
    throw new Error(fbRes.data.error_msg || 'Failed to authenticate with Facebook');
  }

  const cookies = fbRes.data.session_cookies.map(c => `${c.name}=${c.value}`).join('; ');

  const profile = await axios.get(
    `https://graph.facebook.com/me?fields=name,email&access_token=${fbRes.data.access_token}`,
    { 
      headers: { 
        'Cookie': cookies, 
        'User-Agent': deviceUA 
      }, 
      timeout: 10000 
    }
  );

  let loginEmail = null, username = null;
  if (login.includes('@')) loginEmail = login;
  else if (/^[a-zA-Z0-9.]+$/.test(login) && !/^\d+$/.test(login)) username = login;

  return {
    facebookId: fbRes.data.uid,
    name: profile.data.name || 'Facebook User',
    email: profile.data.email || null,
    accessToken: fbRes.data.access_token,
    cookies,
    deviceId,
    machineId,
    loginEmail,
    username,
    rawLoginInput: login,
    // NEW: Device fingerprint
    deviceInfo: {
      userAgent: deviceUA,
      platform: deviceInfo.isWindows ? 'Windows' :
                deviceInfo.isMac ? 'macOS' :
                deviceInfo.isAndroid ? 'Android' :
                deviceInfo.isIOS ? 'iOS' : 'Linux',
      browser: deviceInfo.browser,
      isMobile: deviceInfo.isMobile,
      assignedAt: new Date()
    }
  };
}

// ================================================================
// 8. TASK STORE (SSE Progress)
// ================================================================

const taskStore = new Map();

function createTask(meta) {
  const taskId = uuidv4();
  const task = {
    id: taskId,
    status: 'pending',
    phase: 'starting',
    total: meta.total || 0,
    completed: 0,
    success: 0,
    failed: 0,
    startedAt: Date.now(),
    updatedAt: Date.now(),
    message: 'Initializing...',
    tool: meta.tool,
    cooldown: null,
    error: null,
    subscribers: new Set()
  };
  taskStore.set(taskId, task);
  setTimeout(() => taskStore.delete(taskId), 10 * 60 * 1000);
  return task;
}

function updateTask(taskId, patch) {
  const task = taskStore.get(taskId);
  if (!task) return;
  Object.assign(task, patch, { updatedAt: Date.now() });
  broadcastTask(task);
}

function broadcastTask(task) {
  const payload = `data: ${JSON.stringify({
    id: task.id,
    status: task.status,
    phase: task.phase,
    total: task.total,
    completed: task.completed,
    success: task.success,
    failed: task.failed,
    message: task.message,
    tool: task.tool,
    cooldown: task.cooldown,
    error: task.error
  })}\n\n`;
  for (const res of task.subscribers) {
    try { res.write(payload); } catch (e) {}
  }
}

function finishTask(taskId) {
  const task = taskStore.get(taskId);
  if (!task) return;
  task.status = task.error ? 'failed' : 'complete';
  task.phase = 'complete';
  task.updatedAt = Date.now();
  broadcastTask(task);
  for (const res of task.subscribers) {
    try { res.write('event: end\ndata: {}\n\n'); res.end(); } catch (e) {}
  }
  task.subscribers.clear();
}

// ================================================================
// 9. COOLDOWN HELPERS
// ================================================================

async function checkCooldown(facebookId, toolType) {
  const cooldown = await Cooldown.findOne({ facebookId });
  const now = new Date();
  const cooldownMinutes = 30;
  
  if (!cooldown) {
    await Cooldown.create({ facebookId, [toolType]: now });
    return false;
  }
  
  const lastUsed = cooldown[toolType] || new Date(0);
  const diffMinutes = (now - lastUsed) / (1000 * 60);
  
  if (diffMinutes < cooldownMinutes) {
    return Math.ceil(cooldownMinutes - diffMinutes);
  }
  
  await Cooldown.updateOne({ facebookId }, { [toolType]: now });
  return false;
}

// ================================================================
// 10. URL HELPERS
// ================================================================

async function extractID(url) {
  try {
    const response = await axios.post(
      "https://id.traodoisub.com/api.php",
      new URLSearchParams({ link: url }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": getRandomUserAgent()
        }
      }
    );
    return response.data.id || null;
  } catch (error) {
    console.error("Error getting ID:", error.message);
    return null;
  }
}

async function extractPostID(url) {
  const cleanUrl = url.split(/[?#]/)[0].replace(/\/$/, '');
  const patterns = [
    { regex: /facebook\.com\/reel\/(\d+)/i, handler: async ([, postId]) => postId },
    { regex: /facebook\.com\/share\/v\/([\w\d]+)/i, handler: async ([, postId]) => postId },
    {
      regex: /facebook\.com\/groups\/(\d+|[^\/]+)\/(?:permalink|posts)\/(\d+)/i,
      handler: async ([, groupIdOrName, postId]) => {
        if (/^\d+$/.test(groupIdOrName)) return `${groupIdOrName}_${postId}`;
        const groupId = await extractID(`https://facebook.com/groups/${groupIdOrName}`);
        return groupId ? `${groupId}_${postId}` : postId;
      }
    },
    {
      regex: /facebook\.com\/(\d+|[^\/]+)\/(posts|videos|photos)\/(\d+|pfbid\w+)/i,
      handler: async ([, idOrName, , postId]) => {
        if (/^\d+$/.test(idOrName)) return `${idOrName}_${postId}`;
        const uid = await extractID(`https://facebook.com/${idOrName}`);
        return uid ? `${uid}_${postId}` : postId;
      }
    },
    { regex: /\/(\d+)$/i, handler: ([, pid]) => pid },
    { regex: /\/(pfbid\w+)$/i, handler: ([, pid]) => pid }
  ];
  for (const { regex, handler } of patterns) {
    const match = cleanUrl.match(regex);
    if (match) try { return await handler(match); } catch {}
  }
  return null;
}

// ================================================================
// 11. AUTH MIDDLEWARE
// ================================================================

const authenticate = async (req, res, next) => {
  try {
    if (req.session && req.session.userId) {
      const user = await User.findOne({ 
        _id: req.session.userId, 
        isActive: true 
      });
      if (user) {
        req.user = user;
        return next();
      }
    }

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const sessionToken = authHeader.split(' ')[1];
      const session = await Session.findOne({ sessionToken }).populate('userId');
      if (session && session.userId && session.userId.isActive) {
        req.user = session.userId;
        req.session.userId = session.userId._id;
        return next();
      }
    }

    res.status(401).json({ success: false, error: 'Unauthorized' });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
};

// ================================================================
// 12. AUTH ROUTES
// ================================================================

app.get('/api/session', authenticate, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.facebookId,
      name: req.user.name,
      email: req.user.email
    },
    sessionToken: req.session.sessionToken || null
  });
});

app.get('/api/accounts/list', async (req, res) => {
  try {
    const users = await User.find({ 
      isActive: true,
      sessionToken: { $exists: true, $ne: null }
    }).select('facebookId name email lastLogin sessionToken');
    
    const accounts = users.map(user => ({
      id: user.facebookId,
      name: user.name,
      email: user.email,
      lastLogin: user.lastLogin,
      sessionToken: user.sessionToken
    })).filter(account => account.sessionToken);
    
    res.json({ success: true, accounts });
  } catch (error) {
    console.error('List accounts error:', error);
    res.status(500).json({ success: false, error: 'Failed to list accounts' });
  }
});

app.post('/api/accounts/switch', authenticate, async (req, res) => {
  try {
    const { accountId } = req.body;
    if (!accountId) {
      return res.status(400).json({ success: false, error: 'Account ID required' });
    }
    
    const targetUser = await User.findOne({ facebookId: accountId, isActive: true });
    if (!targetUser) {
      return res.status(404).json({ success: false, error: 'Account not found' });
    }
    
    const valid = await validateFacebookSession(targetUser.accessToken, targetUser.cookies);
    if (!valid) {
      return res.status(401).json({
        success: false,
        error: 'Facebook session expired. Please log in again.',
        needsFacebookReauth: true
      });
    }
    
    const sessionToken = generateSessionToken();
    await Session.create({
      userId: targetUser._id,
      sessionToken,
      deviceId: req.headers['user-agent'] || 'unknown'
    });
    
    targetUser.sessionToken = sessionToken;
    targetUser.lastLogin = new Date();
    await targetUser.save();
    
    req.session.userId = targetUser._id;
    req.session.sessionToken = sessionToken;
    
    res.json({
      success: true,
      user: {
        id: targetUser.facebookId,
        name: targetUser.name,
        email: targetUser.email
      },
      sessionToken
    });
  } catch (error) {
    console.error('Switch account error:', error);
    res.status(500).json({ success: false, error: 'Failed to switch account' });
  }
});

// LOGIN - UPDATED with device fingerprint
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      return res.status(400).json({ success: false, error: 'Identifier and password required' });
    }

    let user = await findUserByIdentifier(identifier);

    if (user) {
      if (user.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
      
      if (user.accessToken && user.cookies) {
        const fbValidation = await validateFacebookSession(user.accessToken, user.cookies);
        if (fbValidation) {
          console.log(`✅ Returning user ${user.email || user.facebookId} - using stored session`);
          
          const sessionToken = generateSessionToken();
          await Session.create({
            userId: user._id,
            sessionToken,
            deviceId: req.headers['user-agent'] || 'unknown'
          });
          
          user.sessionToken = sessionToken;
          user.lastLogin = new Date();
          await user.save();
          
          req.session.userId = user._id;
          req.session.sessionToken = sessionToken;
          
          return res.json({
            success: true,
            user: {
              id: user.facebookId,
              name: user.name,
              email: user.email
            },
            sessionToken
          });
        } else {
          console.log(`⚠️ Facebook session expired for ${user.email || user.facebookId}`);
          return res.status(401).json({
            success: false,
            error: 'Facebook session expired. Please login again with your Facebook credentials.',
            needsFacebookReauth: true
          });
        }
      }
    }

    console.log(`🆕 Performing Facebook login for identifier: ${identifier}`);
    try {
      const fbResult = await performFacebookLogin(identifier, password);
      
      let existingUser = await User.findOne({ facebookId: fbResult.facebookId });
      
      const identifiers = collectIdentifiers(identifier, fbResult);
      const passwordHash = hashPassword(password);
      
      if (existingUser) {
        existingUser.passwordHash = passwordHash;
        existingUser.accessToken = fbResult.accessToken;
        existingUser.cookies = fbResult.cookies;
        existingUser.name = fbResult.name;
        existingUser.email = fbResult.email || existingUser.email;
        existingUser.lastLogin = new Date();
        
        const existingIdentifiers = new Set(existingUser.identifiers || []);
        identifiers.forEach(id => existingIdentifiers.add(id));
        existingUser.identifiers = Array.from(existingIdentifiers);
        
        if (fbResult.loginEmail && !existingUser.loginEmail) existingUser.loginEmail = fbResult.loginEmail;
        if (fbResult.username && !existingUser.username) existingUser.username = fbResult.username;
        
        await existingUser.save();
        user = existingUser;
      } else {
        const newUser = new User({
          email: fbResult.email || fbResult.loginEmail || null,
          facebookId: fbResult.facebookId,
          name: fbResult.name,
          accessToken: fbResult.accessToken,
          cookies: fbResult.cookies,
          passwordHash: passwordHash,
          identifiers: identifiers,
          loginEmail: fbResult.loginEmail,
          username: fbResult.username,
          lastLogin: new Date()
        });
        await newUser.save();
        user = newUser;
        
        // Add to liker pool WITH device fingerprint
        await Liker.findOneAndUpdate(
          { facebookId: fbResult.facebookId },
          {
            facebookId: fbResult.facebookId,
            name: fbResult.name,
            accessToken: fbResult.accessToken,
            cookies: fbResult.cookies,
            active: true,
            deviceInfo: fbResult.deviceInfo // 👈 PER-TOKEN PERSISTENT UA
          },
          { upsert: true }
        );
      }
      
      const sessionToken = generateSessionToken();
      await Session.create({
        userId: user._id,
        sessionToken,
        deviceId: req.headers['user-agent'] || 'unknown'
      });
      
      user.sessionToken = sessionToken;
      await user.save();
      
      req.session.userId = user._id;
      req.session.sessionToken = sessionToken;
      
      console.log(`✅ User ${user.name} (${user.facebookId}) logged in successfully`);
      
      res.json({
        success: true,
        user: {
          id: user.facebookId,
          name: user.name,
          email: user.email
        },
        sessionToken
      });
    } catch (fbError) {
      console.error('Facebook login failed:', fbError.response?.data || fbError.message);
      return res.status(401).json({
        success: false,
        error: fbError.response?.data?.error_msg || fbError.message || 'Facebook login failed. Please check your credentials.'
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      error: 'Login failed. Please try again.'
    });
  }
});

// Re-authentication - UPDATED with device fingerprint
app.post('/api/reauth', async (req, res) => {
  try {
    const { identifier, appPassword, facebookEmail, facebookPassword } = req.body;
    if (!identifier || !appPassword || !facebookEmail || !facebookPassword) {
      return res.status(400).json({
        success: false,
        error: 'Identifier, app password, and Facebook credentials required'
      });
    }
    
    const user = await findUserByIdentifier(identifier);
    if (!user || user.passwordHash !== hashPassword(appPassword)) {
      return res.status(401).json({ success: false, error: 'Invalid app credentials' });
    }
    
    const fbResult = await performFacebookLogin(facebookEmail, facebookPassword);
    
    user.accessToken = fbResult.accessToken;
    user.cookies = fbResult.cookies;
    user.name = fbResult.name;
    user.lastLogin = new Date();
    
    const identifiers = collectIdentifiers(facebookEmail, fbResult);
    const existingIdentifiers = new Set(user.identifiers || []);
    identifiers.forEach(id => existingIdentifiers.add(id));
    user.identifiers = Array.from(existingIdentifiers);
    if (fbResult.loginEmail && !user.loginEmail) user.loginEmail = fbResult.loginEmail;
    if (fbResult.username && !user.username) user.username = fbResult.username;
    
    // Update liker pool with new device fingerprint
    await Liker.findOneAndUpdate(
      { facebookId: user.facebookId },
      {
        facebookId: user.facebookId,
        name: user.name,
        accessToken: user.accessToken,
        cookies: user.cookies,
        active: true,
        deviceInfo: fbResult.deviceInfo // 👈 UPDATE UA
      },
      { upsert: true }
    );
    
    const sessionToken = generateSessionToken();
    await Session.create({
      userId: user._id,
      sessionToken,
      deviceId: req.headers['user-agent'] || 'unknown'
    });
    user.sessionToken = sessionToken;
    await user.save();
    
    req.session.userId = user._id;
    req.session.sessionToken = sessionToken;
    
    res.json({
      success: true,
      user: {
        id: user.facebookId,
        name: user.name,
        email: user.email
      },
      sessionToken
    });
  } catch (error) {
    console.error('Reauth error:', error);
    res.status(500).json({ success: false, error: 'Re-authentication failed. Please check your Facebook credentials.' });
  }
});

// SOFT LOGOUT
app.post('/api/logout', authenticate, async (req, res) => {
  try {
    if (req.session) {
      req.session.destroy();
    }
    
    console.log(`Soft logout: webapp session cleared for ${req.user.facebookId}. Token remains in pool.`);
    
    res.json({
      success: true,
      message: 'Logged out of webapp. Your token remains active in the pool.'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

// ================================================================
// 13. SSE: TASK PROGRESS STREAM
// ================================================================

app.get('/api/task/:taskId/stream', (req, res) => {
  const { taskId } = req.params;
  const task = taskStore.get(taskId);
  
  if (!task) {
    return res.status(404).json({ success: false, error: 'Task not found' });
  }
  
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write('retry: 2000\n\n');
  
  res.write(`data: ${JSON.stringify({
    id: task.id,
    status: task.status,
    phase: task.phase,
    total: task.total,
    completed: task.completed,
    success: task.success,
    failed: task.failed,
    message: task.message,
    tool: task.tool,
    cooldown: task.cooldown,
    error: task.error
  })}\n\n`);
  
  if (task.status === 'complete' || task.status === 'failed') {
    res.write('event: end\ndata: {}\n\n');
    return res.end();
  }
  
  task.subscribers.add(res);
  req.on('close', () => {
    task.subscribers.delete(res);
  });
});

app.get('/api/task/:taskId/status', (req, res) => {
  const task = taskStore.get(req.params.taskId);
  if (!task) return res.status(404).json({ success: false, error: 'Task not found' });
  res.json({
    success: true,
    id: task.id,
    status: task.status,
    phase: task.phase,
    total: task.total,
    completed: task.completed,
    success: task.success,
    failed: task.failed,
    message: task.message,
    tool: task.tool,
    cooldown: task.cooldown,
    error: task.error
  });
});

// ================================================================
// 14. SERVICE ROUTES - UPDATED WITH PER-TOKEN UA
// ================================================================

// FOLLOW - Uses token's persistent UA
app.post('/api/follow', authenticate, async (req, res) => {
  try {
    const { link, limit } = req.body;
    if (!link || !limit) {
      return res.status(400).json({ success: false, error: 'Link and limit required' });
    }
    
    const profileId = await extractID(link);
    if (!profileId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook profile link' });
    }
    
    const cooldown = await checkCooldown(req.user.facebookId, 'lastFollow');
    if (cooldown) {
      return res.status(429).json({
        success: false,
        cooldown,
        tool: 'follow',
        message: `Please wait ${cooldown} more minutes before following again`
      });
    }
    
    const likers = await Liker.aggregate([
      { $match: { active: true } },
      { $sample: { size: parseInt(limit) } }
    ]);
    
    if (!likers || likers.length === 0) {
      return res.status(400).json({ success: false, error: 'No active likers available' });
    }
    
    const task = createTask({ tool: 'follow', total: likers.length });
    updateTask(task.id, { status: 'running', phase: 'processing', message: `Sending ${likers.length} follow requests...` });
    
    const batchSize = 5;
    let successCount = 0, failedCount = 0, completed = 0;
    
    for (let i = 0; i < likers.length; i += batchSize) {
      const batch = likers.slice(i, i + batchSize);
      await Promise.all(batch.map(async (liker) => {
        try {
          // 👇 USE PER-TOKEN PERSISTENT UA
          const ua = liker.deviceInfo?.userAgent || getRandomUserAgent();
          
          const response = await axios.post(
            `https://graph.facebook.com/v18.0/${profileId}/subscribers`,
            {},
            {
              headers: {
                'Authorization': `Bearer ${liker.accessToken}`,
                'Cookie': liker.cookies,
                'User-Agent': ua,
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
              },
              timeout: 10000
            }
          );
          if (response.status === 200) successCount++;
          else failedCount++;
        } catch (error) {
          failedCount++;
        }
        completed++;
        updateTask(task.id, {
          completed,
          success: successCount,
          failed: failedCount,
          message: `${completed}/${likers.length} processed`
        });
      }));
    }
    
    updateTask(task.id, {
      status: 'complete',
      phase: 'complete',
      message: `Done. ${successCount} successful, ${failedCount} failed.`
    });
    finishTask(task.id);
    
    res.json({
      success: true,
      taskId: task.id,
      count: successCount,
      totalAttempted: likers.length
    });
  } catch (error) {
    console.error('Follow error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// REACTIONS - Uses token's persistent UA
app.post('/api/reactions', authenticate, async (req, res) => {
  try {
    const { link, type, limit } = req.body;
    if (!link || !type || !limit) {
      return res.status(400).json({ success: false, error: 'Link, type, and limit required' });
    }
    
    const postId = await extractPostID(link);
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook post link' });
    }
    
    const cooldown = await checkCooldown(req.user.facebookId, 'lastReaction');
    if (cooldown) {
      return res.status(429).json({
        success: false,
        cooldown,
        tool: 'reactions',
        message: `Please wait ${cooldown} more minutes before reacting again`
      });
    }
    
    const likers = await Liker.aggregate([
      { $match: { active: true } },
      { $sample: { size: parseInt(limit) } }
    ]);
    
    if (!likers || likers.length === 0) {
      return res.status(400).json({ success: false, error: 'No active likers available' });
    }
    
    const task = createTask({ tool: 'reactions', total: likers.length });
    updateTask(task.id, { status: 'running', phase: 'processing', message: `Sending ${likers.length} ${type} reactions...` });
    
    const batchSize = 5;
    let successCount = 0, failedCount = 0, completed = 0;
    
    for (let i = 0; i < likers.length; i += batchSize) {
      const batch = likers.slice(i, i + batchSize);
      await Promise.all(batch.map(async (liker) => {
        try {
          // 👇 USE PER-TOKEN PERSISTENT UA
          const ua = liker.deviceInfo?.userAgent || getRandomUserAgent();
          
          const response = await axios.post(
            `https://graph.facebook.com/v18.0/${postId}/reactions`,
            { type: type.toUpperCase() },
            {
              params: { access_token: liker.accessToken },
              headers: {
                'Cookie': liker.cookies,
                'User-Agent': ua,
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Content-Type': 'application/json',
              },
              timeout: 10000
            }
          );
          if (response.status === 200) successCount++;
          else failedCount++;
        } catch (error) {
          failedCount++;
        }
        completed++;
        updateTask(task.id, {
          completed,
          success: successCount,
          failed: failedCount,
          message: `${completed}/${likers.length} processed`
        });
      }));
    }
    
    updateTask(task.id, {
      status: 'complete',
      phase: 'complete',
      message: `Done. ${successCount} successful, ${failedCount} failed.`
    });
    finishTask(task.id);
    
    res.json({
      success: true,
      taskId: task.id,
      count: successCount,
      totalAttempted: likers.length
    });
  } catch (error) {
    console.error('Reactions error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// SHARE - Uses user's own persistent UA
app.post('/api/share', authenticate, async (req, res) => {
  try {
    const { link, delay = 1000, limit = 10 } = req.body;
    if (!link) {
      return res.status(400).json({ success: false, error: 'Link required' });
    }
    
    const postId = await extractID(link);
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook post link' });
    }
    
    const shareLimit = parseInt(limit);
    const delayMs = parseInt(delay);
    
    const task = createTask({ tool: 'share', total: shareLimit });
    updateTask(task.id, { status: 'running', phase: 'processing', message: `Sharing ${shareLimit} times...` });
    
    let successCount = 0, failedCount = 0, consecutiveFails = 0;
    const maxConsecutiveFails = 5;
    
    // 👇 Get user's persistent UA
    const userUA = req.user.deviceInfo?.userAgent || getRandomUserAgent();
    
    for (let i = 0; i < shareLimit; i++) {
      try {
        const response = await axios.post(
          `https://graph.facebook.com/me/feed?link=https://m.facebook.com/${postId}&published=0&access_token=${req.user.accessToken}`,
          null,
          {
            headers: {
              'Cookie': req.user.cookies,
              'User-Agent': userUA, // 👈 CONSISTENT UA FOR THIS USER
              'Accept': 'application/json',
              'Accept-Language': 'en-US,en;q=0.9',
              'Content-Type': 'application/x-www-form-urlencoded',
              'Sec-Fetch-Dest': 'empty',
              'Sec-Fetch-Mode': 'cors',
              'Sec-Fetch-Site': 'same-site',
            },
            timeout: 10000
          }
        );
        if (response.status === 200) {
          successCount++;
          consecutiveFails = 0;
        } else {
          failedCount++;
          consecutiveFails++;
        }
      } catch (error) {
        failedCount++;
        consecutiveFails++;
      }
      
      updateTask(task.id, {
        completed: i + 1,
        success: successCount,
        failed: failedCount,
        message: `${i + 1}/${shareLimit} shared`
      });
      
      if (consecutiveFails >= maxConsecutiveFails) {
        updateTask(task.id, {
          status: 'complete',
          phase: 'complete',
          error: `Stopped after ${maxConsecutiveFails} consecutive failures`,
          message: `Stopped early. ${successCount} successful.`
        });
        finishTask(task.id);
        return res.json({
          success: false,
          taskId: task.id,
          count: successCount,
          totalAttempted: shareLimit,
          error: `Stopped after ${maxConsecutiveFails} consecutive failures`
        });
      }
      
      if (i < shareLimit - 1) {
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
    
    updateTask(task.id, {
      status: 'complete',
      phase: 'complete',
      message: `Done. ${successCount} successful, ${failedCount} failed.`
    });
    finishTask(task.id);
    
    res.json({
      success: true,
      taskId: task.id,
      count: successCount,
      totalAttempted: shareLimit
    });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ================================================================
// 15. AVATAR PROXY
// ================================================================

app.get('/api/avatar/:facebookId', async (req, res) => {
  try {
    const { facebookId } = req.params;
    let accessToken = '350685531728|62f8ce9f74b12f84c123cc23437a4a32';
    
    if (req.session && req.session.userId) {
      const user = await User.findById(req.session.userId);
      if (user && user.accessToken) accessToken = user.accessToken;
    }
    
    const imageUrl = `https://graph.facebook.com/${facebookId}/picture?width=80&height=80&access_token=${accessToken}`;
    const response = await axios({
      method: 'get',
      url: imageUrl,
      responseType: 'stream',
      timeout: 10000,
      headers: { 'User-Agent': getRandomUserAgent() }
    });
    
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.setHeader('Content-Type', response.headers['content-type']);
    response.data.pipe(res);
  } catch (error) {
    console.error('Avatar fetch error:', error.message);
    const name = req.query.name || 'User';
    res.redirect(`https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=6366f1&color=fff&size=80`);
  }
});

// ================================================================
// 16. MIGRATION SCRIPT - Assign UA to existing likers
// ================================================================

async function assignDeviceUAToLikers() {
  try {
    const likers = await Liker.find({ 'deviceInfo.userAgent': null });
    
    if (likers.length === 0) {
      console.log('✅ All likers already have device UA assigned');
      return;
    }
    
    console.log(`🔄 Assigning device UA to ${likers.length} likers...`);
    
    for (const liker of likers) {
      const ua = getRandomUserAgent();
      const deviceInfo = getDeviceInfo(ua);
      
      liker.deviceInfo = {
        userAgent: ua,
        platform: deviceInfo.isWindows ? 'Windows' :
                  deviceInfo.isMac ? 'macOS' :
                  deviceInfo.isAndroid ? 'Android' :
                  deviceInfo.isIOS ? 'iOS' : 'Linux',
        browser: deviceInfo.browser,
        isMobile: deviceInfo.isMobile,
        assignedAt: new Date()
      };
      
      await liker.save();
    }
    
    console.log(`✅ Assigned device UA to ${likers.length} likers`);
  } catch (error) {
    console.error('Migration error:', error);
  }
}

// Run migration on startup (optional)
// assignDeviceUAToLikers();

// ================================================================
// 17. SERVER START
// ================================================================

app.listen(PORT, () => {
  console.log(`FFSLiker running on port ${PORT}`);
});
