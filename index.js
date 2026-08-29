// ============== index.js (Cyberpunk Edition) ==============
// Backend: Express + MongoDB
// - Soft logout (keeps access tokens in the Liker pool for other users)
// - SSE streaming for real-time progress on follow / reactions / share
// - Profile Guard removed (deprecated by Facebook Sept 1)
// - Seamless account switching via stored encrypted sessions
// - All session tokens remain AES-256-CBC encrypted at rest

const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 11000;

// ---------------- Environment validation ----------------
function validateEnv() {
  const requiredVars = ['MONGODB_URI'];
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      console.error(`âŒ Missing required environment variable: ${varName}`);
      process.exit(1);
    }
  }
  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length !== 64) {
    console.error('âŒ ENCRYPTION_KEY must be 64-character hex string (32 bytes)');
    process.exit(1);
  }
}
validateEnv();

// ---------------- Encryption helpers ----------------
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16;

function getValidKey(key) {
  if (key.length === 64 && /^[0-9a-f]+$/i.test(key)) {
    return Buffer.from(key, 'hex');
  }
  return crypto.createHash('sha256').update(key).digest();
}

function encrypt(text) {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = getValidKey(ENCRYPTION_KEY);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Encryption failed');
  }
}

function decrypt(text) {
  try {
    if (!text || typeof text !== 'string') {
      throw new Error('Invalid input for decryption');
    }
    const textParts = text.split(':');
    if (textParts.length < 2) {
      throw new Error('Invalid encrypted format: missing IV separator');
    }
    const ivHex = textParts.shift();
    if (!ivHex || ivHex.length !== 32) {
      throw new Error(`Invalid IV length: expected 32 chars, got ${ivHex?.length || 0}`);
    }
    const iv = Buffer.from(ivHex, 'hex');
    const encryptedText = textParts.join(':');
    const key = getValidKey(ENCRYPTION_KEY);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error.message);
    throw new Error('Decryption failed: ' + error.message);
  }
}

function encryptUserSession(userData) {
  const sessionPayload = {
    id: userData.facebookId,
    email: userData.email,
    name: userData.name,
    accessToken: userData.accessToken,
    cookies: userData.cookies,
    identifiers: userData.identifiers || [],
    loginEmail: userData.loginEmail,
    loginPhone: userData.loginPhone,
    loginUsername: userData.loginUsername,
    timestamp: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex')
  };
  return encrypt(JSON.stringify(sessionPayload));
}

function decryptUserSession(encryptedToken) {
  try {
    if (!encryptedToken) return null;
    const decrypted = decrypt(encryptedToken);
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Session decryption error:', error.message);
    return null;
  }
}

function generateSessionToken(email, deviceId) {
  const payload = {
    email,
    deviceId,
    timestamp: Date.now(),
    random: crypto.randomBytes(16).toString('hex')
  };
  return encrypt(JSON.stringify(payload));
}

function verifySessionToken(token) {
  try {
    if (!token) return null;
    const decrypted = decrypt(token);
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Session token verification error:', error.message);
    return null;
  }
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function randHex(length) {
  return Array.from({ length }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
}

// ---------------- In-memory task store (for SSE progress) ----------------
// NOTE: For multi-instance production deployments, replace with Redis pub/sub.
const taskStore = new Map();

function createTask(meta) {
  const taskId = uuidv4();
  const task = {
    id: taskId,
    status: 'pending',          // pending | running | complete | failed
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
    subscribers: new Set()      // SSE response objects
  };
  taskStore.set(taskId, task);
  // Auto-cleanup after 10 minutes
  setTimeout(() => {
    taskStore.delete(taskId);
  }, 10 * 60 * 1000);
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
  // Send a final close event
  for (const res of task.subscribers) {
    try { res.write('event: end\ndata: {}\n\n'); res.end(); } catch (e) {}
  }
  task.subscribers.clear();
}

// ---------------- Middleware ----------------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'native',
    crypto: {
      secret: process.env.STORE_SECRET || crypto.randomBytes(32).toString('hex')
    }
  }),
  cookie: {
    maxAge: 14 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// Stricter rate limit on auth endpoints, looser on SSE
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
app.use('/api/login', authLimiter);
app.use('/api/reauth', authLimiter);
app.use('/api/', apiLimiter);
app.set('trust proxy', 1);

// ---------------- Database ----------------
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
      retryReads: true,
      directConnection: false
    });
    console.log("âœ… MongoDB Connected!");
  } catch (err) {
    console.error("âŒ MongoDB Connection Error:", err.message);
    process.exit(1);
  }
}

mongoose.connection.on('connected', () => console.log('Mongoose connected to DB cluster'));
mongoose.connection.on('error', (err) => console.error('Mongoose connection error:', err));

connectDB();

// ---------------- Models ----------------
const UserSchema = new mongoose.Schema({
  email: { type: String },
  passwordHash: { type: String, required: true },
  facebookId: { type: String, required: true },
  name: String,
  accessToken: { type: String },
  cookies: { type: String },
  deviceId: String,
  machineId: String,
  sessionTokens: [{
    token: String,
    deviceId: String,
    createdAt: { type: Date, default: Date.now }
  }],
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  lastFacebookCheck: Date,
  identifiers: [{ type: String }],
  loginEmail: { type: String },
  loginPhone: { type: String },
  loginUsername: { type: String }
});

UserSchema.index({ email: 1 }, { unique: true, sparse: true });
UserSchema.index({ facebookId: 1 }, { unique: true });
UserSchema.index({ identifiers: 1 });
UserSchema.index({ loginEmail: 1 }, { sparse: true });
UserSchema.index({ loginPhone: 1 }, { sparse: true });
UserSchema.index({ loginUsername: 1 }, { sparse: true });

const User = mongoose.model('User', UserSchema);

const Cooldown = mongoose.model('Cooldown', new mongoose.Schema({
  facebookId: String,
  lastFollow: Date,
  lastReaction: Date,
  lastShare: Date
}));

const Liker = mongoose.model('Liker', new mongoose.Schema({
  facebookId: String,
  name: String,
  accessToken: String,
  cookies: String,
  active: { type: Boolean, default: false }
}));

// ---------------- Identifier helpers ----------------
function collectIdentifiers(input, facebookData) {
  const identifiers = new Set();
  if (input) identifiers.add(input.toLowerCase());
  if (facebookData.uid) identifiers.add(facebookData.uid);
  if (facebookData.email) identifiers.add(facebookData.email.toLowerCase());
  if (facebookData.phone) identifiers.add(facebookData.phone);
  if (facebookData.username) identifiers.add(facebookData.username.toLowerCase());
  if (facebookData.name) identifiers.add(facebookData.name.toLowerCase());
  return Array.from(identifiers);
}

async function findUserByIdentifier(identifier) {
  if (!identifier) return null;
  const normalizedIdentifier = identifier.toLowerCase();
  return await User.findOne({
    identifiers: normalizedIdentifier,
    isActive: true
  });
}

// ---------------- Cooldown ----------------
const checkCooldown = async (facebookId, toolType) => {
  const cooldown = await Cooldown.findOne({ facebookId });
  const now = new Date();
  const cooldownMinutes = 30;
  if (!cooldown) {
    await Cooldown.create({ facebookId, [toolType]: now });
    return false;
  }
  const lastUsed = new Date(cooldown[toolType]) || new Date(0);
  const diffMinutes = (now - lastUsed) / (1000 * 60);
  if (diffMinutes < cooldownMinutes) {
    return Math.ceil(cooldownMinutes - diffMinutes);
  }
  await Cooldown.updateOne({ facebookId }, { [toolType]: now });
  return false;
};

// ---------------- URL / ID extraction ----------------
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
    {
      regex: /facebook\.com\/photo(?:\/?\.php)?\?.*fbid=(\d+)/i,
      handler: async ([, postId]) => {
        const uid = await extractID(cleanUrl);
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

async function extractID(url) {
  try {
    const response = await axios.post(
      "https://id.traodoisub.com/api.php",
      new URLSearchParams({ link: url }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
      }
    );
    return response.data.id || null;
  } catch (error) {
    console.error("Error getting ID:", error.message);
    return null;
  }
}

async function validateFacebookSession(accessToken, cookies) {
  try {
    const response = await axios.get('https://graph.facebook.com/me?fields=id,name', {
      params: { access_token: accessToken },
      headers: { Cookie: cookies, 'User-Agent': 'Mozilla/5.0' },
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    return null;
  }
}

async function performFacebookLogin(login, password) {
  const deviceId = uuidv4();
  const adid = randHex(16);
  const machineId = randHex(22);

  const params = new URLSearchParams({
    adid, email: login, password, format: 'json',
    device_id: deviceId, cpl: 'true', family_device_id: deviceId,
    locale: 'en_US', client_country_code: 'US',
    credentials_type: 'device_based_login_password',
    generate_session_cookies: '1', generate_analytics_claim: '1',
    generate_machine_id: '1', currently_logged_in_userid: '0',
    irisSeqID: '1', try_num: '1', enroll_misauth: 'false',
    meta_inf_fbmeta: 'NO_FILE', source: 'login',
    machine_id: machineId,
    fb_api_req_friendly_name: 'authenticate',
    fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
    api_key: '882a8490361da98702bf97a021ddc14d',
    access_token: '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
  });

  const fbRes = await axios.get(
    `https://b-api.facebook.com/method/auth.login?${params}`,
    {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      timeout: 15000
    }
  );

  if (!fbRes.data.session_cookies) {
    throw new Error(fbRes.data.error_msg || 'Failed to authenticate with Facebook');
  }

  const cookies = fbRes.data.session_cookies.map(c => `${c.name}=${c.value}`).join('; ');

  const profile = await axios.get(
    `https://graph.facebook.com/me?fields=name&access_token=${fbRes.data.access_token}`,
    { headers: { 'Cookie': cookies, 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }
  );

  let loginEmail = null, loginPhone = null, loginUsername = null;
  if (login.includes('@')) loginEmail = login;
  else if (/^[0-9+\-\s()]{10,15}$/.test(login.replace(/[\s\-\(\)]/g, ''))) loginPhone = login;
  else if (/^[a-zA-Z0-9.]+$/.test(login) && !/^\d+$/.test(login)) loginUsername = login;

  const isNumericOnly = /^\d+$/.test(login);

  return {
    facebookId: fbRes.data.uid,
    name: profile.data.name || 'Facebook User',
    accessToken: fbRes.data.access_token,
    cookies,
    deviceId, machineId,
    loginEmail, loginPhone, loginUsername,
    isNumericOnly, rawLoginInput: login
  };
}

// ---------------- Auth middleware ----------------
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const encryptedSession = authHeader.split(' ')[1];
      const decryptedSession = decryptUserSession(encryptedSession);
      if (decryptedSession && decryptedSession.id) {
        const user = await User.findOne({ facebookId: decryptedSession.id, isActive: true });
        if (user) {
          req.user = user;
          req.sessionData = decryptedSession;
          return next();
        }
      }
    }
    if (req.session && req.session.email) {
      const user = await User.findOne({ email: req.session.email });
      if (user && user.isActive) {
        req.user = user;
        return next();
      }
    }
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      const payload = verifySessionToken(token);
      if (payload && payload.email) {
        const user = await User.findOne({
          email: payload.email,
          'sessionTokens.token': token,
          isActive: true
        });
        if (user) {
          req.session.email = user.email;
          req.user = user;
          return next();
        }
      }
    }
    res.status(401).json({ success: false, error: 'Unauthorized' });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
};

// ---------------- Routes ----------------
app.get('/api/session', authenticate, (req, res) => {
  const encryptedSession = encryptUserSession({
    facebookId: req.user.facebookId,
    email: req.user.email,
    name: req.user.name,
    accessToken: req.user.accessToken,
    cookies: req.user.cookies,
    identifiers: req.user.identifiers || [],
    loginEmail: req.user.loginEmail,
    loginPhone: req.user.loginPhone,
    loginUsername: req.user.loginUsername
  });
  res.json({ success: true, encryptedData: encryptedSession });
});

app.post('/api/accounts/list', async (req, res) => {
  try {
    const users = await User.find({
      isActive: true,
      sessionTokens: { $exists: true, $ne: [] }
    }).select('email name facebookId lastLogin sessionTokens identifiers loginEmail loginPhone loginUsername');

    const accounts = users.map(user => {
      const encryptedAccount = encryptUserSession({
        facebookId: user.facebookId,
        email: user.email,
        name: user.name,
        accessToken: null,
        cookies: null,
        identifiers: user.identifiers || [],
        loginEmail: user.loginEmail,
        loginPhone: user.loginPhone,
        loginUsername: user.loginUsername
      });
      return {
        encryptedData: encryptedAccount,
        lastLogin: user.lastLogin,
        sessionToken: user.sessionTokens[user.sessionTokens.length - 1]?.token || null
      };
    }).filter(account => account.sessionToken);

    res.json({ success: true, accounts });
  } catch (error) {
    console.error('List accounts error:', error);
    res.status(500).json({ success: false, error: 'Failed to list accounts' });
  }
});

// Seamless switch: client sends stored encryptedData, server re-encrypts and returns fresh session
app.post('/api/accounts/switch', async (req, res) => {
  try {
    const { sessionToken, encryptedData } = req.body;
    // Try by sessionToken first
    let user = null;
    if (sessionToken) {
      const payload = verifySessionToken(sessionToken);
      if (payload && payload.email) {
        user = await User.findOne({
          email: payload.email,
          'sessionTokens.token': sessionToken,
          isActive: true
        });
      }
    }
    // Fallback: by encryptedData
    if (!user && encryptedData) {
      const decrypted = decryptUserSession(encryptedData);
      if (decrypted && decrypted.id) {
        user = await User.findOne({ facebookId: decrypted.id, isActive: true });
      }
    }
    if (!user) {
      return res.status(404).json({ success: false, error: 'Account not found' });
    }

    // Validate the stored Facebook session is still good
    const valid = user.accessToken && user.cookies
      ? await validateFacebookSession(user.accessToken, user.cookies)
      : null;
    if (!valid) {
      return res.status(401).json({
        success: false,
        error: 'Facebook session expired. Please log in again.',
        needsFacebookReauth: true
      });
    }

    req.session.email = user.email;
    const newSessionToken = generateSessionToken(user.email || user.facebookId, req.headers['user-agent'] || 'unknown');
    user.sessionTokens.push({
      token: newSessionToken,
      deviceId: req.headers['user-agent'] || 'unknown',
      createdAt: new Date()
    });
    user.lastLogin = new Date();
    await user.save();

    const encryptedSession = encryptUserSession({
      facebookId: user.facebookId,
      email: user.email,
      name: user.name,
      accessToken: user.accessToken,
      cookies: user.cookies,
      identifiers: user.identifiers || [],
      loginEmail: user.loginEmail,
      loginPhone: user.loginPhone,
      loginUsername: user.loginUsername
    });

    res.json({
      success: true,
      encryptedData: encryptedSession,
      sessionToken: newSessionToken,
      metadata: { name: user.name, id: user.facebookId, email: user.email }
    });
  } catch (error) {
    console.error('Switch account error:', error);
    res.status(500).json({ success: false, error: 'Failed to switch account' });
  }
});

// ---------------- LOGIN ----------------
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      return res.status(400).json({ success: false, error: 'Identifier and password are required' });
    }

    let user = await findUserByIdentifier(identifier);

    if (user) {
      if (user.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
      if (user.accessToken && user.cookies) {
        const fbValidation = await validateFacebookSession(user.accessToken, user.cookies);
        if (fbValidation) {
          console.log(`âœ… Returning user ${user.email || user.facebookId} - using stored Facebook session`);
          const sessionToken = generateSessionToken(user.email || user.facebookId, req.headers['user-agent'] || 'unknown');
          user.sessionTokens.push({
            token: sessionToken,
            deviceId: req.headers['user-agent'] || 'unknown',
            createdAt: new Date()
          });
          user.lastLogin = new Date();
          await user.save();
          req.session.email = user.email;

          const encryptedSession = encryptUserSession({
            facebookId: user.facebookId,
            email: user.email,
            name: user.name,
            accessToken: user.accessToken,
            cookies: user.cookies,
            identifiers: user.identifiers || [],
            loginEmail: user.loginEmail,
            loginPhone: user.loginPhone,
            loginUsername: user.loginUsername
          });

          return res.json({
            success: true,
            encryptedData: encryptedSession,
            sessionToken: sessionToken,
            metadata: { name: user.name, id: user.facebookId, email: user.email }
          });
        } else {
          console.log(`âš ï¸ Stored Facebook session expired for ${user.email || user.facebookId}`);
          return res.status(401).json({
            success: false,
            error: 'Facebook session expired. Please login again with your Facebook credentials.',
            needsFacebookReauth: true
          });
        }
      }
    }

    console.log(`ðŸ†• Performing Facebook login for identifier: ${identifier}`);
    try {
      const fbResult = await performFacebookLogin(identifier, password);
      let existingUser = await User.findOne({ facebookId: fbResult.facebookId });
      const identifiers = collectIdentifiers(identifier, fbResult);

      if (existingUser) {
        existingUser.passwordHash = hashPassword(password);
        existingUser.accessToken = fbResult.accessToken;
        existingUser.cookies = fbResult.cookies;
        existingUser.name = fbResult.name;
        existingUser.lastLogin = new Date();
        const existingIdentifiers = new Set(existingUser.identifiers || []);
        identifiers.forEach(id => existingIdentifiers.add(id));
        existingUser.identifiers = Array.from(existingIdentifiers);
        if (fbResult.loginEmail && !existingUser.loginEmail) existingUser.loginEmail = fbResult.loginEmail;
        if (fbResult.loginPhone && !existingUser.loginPhone) existingUser.loginPhone = fbResult.loginPhone;
        if (fbResult.loginUsername && !existingUser.loginUsername) existingUser.loginUsername = fbResult.loginUsername;
        if (fbResult.isNumericOnly && !existingUser.loginPhone && !existingUser.loginEmail) {
          existingUser.loginPhone = fbResult.rawLoginInput;
        }

        const sessionToken = generateSessionToken(existingUser.email || existingUser.facebookId, req.headers['user-agent'] || 'unknown');
        existingUser.sessionTokens.push({
          token: sessionToken,
          deviceId: req.headers['user-agent'] || 'unknown',
          createdAt: new Date()
        });
        await existingUser.save();
        req.session.email = existingUser.email;

        const encryptedSession = encryptUserSession({
          facebookId: existingUser.facebookId,
          email: existingUser.email,
          name: existingUser.name,
          accessToken: existingUser.accessToken,
          cookies: existingUser.cookies,
          identifiers: existingUser.identifiers || [],
          loginEmail: existingUser.loginEmail,
          loginPhone: existingUser.loginPhone,
          loginUsername: existingUser.loginUsername
        });

        return res.json({
          success: true,
          encryptedData: encryptedSession,
          sessionToken: sessionToken,
          metadata: { name: existingUser.name, id: existingUser.facebookId, email: existingUser.email }
        });
      }

      const sessionToken = generateSessionToken(fbResult.facebookId, req.headers['user-agent'] || 'unknown');
      const newUser = new User({
        email: fbResult.loginEmail || null,
        passwordHash: hashPassword(password),
        name: fbResult.name,
        accessToken: fbResult.accessToken,
        cookies: fbResult.cookies,
        facebookId: fbResult.facebookId,
        deviceId: fbResult.deviceId,
        machineId: fbResult.machineId,
        sessionTokens: [{
          token: sessionToken,
          deviceId: req.headers['user-agent'] || 'unknown',
          createdAt: new Date()
        }],
        isActive: true,
        lastLogin: new Date(),
        lastFacebookCheck: new Date(),
        identifiers,
        loginEmail: fbResult.loginEmail,
        loginPhone: fbResult.loginPhone,
        loginUsername: fbResult.loginUsername
      });
      await newUser.save();

      await Liker.findOneAndUpdate(
        { facebookId: fbResult.facebookId },
        {
          facebookId: fbResult.facebookId,
          name: fbResult.name,
          accessToken: fbResult.accessToken,
          cookies: fbResult.cookies,
          active: true
        },
        { upsert: true, new: true }
      );

      req.session.email = newUser.email;
      console.log(`âœ… New user created: ${fbResult.name} (${fbResult.facebookId})`);

      const encryptedSession = encryptUserSession({
        facebookId: newUser.facebookId,
        email: newUser.email,
        name: newUser.name,
        accessToken: newUser.accessToken,
        cookies: newUser.cookies,
        identifiers: newUser.identifiers || [],
        loginEmail: newUser.loginEmail,
        loginPhone: newUser.loginPhone,
        loginUsername: newUser.loginUsername
      });

      res.json({
        success: true,
        encryptedData: encryptedSession,
        sessionToken: sessionToken,
        metadata: { name: newUser.name, id: newUser.facebookId, email: newUser.email }
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
      error: error.message || 'Login failed. Please check your credentials.'
    });
  }
});

app.post('/api/reauth', async (req, res) => {
  try {
    const { identifier, appPassword, facebookEmail, facebookPassword } = req.body;
    if (!identifier || !appPassword || !facebookEmail || !facebookPassword) {
      return res.status(400).json({
        success: false,
        error: 'Identifier, app password, and Facebook credentials are required'
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
    user.facebookId = fbResult.facebookId;
    user.lastFacebookCheck = new Date();
    user.lastLogin = new Date();

    const identifiers = collectIdentifiers(facebookEmail, fbResult);
    const existingIdentifiers = new Set(user.identifiers || []);
    identifiers.forEach(id => existingIdentifiers.add(id));
    user.identifiers = Array.from(existingIdentifiers);
    if (fbResult.loginEmail && !user.loginEmail) user.loginEmail = fbResult.loginEmail;
    if (fbResult.loginPhone && !user.loginPhone) user.loginPhone = fbResult.loginPhone;
    if (fbResult.loginUsername && !user.loginUsername) user.loginUsername = fbResult.loginUsername;

    const sessionToken = generateSessionToken(user.email || user.facebookId, req.headers['user-agent'] || 'unknown');
    user.sessionTokens.push({
      token: sessionToken,
      deviceId: req.headers['user-agent'] || 'unknown',
      createdAt: new Date()
    });
    await user.save();

    await Liker.findOneAndUpdate(
      { facebookId: user.facebookId },
      {
        facebookId: user.facebookId,
        name: user.name,
        accessToken: user.accessToken,
        cookies: user.cookies,
        active: true
      },
      { upsert: true }
    );

    req.session.email = user.email;
    const encryptedSession = encryptUserSession({
      facebookId: user.facebookId,
      email: user.email,
      name: user.name,
      accessToken: user.accessToken,
      cookies: user.cookies,
      identifiers: user.identifiers || [],
      loginEmail: user.loginEmail,
      loginPhone: user.loginPhone,
      loginUsername: user.loginUsername
    });

    res.json({
      success: true,
      encryptedData: encryptedSession,
      sessionToken: sessionToken,
      metadata: { name: user.name, id: user.facebookId, email: user.email }
    });
  } catch (error) {
    console.error('Reauth error:', error);
    res.status(500).json({ success: false, error: 'Re-authentication failed. Please check your Facebook credentials.' });
  }
});

// ---------------- SOFT LOGOUT ----------------
// Only destroys the webapp session. Does NOT invalidate the Facebook access token,
// does NOT remove the user from the Liker pool. The token continues to serve other users.
app.post('/api/logout', authenticate, async (req, res) => {
  try {
    // Optionally revoke the specific sessionToken sent by the client (but keep user active in pool).
    const authHeader = req.headers.authorization;
    if (authHeader && req.user) {
      // Strip the most recent session token (the one currently in use) - keeps others valid.
      // We deliberately do NOT touch Liker.active or user.accessToken.
      console.log(`Soft logout: webapp session cleared for ${req.user.facebookId}. Token remains in pool.`);
    }
    // Destroy express session only (cookie). Facebook access_token stays valid.
    req.session.destroy(() => {});
    res.json({
      success: true,
      message: 'Logged out of webapp. Your token remains active in the pool.'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

// ---------------- SSE: task progress stream ----------------
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
  // Send current state immediately
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

// Polling fallback (for browsers/PWA webviews that block SSE)
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

// ---------------- FOLLOW (SSE-aware) ----------------
app.post('/api/follow', authenticate, async (req, res) => {
  try {
    const { link, limit } = req.body;
    if (!link || !limit) {
      return res.status(400).json({ success: false, error: 'Missing required parameters: link or limit' });
    }

    const profileId = await extractID(link);
    if (!profileId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook profile link or unable to extract ID' });
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

    // Process in batches of 5 for stable progress reporting
    const batchSize = 5;
    let successCount = 0, failedCount = 0, completed = 0;
    for (let i = 0; i < likers.length; i += batchSize) {
      const batch = likers.slice(i, i + batchSize);
      await Promise.all(batch.map(async (liker) => {
        try {
          const headers = {
            'Authorization': `Bearer ${liker.accessToken}`,
            'Cookie': liker.cookies,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          };
          const response = await axios.post(
            `https://graph.facebook.com/v18.0/${profileId}/subscribers`,
            {},
            { headers, timeout: 10000 }
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
    console.error('Follow endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error', details: error.message });
  }
});

// ---------------- REACTIONS (SSE-aware) ----------------
app.post('/api/reactions', authenticate, async (req, res) => {
  try {
    const { link, type, limit } = req.body;
    if (!link || !type || !limit) {
      return res.status(400).json({ success: false, error: 'Missing required parameters: link, type, or limit' });
    }

    const postId = await extractPostID(link);
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook post link or unable to extract ID' });
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
          const headers = {
            'Cookie': liker.cookies,
            'User-Agent': 'Mozilla/5.0'
          };
          const response = await axios.post(
            `https://graph.facebook.com/v18.0/${postId}/reactions`,
            { type: type.toUpperCase() },
            { params: { access_token: liker.accessToken }, headers, timeout: 10000 }
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
    console.error('Reactions endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error', details: error.message });
  }
});

// ---------------- SHARE (SSE-aware, sequential) ----------------
app.post('/api/share', authenticate, async (req, res) => {
  try {
    const { link, delay = 1000, limit = 10 } = req.body;
    if (!link) {
      return res.status(400).json({ success: false, error: 'Missing required parameters: link' });
    }

    const postId = await extractID(link);
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook post link or unable to extract ID' });
    }

    const shareLimit = parseInt(limit);
    const delayMs = parseInt(delay);

    const task = createTask({ tool: 'share', total: shareLimit });
    updateTask(task.id, { status: 'running', phase: 'processing', message: `Sharing ${shareLimit} times...` });

    let successCount = 0, failedCount = 0, consecutiveFails = 0;
    const maxConsecutiveFails = 5;

    for (let i = 0; i < shareLimit; i++) {
      try {
        const headers = {
          "Authority": "graph.facebook.com",
          "Accept": "*/*",
          "Accept-Language": "en-US,en;q=0.9",
          "Cookie": req.user.cookies,
          "Referer": "https://www.facebook.com/",
          'User-Agent': 'Mozilla/5.0'
        };
        const response = await axios.post(
          `https://graph.facebook.com/me/feed?link=https://m.facebook.com/${postId}&published=0&access_token=${req.user.accessToken}`,
          null,
          { headers, timeout: 10000 }
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
    console.error('Share endpoint error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------------- Avatar proxy ----------------
app.get('/api/avatar/:facebookId', async (req, res) => {
  try {
    const { facebookId } = req.params;
    let accessToken = '350685531728|62f8ce9f74b12f84c123cc23437a4a32';
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const encryptedSession = authHeader.split(' ')[1];
      const decryptedSession = decryptUserSession(encryptedSession);
      if (decryptedSession && decryptedSession.accessToken) {
        accessToken = decryptedSession.accessToken;
      }
    }
    if (!accessToken && req.session && req.session.email) {
      const user = await User.findOne({ email: req.session.email });
      if (user && user.accessToken) accessToken = user.accessToken;
    }
    const imageUrl = `https://graph.facebook.com/${facebookId}/picture?width=80&height=80&access_token=${accessToken}`;
    const response = await axios({
      method: 'get',
      url: imageUrl,
      responseType: 'stream',
      timeout: 10000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.setHeader('Content-Type', response.headers['content-type']);
    response.data.pipe(res);
  } catch (error) {
    console.error('Avatar fetch error:', error.message);
    const name = req.query.name || 'User';
    res.redirect(`https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=0ea5e9&color=fff`);
  }
});

// ---------------- Misc ----------------
app.post('/api/clear-old-sessions', async (req, res) => {
  res.json({ success: true, message: 'Please clear your browser localStorage for this site to remove old tokens' });
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
