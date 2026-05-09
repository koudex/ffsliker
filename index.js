const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const querystring = require('querystring');
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

  // Validate encryption key length
  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length !== 64) {
    console.error('❌ ENCRYPTION_KEY must be 64-character hex string (32 bytes)');
    process.exit(1);
  }
}

validateEnv();

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16;

// Helper function to ensure proper key length
function getValidKey(key) {
  if (key.length === 64 && /^[0-9a-f]+$/i.test(key)) {
    return Buffer.from(key, 'hex');
  }
  return crypto.createHash('sha256').update(key).digest();
}

// Encryption functions
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

// JWT-like token generation for persistent sessions
function generateSessionToken(userId, deviceId) {
  const payload = {
    userId,
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

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Session configuration
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);
app.set('trust proxy', 1);

// Database connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://zishindev:I352MfK5GcFsZDIw@ffsliker.j9iepam.mongodb.net/ffsliker?retryWrites=true&w=majority";

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

// Models 
const UserSchema = new mongoose.Schema({
  userId: { type: String, unique: true },
  name: String,
  accessToken: String,
  cookies: String,
  deviceId: String,
  machineId: String,
  sessionTokens: [String], // Array of active session tokens
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const User = mongoose.model('User', UserSchema);

const Cooldown = mongoose.model('Cooldown', new mongoose.Schema({
  userId: String,
  lastFollow: Date,
  lastReaction: Date
}));

const Liker = mongoose.model('Liker', new mongoose.Schema({
  userId: String,
  name: String,
  accessToken: String,
  cookies: String,
  active: { type: Boolean, default: false }
}));

// Helper functions 
const checkCooldown = async (userId, toolType) => {
  const cooldown = await Cooldown.findOne({ userId });
  const now = new Date();
  const cooldownMinutes = 30;
  
  if (!cooldown) {
    await Cooldown.create({ userId, [toolType]: now });
    return false;
  }

  const lastUsed = new Date(cooldown[toolType]) || new Date(0);
  const diffMinutes = (now - lastUsed) / (1000 * 60);

  if (diffMinutes < cooldownMinutes) {
    return Math.ceil(cooldownMinutes - diffMinutes);
  }

  await Cooldown.updateOne({ userId }, { [toolType]: now });
  return false;
};

// Facebook Post ID Extractor (Supports Profiles/Pages/Groups)
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
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
        }
      }
    );
    return response.data.id || null;
  } catch (error) {
    console.error("Error getting ID:", error.message);
    return null;
  }
}

function generateRandomHex(length) {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    // Check server-side session first
    if (req.session.userId) {
      const user = await User.findOne({ userId: req.session.userId });
      if (user && user.isActive) {
        req.user = user;
        return next();
      }
    }
    
    // Check persistent token from header
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      const payload = verifySessionToken(token);
      
      if (payload && payload.userId) {
        const user = await User.findOne({ 
          userId: payload.userId,
          sessionTokens: token,
          isActive: true
        });
        
        if (user) {
          req.session.userId = user.userId;
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
app.get('/api/session', authenticate, (req, res) => {
  res.json({ 
    success: true, 
    user: {
      id: req.user.userId,
      name: req.user.name,
      token: req.user.accessToken,
      cookies: req.user.cookies
    }
  });
});

// Get all saved accounts for the device
app.post('/api/accounts/list', async (req, res) => {
  try {
    const { deviceToken } = req.body;
    if (!deviceToken) {
      return res.status(400).json({ success: false, error: 'Device token required' });
    }

    const payload = verifySessionToken(deviceToken);
    if (!payload) {
      return res.status(400).json({ success: false, error: 'Invalid device token' });
    }

    const users = await User.find({ 
      isActive: true,
      sessionTokens: { $exists: true, $ne: [] }
    }).select('userId name lastLogin');

    const accounts = users.map(user => ({
      userId: user.userId,
      name: user.name,
      lastLogin: user.lastLogin
    }));

    res.json({ success: true, accounts });
  } catch (error) {
    console.error('List accounts error:', error);
    res.status(500).json({ success: false, error: 'Failed to list accounts' });
  }
});

// Switch to a saved account
app.post('/api/accounts/switch', async (req, res) => {
  try {
    const { userId, sessionToken } = req.body;
    
    if (!userId || !sessionToken) {
      return res.status(400).json({ success: false, error: 'Missing parameters' });
    }

    const payload = verifySessionToken(sessionToken);
    if (!payload || payload.userId !== userId) {
      return res.status(400).json({ success: false, error: 'Invalid session token' });
    }

    const user = await User.findOne({ 
      userId,
      sessionTokens: sessionToken,
      isActive: true
    });

    if (!user) {
      return res.status(404).json({ success: false, error: 'Account not found' });
    }

    req.session.userId = user.userId;
    
    res.json({ 
      success: true,
      user: {
        id: user.userId,
        name: user.name,
        token: user.accessToken,
        cookies: user.cookies,
        sessionToken
      }
    });
  } catch (error) {
    console.error('Switch account error:', error);
    res.status(500).json({ success: false, error: 'Failed to switch account' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Both email and password are required'
      });
    }

    // Check if user already exists with valid session
    const existingUser = await User.findOne({ 
      $or: [
        { email },
        { userId: email }
      ]
    });

    if (existingUser && existingUser.isActive) {
      // Generate new session token
      const sessionToken = generateSessionToken(existingUser.userId, existingUser.deviceId);
      
      // Add token to user's session tokens
      if (!existingUser.sessionTokens.includes(sessionToken)) {
        existingUser.sessionTokens.push(sessionToken);
      }
      existingUser.lastLogin = new Date();
      await existingUser.save();
      
      req.session.userId = existingUser.userId;
      
      return res.json({
        success: true,
        userId: existingUser.userId,
        name: existingUser.name,
        accessToken: existingUser.accessToken,
        cookies: existingUser.cookies,
        sessionToken: encrypt(sessionToken)
      });
    }

    // Generate device info for new login
    const deviceId = uuidv4();
    const adid = generateRandomHex(16);
    const machineId = generateRandomHex(22);

    const apiParams = {
      adid: adid,
      email: email,
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
    };

    const apiUrl = `https://b-api.facebook.com/method/auth.login?${querystring.stringify(apiParams)}`;

    const apiResponse = await axios.get(apiUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'X-FB-Friendly-Name': 'authenticate',
        'X-FB-Connection-Type': 'MOBILE.LTE',
        'X-FB-Connection-Quality': 'EXCELLENT'
      }
    });

    if (!apiResponse.data.session_cookies) {
      throw new Error(apiResponse.data.error_msg || 'Failed to get session cookies');
    }

    const cookieString = apiResponse.data.session_cookies
      .map(cookie => `${cookie.name}=${cookie.value}`)
      .join('; ');
      
    const userName = await axios.get(
      `https://graph.facebook.com/me?fields=name&access_token=${apiResponse.data.access_token}`,
      {
        headers: {
          'Cookie': cookieString,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      }
    );

    const sessionToken = generateSessionToken(apiResponse.data.uid, deviceId);

    // Create or update user
    const user = await User.findOneAndUpdate(
      { userId: apiResponse.data.uid },
      {
        userId: apiResponse.data.uid,
        name: userName.data.name || 'Facebook User',
        accessToken: apiResponse.data.access_token,
        cookies: cookieString,
        deviceId,
        machineId,
        $push: { sessionTokens: sessionToken },
        isActive: true,
        lastLogin: new Date()
      },
      { upsert: true, new: true }
    );

    // Also save as a liker
    await Liker.findOneAndUpdate(
      { userId: apiResponse.data.uid },
      {
        userId: apiResponse.data.uid,
        name: userName.data.name || 'Facebook User',
        accessToken: apiResponse.data.access_token,
        cookies: cookieString,
        active: true
      },
      { upsert: true, new: true }
    );

    // Set session
    req.session.userId = user.userId;

    res.json({
      success: true,
      userId: user.userId,
      name: user.name,
      accessToken: user.accessToken,
      cookies: user.cookies,
      sessionToken: encrypt(sessionToken)
    });

  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    return res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || 
            error.response?.data?.error_msg || 
            error.message ||
            'Login failed. Please check your credentials.'
    });
  }
});

app.post('/api/logout', authenticate, async (req, res) => {
  try {
    // Remove current session token but keep user active
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      const payload = verifySessionToken(token);
      
      if (payload && req.user) {
        await User.updateOne(
          { userId: req.user.userId },
          { $pull: { sessionTokens: token } }
        );
      }
    }
    
    // Clear server session only
    req.session.destroy();
    
    res.json({ success: true, message: 'Logged out from app only' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

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

    const cooldown = await checkCooldown(req.user.userId, 'lastFollow');
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
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        };

        const response = await axios.post(
          `https://graph.facebook.com/v18.0/${profileId}/subscribers`,
          {},
          { headers }
        );

        if (response.status === 200) {
          successCount++;
        }
      } catch (error) {
        console.error(`Follow failed for user ${liker.userId}:`, error.message);
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

    const cooldown = await checkCooldown(req.user.userId, 'lastReaction');
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
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        };

        const response = await axios.post(
          `https://graph.facebook.com/v18.0/${postId}/reactions`,
          { type },
          {
            params: { access_token: liker.accessToken },
            headers
          }
        );

        if (response.status === 200) {
          successCount++;
        }
      } catch (error) {
        console.error(`Reaction failed for user ${liker.userId}:`, error.message);
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
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        };

        const response = await axios.post(
          `https://graph.facebook.com/me/feed?link=https://m.facebook.com/${postId}&published=0&access_token=${req.user.accessToken}`,
          null,
          { headers }
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
      error: `${error.response?.data?.error?.message || error.message}`,
      details: error.message 
    });
  }
});

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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
          }
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
          error: 'Facebook API did not confirm the change',
          details: response.data
        });
      }
    } catch (fbError) {
      console.error('Facebook API error:', fbError.response?.data || fbError.message);
      return res.status(500).json({ 
        success: false,
        error: 'Failed to update profile guard with Facebook',
        details: fbError.response?.data || fbError.message
      });
    }

  } catch (error) {
    console.error('Profile guard error:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});