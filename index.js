/**
 * Future You Backend Server
 * Handles authentication and profile storage
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
require('dotenv').config();
const Stripe = require('stripe');
const { generateEmbedding, cosineSimilarity } = require('./embeddings');
const sharp = require('sharp');

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'future-you-secret-key-change-in-production';
// In production (Railway), use RAILWAY_VOLUME_MOUNT_PATH for persistent storage
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'futureyou.db');

// Claude API Configuration (key stays server-side only)
const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;

let db = null;

// Initialize database
async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing database or create new one
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Create tables if they don't exist
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      phone TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS profiles (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL,
      future_self_data TEXT NOT NULL,
      long_term_memory TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      session_data TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS reflections (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      session_id TEXT,
      reflection_data TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL,
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      status TEXT NOT NULL DEFAULT 'inactive',
      plan_type TEXT NOT NULL DEFAULT 'paid',
      promo_code_used TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS promo_codes (
      id TEXT PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      discount_percent INTEGER NOT NULL DEFAULT 100,
      max_uses INTEGER NOT NULL DEFAULT -1,
      current_uses INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS memory_nuggets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      content TEXT NOT NULL,
      embedding TEXT NOT NULL,
      session_date TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Add photo columns to profiles if not present
  try {
    db.run('ALTER TABLE profiles ADD COLUMN profile_photo TEXT');
  } catch (e) { /* column already exists */ }
  try {
    db.run('ALTER TABLE profiles ADD COLUMN aged_photo TEXT');
  } catch (e) { /* column already exists */ }

  // Seed default promo code
  const existingPromo = getOne('SELECT id FROM promo_codes WHERE code = ?', ['FUTUREYOU100']);
  if (!existingPromo) {
    run(
      'INSERT INTO promo_codes (id, code, discount_percent, max_uses, current_uses, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [uuidv4(), 'FUTUREYOU100', 100, -1, 0, 1, new Date().toISOString()]
    );
    console.log('Seeded promo code: FUTUREYOU100');
  }

  saveDatabase();
  console.log('Database initialized');
}

// Save database to file
function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Helper to get single row
function getOne(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

// Helper to get multiple rows
function getAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

// Helper to run SQL
function run(sql, params = []) {
  db.run(sql, params);
  saveDatabase();
}

// Middleware
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:8085', 'http://localhost:19006', 'http://localhost:8081'];
app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(helmet());

// Rate limiter for auth endpoints (5 attempts per 15 minutes per IP)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

// General API rate limiter (100 requests per minute per IP)
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', generalLimiter);

// Stripe webhook MUST be before JSON parser (needs raw body for signature verification)
app.post('/api/payment/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const now = new Date().toISOString();

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const customerId = session.customer;
      const subscriptionId = session.subscription;
      const userId = session.metadata?.userId;

      if (userId) {
        run(
          'UPDATE subscriptions SET stripe_subscription_id = ?, status = ?, updated_at = ? WHERE user_id = ?',
          [subscriptionId, 'active', now, userId]
        );
      } else {
        const sub = getOne('SELECT user_id FROM subscriptions WHERE stripe_customer_id = ?', [customerId]);
        if (sub) {
          run(
            'UPDATE subscriptions SET stripe_subscription_id = ?, status = ?, updated_at = ? WHERE user_id = ?',
            [subscriptionId, 'active', now, sub.user_id]
          );
        }
      }
      break;
    }

    case 'customer.subscription.updated': {
      const subscription = event.data.object;
      const mappedStatus = subscription.status === 'canceled' ? 'cancelled' : subscription.status;
      const sub = getOne('SELECT user_id FROM subscriptions WHERE stripe_subscription_id = ?', [subscription.id]);
      if (sub) {
        run('UPDATE subscriptions SET status = ?, updated_at = ? WHERE user_id = ?', [mappedStatus, now, sub.user_id]);
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      const sub = getOne('SELECT user_id FROM subscriptions WHERE stripe_subscription_id = ?', [subscription.id]);
      if (sub) {
        run('UPDATE subscriptions SET status = ?, updated_at = ? WHERE user_id = ?', ['cancelled', now, sub.user_id]);
      }
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const sub = getOne('SELECT user_id FROM subscriptions WHERE stripe_customer_id = ?', [invoice.customer]);
      if (sub) {
        run('UPDATE subscriptions SET status = ?, updated_at = ? WHERE user_id = ?', ['past_due', now, sub.user_id]);
      }
      break;
    }

    default:
      console.log(`Unhandled webhook event: ${event.type}`);
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '10mb' }));

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ============= AI RATE LIMITER =============

const aiRateLimits = new Map();
const AI_RATE_LIMIT = 60;
const AI_RATE_WINDOW_MS = 60 * 1000;

const aiRateLimiter = (req, res, next) => {
  const userId = req.user.userId;
  const now = Date.now();
  const userLimit = aiRateLimits.get(userId);

  if (!userLimit || now - userLimit.windowStart > AI_RATE_WINDOW_MS) {
    aiRateLimits.set(userId, { count: 1, windowStart: now });
    return next();
  }

  if (userLimit.count >= AI_RATE_LIMIT) {
    return res.status(429).json({ error: 'Rate limit exceeded. Please wait before making more requests.' });
  }

  userLimit.count++;
  return next();
};

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of aiRateLimits) {
    if (now - val.windowStart > AI_RATE_WINDOW_MS * 2) aiRateLimits.delete(key);
  }
}, 5 * 60 * 1000);

// ============= CLAUDE API HELPER =============

async function callClaudeAPI({ model, max_tokens, system, messages, temperature }) {
  if (!CLAUDE_API_KEY) {
    throw Object.assign(new Error('CLAUDE_API_KEY not configured on server'), { status: 500 });
  }

  const body = { model, max_tokens, messages };
  if (system) body.system = system;
  if (temperature !== undefined) body.temperature = temperature;

  const response = await fetch(ANTHROPIC_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': CLAUDE_API_KEY,
      'anthropic-version': ANTHROPIC_VERSION,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage;
    try {
      const errorData = JSON.parse(errorText);
      errorMessage = errorData.error?.message || errorData.message || errorText;
    } catch {
      errorMessage = errorText || `HTTP ${response.status}`;
    }
    throw Object.assign(new Error(errorMessage), { status: response.status });
  }

  return response.json();
}

// ============= AI REQUEST VALIDATION =============

const MAX_SYSTEM_PROMPT_LENGTH = 50000;
const MAX_MESSAGE_CONTENT_LENGTH = 10000;
const MAX_MESSAGES_COUNT = 100;

function validateAIRequest(systemPrompt, messages) {
  if (systemPrompt && typeof systemPrompt !== 'string') {
    return 'System prompt must be a string';
  }
  if (systemPrompt && systemPrompt.length > MAX_SYSTEM_PROMPT_LENGTH) {
    return 'System prompt exceeds maximum length';
  }
  if (!Array.isArray(messages)) {
    return 'Messages must be an array';
  }
  if (messages.length > MAX_MESSAGES_COUNT) {
    return 'Too many messages';
  }
  for (const msg of messages) {
    if (!msg.role || !msg.content) return 'Each message must have role and content';
    if (typeof msg.content !== 'string') return 'Message content must be a string';
    if (msg.content.length > MAX_MESSAGE_CONTENT_LENGTH) return 'Message content exceeds maximum length';
    if (!['user', 'assistant'].includes(msg.role)) return 'Invalid message role';
  }
  return null;
}

// ============= AUTH ROUTES =============

// Sign up
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Validate name
    if (name.length < 1 || name.length > 100) {
      return res.status(400).json({ error: 'Name must be between 1 and 100 characters' });
    }

    // Check if user already exists
    const existingUser = getOne('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const userId = uuidv4();
    const now = new Date().toISOString();
    run(
      'INSERT INTO users (id, email, password, name, phone, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, email.toLowerCase(), hashedPassword, name, phone || null, now, now]
    );

    // Generate token (7 day expiry)
    const token = jwt.sign({ userId, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: userId, email: email.toLowerCase(), name, phone }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = getOne('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate token (7 day expiry)
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    // Get profile if exists
    const profile = getOne('SELECT future_self_data FROM profiles WHERE user_id = ?', [user.id]);

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, name: user.name, phone: user.phone },
      hasProfile: !!profile,
      profile: profile ? JSON.parse(profile.future_self_data) : null
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  const user = getOne('SELECT id, email, name, phone FROM users WHERE id = ?', [req.user.userId]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ valid: true, user });
});

// ============= PROFILE ROUTES =============

// Save profile (future self data)
app.post('/api/profile', authenticateToken, (req, res) => {
  try {
    const { futureSelfData, longTermMemory } = req.body;
    const userId = req.user.userId;

    if (!futureSelfData) {
      return res.status(400).json({ error: 'Future self data is required' });
    }

    // Check if profile exists
    const existingProfile = getOne('SELECT id FROM profiles WHERE user_id = ?', [userId]);
    const now = new Date().toISOString();

    if (existingProfile) {
      // Update existing profile
      run(
        'UPDATE profiles SET future_self_data = ?, long_term_memory = ?, updated_at = ? WHERE user_id = ?',
        [JSON.stringify(futureSelfData), longTermMemory ? JSON.stringify(longTermMemory) : null, now, userId]
      );
    } else {
      // Create new profile
      const profileId = uuidv4();
      run(
        'INSERT INTO profiles (id, user_id, future_self_data, long_term_memory, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
        [profileId, userId, JSON.stringify(futureSelfData), longTermMemory ? JSON.stringify(longTermMemory) : null, now, now]
      );
    }

    res.json({ message: 'Profile saved successfully' });
  } catch (error) {
    console.error('Save profile error:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// Get profile
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;

    const profile = getOne('SELECT * FROM profiles WHERE user_id = ?', [userId]);

    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    res.json({
      futureSelfData: JSON.parse(profile.future_self_data),
      longTermMemory: profile.long_term_memory ? JSON.parse(profile.long_term_memory) : null
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// ============= REFLECTIONS ROUTES =============

// Save reflection
app.post('/api/reflections', authenticateToken, (req, res) => {
  try {
    const { reflectionData, sessionId } = req.body;
    const userId = req.user.userId;

    const reflectionId = uuidv4();
    const now = new Date().toISOString();
    run(
      'INSERT INTO reflections (id, user_id, session_id, reflection_data, created_at) VALUES (?, ?, ?, ?, ?)',
      [reflectionId, userId, sessionId || null, JSON.stringify(reflectionData), now]
    );

    res.status(201).json({ message: 'Reflection saved', id: reflectionId });
  } catch (error) {
    console.error('Save reflection error:', error);
    res.status(500).json({ error: 'Failed to save reflection' });
  }
});

// Get reflections
app.get('/api/reflections', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const limit = parseInt(req.query.limit) || 30;

    const reflections = getAll(
      'SELECT * FROM reflections WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
      [userId, limit]
    );

    res.json({
      reflections: reflections.map(r => ({
        id: r.id,
        sessionId: r.session_id,
        createdAt: r.created_at,
        ...JSON.parse(r.reflection_data)
      }))
    });
  } catch (error) {
    console.error('Get reflections error:', error);
    res.status(500).json({ error: 'Failed to get reflections' });
  }
});

// ============= SYNC ROUTE =============

// Sync all user data (for when app loads after login)
app.get('/api/sync', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;

    const user = getOne('SELECT id, email, name, phone FROM users WHERE id = ?', [userId]);
    const profile = getOne('SELECT * FROM profiles WHERE user_id = ?', [userId]);
    const reflections = getAll(
      'SELECT * FROM reflections WHERE user_id = ? ORDER BY created_at DESC LIMIT 30',
      [userId]
    );

    res.json({
      user,
      profile: profile ? {
        futureSelfData: JSON.parse(profile.future_self_data),
        longTermMemory: profile.long_term_memory ? JSON.parse(profile.long_term_memory) : null
      } : null,
      reflections: reflections.map(r => ({
        id: r.id,
        sessionId: r.session_id,
        createdAt: r.created_at,
        ...JSON.parse(r.reflection_data)
      }))
    });
  } catch (error) {
    console.error('Sync error:', error);
    res.status(500).json({ error: 'Failed to sync data' });
  }
});

// ============= PAYMENT ROUTES =============

// Create Stripe Checkout Session
app.post('/api/payment/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userEmail = req.user.email;

    // Check if user already has active access
    const existing = getOne(
      'SELECT * FROM subscriptions WHERE user_id = ? AND (status = ? OR status = ?)',
      [userId, 'active', 'promo']
    );
    if (existing) {
      return res.status(400).json({ error: 'You already have an active subscription' });
    }

    // Create or retrieve Stripe customer
    let customerId;
    const existingSub = getOne('SELECT stripe_customer_id FROM subscriptions WHERE user_id = ?', [userId]);

    if (existingSub && existingSub.stripe_customer_id) {
      customerId = existingSub.stripe_customer_id;
    } else {
      const customer = await stripe.customers.create({
        email: userEmail,
        metadata: { userId },
      });
      customerId = customer.id;
    }

    // Create Checkout Session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL || 'http://localhost:8085'}?payment_success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:8085'}?payment_cancelled=true`,
      metadata: { userId },
    });

    // Upsert subscription record
    const existingRecord = getOne('SELECT id FROM subscriptions WHERE user_id = ?', [userId]);
    const now = new Date().toISOString();
    if (existingRecord) {
      run(
        'UPDATE subscriptions SET stripe_customer_id = ?, status = ?, updated_at = ? WHERE user_id = ?',
        [customerId, 'inactive', now, userId]
      );
    } else {
      run(
        'INSERT INTO subscriptions (id, user_id, stripe_customer_id, status, plan_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [uuidv4(), userId, customerId, 'inactive', 'paid', now, now]
      );
    }

    res.json({ sessionId: session.id, url: session.url });
  } catch (error) {
    console.error('Create checkout session error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Get payment/subscription status
app.get('/api/payment/status', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const subscription = getOne('SELECT * FROM subscriptions WHERE user_id = ?', [userId]);

    if (!subscription) {
      return res.json({ hasAccess: false, status: 'none', planType: null });
    }

    const hasAccess = subscription.status === 'active' || subscription.status === 'promo';
    res.json({
      hasAccess,
      status: subscription.status,
      planType: subscription.plan_type,
      promoCodeUsed: subscription.promo_code_used || null,
    });
  } catch (error) {
    console.error('Payment status error:', error);
    res.status(500).json({ error: 'Failed to check payment status' });
  }
});

// Validate promo code
app.post('/api/promo/validate', authenticateToken, (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.userId;

    if (!code) {
      return res.status(400).json({ error: 'Promo code is required' });
    }

    // Check if user already has active access
    const existingSub = getOne(
      'SELECT * FROM subscriptions WHERE user_id = ? AND (status = ? OR status = ?)',
      [userId, 'active', 'promo']
    );
    if (existingSub) {
      return res.status(400).json({ error: 'You already have an active subscription' });
    }

    // Find promo code (case-insensitive)
    const promo = getOne(
      'SELECT * FROM promo_codes WHERE UPPER(code) = UPPER(?) AND is_active = 1',
      [code.trim()]
    );

    if (!promo) {
      return res.status(404).json({ error: 'Invalid or expired promo code' });
    }

    // Check usage limits (-1 means unlimited)
    if (promo.max_uses !== -1 && promo.current_uses >= promo.max_uses) {
      return res.status(400).json({ error: 'This promo code has reached its usage limit' });
    }

    // Grant access
    const now = new Date().toISOString();
    const existingRecord = getOne('SELECT id FROM subscriptions WHERE user_id = ?', [userId]);

    if (existingRecord) {
      run(
        'UPDATE subscriptions SET status = ?, plan_type = ?, promo_code_used = ?, updated_at = ? WHERE user_id = ?',
        ['promo', 'promo', code.trim().toUpperCase(), now, userId]
      );
    } else {
      run(
        'INSERT INTO subscriptions (id, user_id, status, plan_type, promo_code_used, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [uuidv4(), userId, 'promo', 'promo', code.trim().toUpperCase(), now, now]
      );
    }

    // Increment usage count
    run('UPDATE promo_codes SET current_uses = current_uses + 1 WHERE id = ?', [promo.id]);

    res.json({
      valid: true,
      message: 'Promo code applied! You have full access.',
      hasAccess: true,
    });
  } catch (error) {
    console.error('Promo validation error:', error);
    res.status(500).json({ error: 'Failed to validate promo code' });
  }
});

// ============= MEMORY ROUTES =============

// Store memory nuggets with embeddings
app.post('/api/memory/extract', authenticateToken, async (req, res) => {
  try {
    const { nuggets, sessionDate } = req.body;
    const userId = req.user.userId;

    if (!nuggets || !Array.isArray(nuggets) || nuggets.length === 0) {
      return res.status(400).json({ error: 'Nuggets array is required' });
    }

    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(); // 3 months
    let stored = 0;

    for (const nugget of nuggets) {
      if (!nugget || typeof nugget !== 'string') continue;
      try {
        const embedding = await generateEmbedding(nugget);
        run(
          'INSERT INTO memory_nuggets (id, user_id, content, embedding, session_date, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [uuidv4(), userId, nugget, JSON.stringify(embedding), sessionDate || now.split('T')[0], now, expiresAt]
        );
        stored++;
      } catch (embErr) {
        console.error('Failed to embed nugget:', embErr.message);
      }
    }

    res.json({ stored });
  } catch (error) {
    console.error('Memory extract error:', error);
    res.status(500).json({ error: 'Failed to store memories' });
  }
});

// Retrieve relevant memories via cosine similarity
app.post('/api/memory/retrieve', authenticateToken, async (req, res) => {
  try {
    const { query, limit = 8 } = req.body;
    const userId = req.user.userId;

    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

    // Clean expired nuggets
    const now = new Date().toISOString();
    run('DELETE FROM memory_nuggets WHERE expires_at < ? AND user_id = ?', [now, userId]);

    // Get all user's nuggets
    const nuggets = getAll(
      'SELECT content, embedding FROM memory_nuggets WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    if (nuggets.length === 0) {
      return res.json({ memories: [] });
    }

    // Embed the query
    const queryEmbedding = await generateEmbedding(query);

    // Score each nugget
    const scored = nuggets.map(n => ({
      content: n.content,
      score: cosineSimilarity(queryEmbedding, JSON.parse(n.embedding)),
    }));

    // Sort by similarity, return top N
    scored.sort((a, b) => b.score - a.score);
    const topMemories = scored.slice(0, limit).filter(s => s.score > 0.2).map(s => s.content);

    res.json({ memories: topMemories });
  } catch (error) {
    console.error('Memory retrieve error:', error);
    res.status(500).json({ error: 'Failed to retrieve memories' });
  }
});

// List all memories for user, grouped by date
app.get('/api/memory/all', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;

    // Clean expired nuggets
    const now = new Date().toISOString();
    run('DELETE FROM memory_nuggets WHERE expires_at < ? AND user_id = ?', [now, userId]);

    const nuggets = getAll(
      'SELECT content, session_date, created_at FROM memory_nuggets WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    // Group by session_date
    const grouped = {};
    for (const n of nuggets) {
      const date = n.session_date;
      if (!grouped[date]) grouped[date] = [];
      grouped[date].push({ content: n.content, createdAt: n.created_at });
    }

    // Convert to sorted array
    const days = Object.entries(grouped)
      .map(([date, memories]) => ({ date, memories }))
      .sort((a, b) => b.date.localeCompare(a.date));

    res.json({ days, totalMemories: nuggets.length });
  } catch (error) {
    console.error('Memory list error:', error);
    res.status(500).json({ error: 'Failed to list memories' });
  }
});

// ============= AI PROXY ROUTES =============

// Proxy: send conversation message
app.post('/api/ai/message', authenticateToken, aiRateLimiter, async (req, res) => {
  try {
    const { systemPrompt, messages, model, maxTokens } = req.body;

    const validationError = validateAIRequest(systemPrompt, messages);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const data = await callClaudeAPI({
      model: model || 'claude-sonnet-4-20250514',
      max_tokens: Math.min(maxTokens || 150, 4096),
      system: systemPrompt,
      messages,
    });

    const textContent = data.content?.find(c => c.type === 'text');
    res.json({ response: textContent?.text || '' });
  } catch (error) {
    console.error('AI message error:', error.message);
    res.status(error.status || 500).json({ error: error.message || 'Failed to get AI response' });
  }
});

// Proxy: generate opening message
app.post('/api/ai/opening-message', authenticateToken, aiRateLimiter, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const data = await callClaudeAPI({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 100,
      messages: [{ role: 'user', content: prompt }],
    });

    const textContent = data.content?.find(c => c.type === 'text');
    res.json({ response: textContent?.text || '' });
  } catch (error) {
    console.error('AI opening-message error:', error.message);
    res.status(error.status || 500).json({ error: error.message || 'Failed to generate opening message' });
  }
});

// Proxy: generate reflection
app.post('/api/ai/reflection', authenticateToken, aiRateLimiter, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const data = await callClaudeAPI({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }],
    });

    const textContent = data.content?.find(c => c.type === 'text');
    res.json({ response: textContent?.text || '{}' });
  } catch (error) {
    console.error('AI reflection error:', error.message);
    res.status(error.status || 500).json({ error: error.message || 'Failed to generate reflection' });
  }
});

// Proxy: generate weekly digest
app.post('/api/ai/weekly-digest', authenticateToken, aiRateLimiter, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const data = await callClaudeAPI({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 500,
      messages: [{ role: 'user', content: prompt }],
    });

    const textContent = data.content?.find(c => c.type === 'text');
    res.json({ response: textContent?.text || '{}' });
  } catch (error) {
    console.error('AI weekly-digest error:', error.message);
    res.status(error.status || 500).json({ error: error.message || 'Failed to generate weekly digest' });
  }
});

// Proxy: generate daily challenge
app.post('/api/ai/daily-challenge', authenticateToken, aiRateLimiter, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const data = await callClaudeAPI({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 60,
      messages: [{ role: 'user', content: prompt }],
    });

    const textContent = data.content?.find(c => c.type === 'text');
    res.json({ response: textContent?.text?.trim() || '' });
  } catch (error) {
    console.error('AI daily-challenge error:', error.message);
    res.status(error.status || 500).json({ error: error.message || 'Failed to generate daily challenge' });
  }
});

// Proxy: extract memory nuggets
app.post('/api/ai/memory-nuggets', authenticateToken, aiRateLimiter, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const data = await callClaudeAPI({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 200,
      temperature: 0,
      messages: [{ role: 'user', content: prompt }],
    });

    const textContent = data.content?.find(c => c.type === 'text');
    let nuggets = [];
    try {
      nuggets = JSON.parse(textContent?.text || '[]');
    } catch { /* return empty on parse failure */ }

    res.json({ nuggets: Array.isArray(nuggets) ? nuggets : [] });
  } catch (error) {
    console.error('AI memory-nuggets error:', error.message);
    res.status(error.status || 500).json({ error: error.message || 'Failed to extract memory nuggets' });
  }
});

// Proxy: test AI connection
app.post('/api/ai/test', authenticateToken, async (req, res) => {
  try {
    await callClaudeAPI({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 10,
      messages: [{ role: 'user', content: 'Hi' }],
    });
    res.json({ connected: true });
  } catch (error) {
    res.json({ connected: false, error: error.message });
  }
});

// ============================================================
// PHOTO AGING ENDPOINT (sharp - free, no API key needed)
// ============================================================

app.post('/api/ai/age-photo', authenticateToken, async (req, res) => {
  const { photo, currentAge, targetAge } = req.body;
  const userId = req.user.userId;

  if (!photo || !currentAge || !targetAge) {
    return res.status(400).json({ error: 'photo (base64), currentAge, and targetAge are required' });
  }

  // One-time aging per user — check if already done
  const profile = getOne('SELECT aged_photo FROM profiles WHERE user_id = ?', [userId]);
  if (profile && profile.aged_photo) {
    return res.status(409).json({ error: 'Photo already aged. Upload a custom photo instead.' });
  }

  try {
    const inputBuffer = Buffer.from(photo, 'base64');
    const ageDiff = targetAge - currentAge;

    // Scale the aging effect based on how far into the future
    // More years = stronger effect
    const intensity = Math.min(ageDiff / 30, 1); // 0-1 scale, maxes at 30 years

    // Apply aging transformations with sharp:
    // 1. Warm color shift (golden/amber tone — like aged photographs)
    // 2. Slight desaturation (colors fade with age)
    // 3. Subtle softening (skin texture smoothing)
    // 4. Slight brightness/contrast adjustment
    const agedBuffer = await sharp(inputBuffer)
      .modulate({
        brightness: 1 + (intensity * 0.05),    // Slightly brighter
        saturation: 1 - (intensity * 0.2),     // Reduce saturation 0-20%
        hue: Math.round(intensity * 15),        // Warm shift toward golden
      })
      .gamma(1 + (intensity * 0.15))            // Subtle gamma lift (softer look)
      .sharpen({ sigma: 0.5 + intensity })      // Light sharpening to offset softness
      .jpeg({ quality: 85 })
      .toBuffer();

    const agedBase64 = agedBuffer.toString('base64');

    // Store both photos in the profile
    if (profile) {
      run('UPDATE profiles SET profile_photo = ?, aged_photo = ?, updated_at = ? WHERE user_id = ?',
        [photo.substring(0, 200000), agedBase64.substring(0, 200000), new Date().toISOString(), userId]);
      saveDatabase();
    }

    res.json({ agedPhoto: agedBase64 });
  } catch (error) {
    console.error('Photo aging error:', error.message);
    res.status(500).json({ error: 'Failed to process photo.' });
  }
});

// Get aged photo (for loading on app restart)
app.get('/api/ai/aged-photo', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const profile = getOne('SELECT aged_photo, profile_photo FROM profiles WHERE user_id = ?', [userId]);
  if (!profile || !profile.aged_photo) {
    return res.json({ agedPhoto: null, profilePhoto: null });
  }
  res.json({ agedPhoto: profile.aged_photo, profilePhoto: profile.profile_photo });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Initialize and start server
initDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Future You server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
