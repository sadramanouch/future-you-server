/**
 * Future You Backend Server
 * Handles authentication and profile storage
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
require('dotenv').config();
const Stripe = require('stripe');
const { generateEmbedding, cosineSimilarity } = require('./embeddings');

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'future-you-secret-key-change-in-production';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'futureyou.db');

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

// ============= AUTH ROUTES =============

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Check if user already exists
    const existingUser = getOne('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userId = uuidv4();
    const now = new Date().toISOString();
    run(
      'INSERT INTO users (id, email, password, name, phone, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, email.toLowerCase(), hashedPassword, name, phone || null, now, now]
    );

    // Generate token
    const token = jwt.sign({ userId, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });

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
app.post('/api/auth/login', async (req, res) => {
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

    // Generate token
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Initialize and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Future You server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
