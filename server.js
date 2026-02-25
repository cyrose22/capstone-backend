import express from 'express';
import jwt from 'jsonwebtoken';
// import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';
import pkg from 'pg';
const { Pool } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SEMAPHORE_API_KEY = process.env.SEMAPHORE_API_KEY;
const SENDER_ID = process.env.SEMAPHORE_SENDER_ID || 'SMSINFO';

async function sendSms(to, message) {
  const url = 'https://api.semaphore.co/api/v4/messages';

  const params = new URLSearchParams();
  params.append('apikey', SEMAPHORE_API_KEY);
  params.append('number', to);
  params.append('message', message);
  params.append('sendername', SENDER_ID);

  const response = await fetch(url, {
    method: 'POST',
    body: params
  });

  return response.json();
}

const app = express();
app.use(cors());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Increase payload limit for large JSON (e.g., base64 images)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Ensure "uploads" directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

let qrImagePath = ''; // Stores the latest QR image path

//REGISTER
app.post('/register', async (req, res) => {
  const {
    fullname,
    username,
    password,
    contact,
    role,
    province,
    municipality,
    barangay
  } = req.body;

  try {
    // Check if username already exists
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await db.query(
      `INSERT INTO users 
        (fullname, username, password, role, contact,
        province, municipality, barangay,
        otp_code, otp_expiry, is_verified)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false)`,
      [
        fullname,
        username,
        hashedPassword,
        role,
        contact,
        province,
        municipality,
        barangay,
        otp,
        expiry
      ]
    );

    // Send SMS
    await sendSms(
      contact,
      `Your OTP code is ${otp}. It will expire in 10 minutes.`
    );

    res.json({ message: 'OTP sent successfully' });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Registration failed' });
  }
});

//VERIFY OTP
app.post('/verify-otp', async (req, res) => {
  const { username, otp } = req.body;

  try {
    const result = await db.query(
      'SELECT otp_code, otp_expiry FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ message: 'User not found' });

    const user = result.rows[0];

    if (user.otp_code !== otp)
      return res.status(400).json({ message: 'Invalid OTP' });

    if (new Date(user.otp_expiry) < new Date())
      return res.status(400).json({ message: 'OTP expired' });

    await db.query(
      `UPDATE users 
       SET is_verified = true, otp_code = NULL, otp_expiry = NULL
       WHERE username = $1`,
      [username]
    );

    res.json({ message: 'Account verified successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Verification failed' });
  }
});

//LOGIN
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ message: 'Invalid credentials' });

    const user = result.rows[0];

    if (!user.is_verified)
      return res.status(403).json({
        message: 'Please verify your account using OTP before logging in.'
      });

    if (user.status === 'inactive')
      return res.status(403).json({
        message: 'Your account has been deactivated.'
      });

    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        username: user.username
      },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      message: 'Login successful',
      token
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Login failed' });
  }
});

//USERS
app.get('/users', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, fullname, username, role, contact
      FROM users
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.put('/users/:id/role', async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  try {
    await db.query(
      'UPDATE users SET role = $1 WHERE id = $2',
      [role, id]
    );

    res.json({ message: 'Role updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.delete('/users/:id', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      'DELETE FROM users WHERE id = $1',
      [id]
    );

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.put('/users/:id/contact', async (req, res) => {
  const { id } = req.params;
  const { contact } = req.body;

  if (!contact || contact.trim() === '') {
    return res.status(400).json({ message: 'Contact number is required' });
  }

  try {
    await db.query(
      'UPDATE users SET contact = $1 WHERE id = $2',
      [contact, id]
    );

    res.json({ message: 'Contact updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update contact' });
  }
});

app.get('/users/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      'SELECT id, fullname, username, role, contact FROM users WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});
// Product management
app.post('/products', async (req, res) => {
  const { name, category, image, variants } = req.body;

  if (!name) return res.status(400).json({ message: 'Product name is required' });

  try {
    const productResult = await db.query(
      'INSERT INTO products (name, category, image) VALUES ($1, $2, $3) RETURNING id',
      [name, category, image || null]
    );

    const productId = productResult.rows[0].id;

    if (Array.isArray(variants)) {
      for (const v of variants) {
        await db.query(
          'INSERT INTO product_variants (product_id, variant_name, price, quantity, image) VALUES ($1, $2, $3, $4, $5)',
          [
            productId,
            v.variantName || 'Original',
            parseFloat(v.price) || 0,
            parseInt(v.qty, 10) || 0,
            v.images?.[0] || null
          ]
        );
      }
    }

    res.json({ message: 'Product added', id: productId });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to add product' });
  }
});

app.get('/products', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        p.id AS product_id,
        p.name AS product_name,
        p.category,
        p.image AS product_image,
        v.id AS variant_id,
        v.variant_name,
        v.price,
        v.quantity,
        v.image AS variant_image
      FROM products p
      LEFT JOIN product_variants v ON p.id = v.product_id
    `);

    const rows = result.rows;
    const productsMap = {};

    rows.forEach(row => {
      if (!productsMap[row.product_id]) {
        productsMap[row.product_id] = {
          id: row.product_id,
          name: row.product_name,
          category: row.category,
          image: row.product_image,
          variants: []
        };
      }

      if (row.variant_id) {
        productsMap[row.product_id].variants.push({
          id: row.variant_id,
          variant_name: row.variant_name,
          price: row.price,
          quantity: row.quantity,
          image: row.variant_image
        });
      }
    });

    res.json(Object.values(productsMap));

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch products' });
  }
});

// app.post('/products', async (req, res) => {
//   const { name, category, image, variants } = req.body;

//   if (!name) return res.status(400).json({ message: 'Product name is required' });

//   try {
//     const [result] = await db.promise().query(
//       'INSERT INTO products (name, category, image) VALUES (?, ?, ?)',
//       [name, category, image || null]
//     );
//     const productId = result.insertId;

//     if (Array.isArray(variants)) {
//       for (const v of variants) {
//         await db.promise().query(
//           'INSERT INTO product_variants (product_id, variant_name, price, quantity, image) VALUES (?, ?, ?, ?, ?)',
//           [productId, v.variant_name, v.price, v.quantity, v.image || null]
//         );
//       }
//     }

//     res.json({ message: 'Product added', id: productId });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: 'Failed to add product' });
//   }
// });

app.put('/products/:id', async (req, res) => {
  const { id } = req.params;
  const { name, category, image, variants } = req.body;

  try {
    // 1. Update main product
    await db.promise().query(
      'UPDATE products SET name = ?, category = ?, image = ? WHERE id = ?',
      [name, category, image || null, id]
    );

    // 2. Fetch existing variants
    const [existingVariants] = await db.promise().query(
      'SELECT id FROM product_variants WHERE product_id = ?',
      [id]
    );
    const existingIds = existingVariants.map(v => v.id);

    // 3. Handle variants
    const sentIds = [];
    if (Array.isArray(variants)) {
      for (const v of variants) {
        // Ensure variant_name is not null
        const variantName = v.variantName || 'Original';
        const price = parseFloat(v.price) || 0;
        const qty = parseInt(v.qty, 10) || 0;
        const variantImage = v.images && v.images[0] ? v.images[0] : null;

        if (v.id) {
          // Update existing variant
          await db.promise().query(
            'UPDATE product_variants SET variant_name = ?, price = ?, quantity = ?, image = ? WHERE id = ?',
            [variantName, price, qty, variantImage, v.id]
          );
          sentIds.push(v.id);
        } else {
          // Insert new variant
          const [result] = await db.promise().query(
            'INSERT INTO product_variants (product_id, variant_name, price, quantity, image) VALUES (?, ?, ?, ?, ?)',
            [id, variantName, price, qty, variantImage]
          );
          sentIds.push(result.insertId);
        }
      }
    }

    // 4. Delete variants that were removed in frontend
    const idsToDelete = existingIds.filter(eid => !sentIds.includes(eid));
    if (idsToDelete.length > 0) {
      await db.promise().query(
        `DELETE FROM product_variants WHERE id IN (${idsToDelete.join(',')})`
      );
    }

    res.json({ message: 'Product updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update product' });
  }
});

app.delete('/products/:id', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query('BEGIN');

    await db.query(
      'DELETE FROM product_variants WHERE product_id = $1',
      [id]
    );

    const result = await db.query(
      'DELETE FROM products WHERE id = $1 RETURNING id',
      [id]
    );

    await db.query('COMMIT');

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.json({ message: 'Product deleted successfully' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: 'Failed to delete product' });
  }
});

// Create a sale
app.post('/sales', async (req, res) => {
  const {
    userId,
    items,
    status = 'processing',
    customer_name = '',
    contact = '',
    payment_method,
    receipt_url = ''
  } = req.body;

  try {
    await db.query('BEGIN');

    let total = 0;
    items.forEach(item => total += item.price * item.quantity);

    const saleResult = await db.query(
      `INSERT INTO sales 
      (user_id, total, status, customer_name, contact, payment_method, receipt_url) 
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING id`,
      [userId, total, status, customer_name, contact, payment_method, receipt_url]
    );

    const saleId = saleResult.rows[0].id;

    for (const i of items) {
      await db.query(
        `INSERT INTO sale_items
        (sale_id, product_id, variant_id, quantity, price, variant_name, variant_image)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          saleId,
          i.productId,
          i.variantId || null,
          i.quantity,
          i.price,
          i.variantName || null,
          i.variantImage || null
        ]
      );

      if (i.variantId) {
        await db.query(
          `UPDATE product_variants 
           SET quantity = quantity - $1 
           WHERE id = $2`,
          [i.quantity, i.variantId]
        );
      }
    }

    await db.query('COMMIT');

    res.json({ message: 'Sale completed', saleId });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: 'Error creating sale' });
  }
});

// Get sales (all or by user)
app.get('/sales', async (req, res) => {
  const { userId } = req.query;

  try {
    let query = `
      SELECT id, total, created_at, status, contact,
             payment_method, receipt_url,
             customer_name, cancel_description
      FROM sales
    `;

    const params = [];

    if (userId) {
      query += ' WHERE user_id = $1';
      params.push(userId);
    }

    query += ' ORDER BY created_at DESC';

    const salesResult = await db.query(query, params);
    const sales = salesResult.rows;

    const enrichedSales = await Promise.all(
      sales.map(async sale => {
        const itemsResult = await db.query(`
          SELECT si.quantity, si.price, si.variant_name, si.variant_image,
                 p.name AS product_name, p.image AS product_image,
                 v.id AS variant_id,
                 v.variant_name AS db_variant_name,
                 v.image AS db_variant_image
          FROM sale_items si
          JOIN products p ON si.product_id = p.id
          LEFT JOIN product_variants v ON si.variant_id = v.id
          WHERE si.sale_id = $1
        `, [sale.id]);

        return { ...sale, items: itemsResult.rows };
      })
    );

    res.json(enrichedSales);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch sales' });
  }
});

// Get sales by user ID
app.get('/sales/user/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    const salesResult = await db.query(`
      SELECT 
        s.id, s.total, s.created_at, s.status, s.payment_method,
        s.receipt_url, s.customer_name, s.contact,
        s.cancel_description, s.cancelled_by,
        u.fullname AS cancelled_by_name,
        u.role AS cancelled_by_role
      FROM sales s
      LEFT JOIN users u ON s.cancelled_by = u.id
      WHERE s.user_id = $1
      ORDER BY s.created_at DESC
    `, [userId]);

    const sales = salesResult.rows;

    const enrichedSales = await Promise.all(
      sales.map(async sale => {
        const itemsResult = await db.query(`
          SELECT si.quantity, si.price, si.variant_name, si.variant_image,
                 p.name AS product_name,
                 p.image AS product_image
          FROM sale_items si
          JOIN products p ON si.product_id = p.id
          WHERE si.sale_id = $1
        `, [sale.id]);

        return { ...sale, items: itemsResult.rows };
      })
    );

    res.json(enrichedSales);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch sales' });
  }
});

// Update sale status
app.put('/sales/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status, reason = null, cancelled_by = null } = req.body;

  try {
    if (reason) {
      await db.query(
        `UPDATE sales
         SET status = $1,
             cancel_description = $2,
             cancelled_by = $3
         WHERE id = $4`,
        [status, reason, cancelled_by, id]
      );
    } else {
      await db.query(
        `UPDATE sales
         SET status = $1
         WHERE id = $2`,
        [status, id]
      );
    }

    res.json({ message: 'Status updated successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update status' });
  }
});

// PUT /users/:id/password
app.put('/users/:id/password', async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;

  if (!password || password.trim().length < 6) {
    return res.status(400).json({
      message: 'Password must be at least 6 characters long'
    });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    await db.query(
      'UPDATE users SET password = $1 WHERE id = $2',
      [hashed, id]
    );

    res.json({
      success: true,
      message: 'Password updated successfully'
    });

  } catch (error) {
    console.error('Password update error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueName = `receipt-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/jpg'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPG/PNG images are allowed'), false);
    }
  },
});

// Upload QR code image
app.get('/api/admin/qr-code', (req, res) => {
  const sql = 'SELECT url FROM qr_codes ORDER BY uploaded_at DESC LIMIT 1';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching QR Code:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'QR Code not found' });
    }

    const qrUrl = `https://capstone-backend-kiax.onrender.com${results[0].url}`;
    res.json({ url: qrUrl });
  });
});

// Get QR image
app.get('/admin/get-qr', (req, res) => {
  try {
    const data = fs.readFileSync('qr.json', 'utf-8');
    const parsed = JSON.parse(data);
    res.json({ url: parsed.url });
  } catch (err) {
    res.status(404).json({ message: 'QR code not found' });
  }
});

// Endpoint to upload receipt
app.post('/upload-receipt', (req, res) => {
  upload.single('receipt')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ message: err.message });
    }
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const receiptUrl = `https://capstone-backend-kiax.onrender.com/uploads/${req.file.filename}`;
    res.json({ url: receiptUrl });
  });
});

// Admin QR Upload (saves uploaded QR and updates database)
app.post('/admin/upload-qr', upload.single('qrImage'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

  const qrPath = `/uploads/${req.file.filename}`;

  const sql = 'INSERT INTO qr_codes (url, uploaded_at) VALUES (?, NOW())';
  db.query(sql, [qrPath], (err) => {
    if (err) {
      console.error('Failed to save QR URL to database:', err);
      return res.status(500).json({ message: 'Error saving QR code' });
    }

    res.json({ message: 'QR uploaded successfully', url: `https://capstone-backend-kiax.onrender.com${qrPath}` });
  });
});

// Simple FAQ chatbot
app.post('/chatbot', async (req, res) => {
  const { message, userName } = req.body;
  const lower = message?.toLowerCase() || "";

  let reply = "Sorry, I don’t understand. Can you rephrase?";

  try {

    if (lower.includes("hello") || lower.includes("hi") || lower.includes("home")) {
      reply = `👋 Hi ${userName || "there"}! How can I help you today?`;

    } else if (lower.includes("price") || lower.includes("cost") || lower.includes("products")) {

      const result = await db.query(
        "SELECT name, category FROM products"
      );

      const products = result.rows;

      if (products.length > 0) {
        const productList = products
          .map(p => `🛒 ${p.name} – ${p.category}`)
          .join("\n");

        reply = productList;
      } else {
        reply = "⚠️ No products found in the database.";
      }

    } else if (lower.includes("payment")) {
      reply = "💳 We accept Cash on Delivery or via GCash.";

    } else if (lower.includes("contact")) {
      reply = "☎️ You can reach us at 0912-345-6789 or support@yourshop.com.";

    } else if (lower.includes("location") || lower.includes("located")) {
      reply = "We are located at Liloan, Cebu";
    }

    res.json({ reply });

  } catch (err) {
    console.error("Chatbot error:", err);
    res.status(500).json({ reply: "⚠️ Server error." });
  }
});

// Serve uploaded images
app.use('/uploads', express.static(uploadDir));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

app.get("/make-admin/:username", async (req, res) => {
  const { username } = req.params;

  try {
    await db.query(
      "UPDATE users SET role = 'admin' WHERE username = $1",
      [username]
    );

    res.json({ message: "User promoted to admin successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to promote user" });
  }
});

app.get('/init-db', async (req, res) => {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        fullname TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        contact TEXT,

        province TEXT,
        municipality TEXT,
        barangay TEXT,
        street TEXT,
        block TEXT,

        otp_code TEXT,
        otp_expiry TIMESTAMP,
        is_verified BOOLEAN DEFAULT FALSE,
        status TEXT DEFAULT 'active'
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT,
        image TEXT
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS product_variants (
        id SERIAL PRIMARY KEY,
        product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
        variant_name TEXT,
        price NUMERIC,
        quantity INTEGER,
        image TEXT
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS sales (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        total NUMERIC,
        status TEXT,
        customer_name TEXT,
        contact TEXT,
        payment_method TEXT,
        receipt_url TEXT,
        cancel_description TEXT,
        cancelled_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS sale_items (
        id SERIAL PRIMARY KEY,
        sale_id INTEGER REFERENCES sales(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products(id),
        variant_id INTEGER REFERENCES product_variants(id),
        quantity INTEGER,
        price NUMERIC,
        variant_name TEXT,
        variant_image TEXT
      );
    `);

    res.json({ message: "Database initialized successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to initialize database" });
  }
});