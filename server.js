import express from 'express';
// import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pkg from 'pg';
const { Pool } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Increase payload limit for large JSON (e.g., base64 images)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// const db = mysql.createPool({
//   host: 'localhost',
//   user: 'root',
//   password: '',
//   database: 'capstone_project',
//   decimalNumbers: true,
// });

// const db = mysql.createPool({
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   decimalNumbers: true,
// });
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

// Register
// app.post('/register', async (req, res) => {
//   const { fullname, username, password, contact, role  } = req.body;

//   try {
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const sql = 'INSERT INTO users (fullname, username, password, role, contact) VALUES (?, ?, ?, ?, ?)';
//     db.query(sql, [fullname, username, hashedPassword, role, contact], (err) => {
//       if (err) return res.status(500).json({ message: 'Registration failed or duplicate username' });
//       res.json({ message: 'Registration successful. Awaiting approval.' });
//     });
//   } catch {
//     res.status(500).json({ message: 'Server error during registration' });
//   }
// });
app.post('/register', async (req, res) => {
  const { fullname, username, password, contact, role } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      `INSERT INTO users (fullname, username, password, role, contact)
       VALUES ($1, $2, $3, $4, $5)`,
      [fullname, username, hashedPassword, role, contact]
    );

    res.json({ message: 'Registration successful. Awaiting approval.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Registration failed or duplicate username' });
  }
});

// Login
// app.post('/login', (req, res) => {
//   const { username, password } = req.body;
//   const sql = 'SELECT * FROM users WHERE username = ?';

//   db.query(sql, [username], async (err, result) => {
//     if (err) return res.status(500).json({ message: 'DB error' });
//     if (result.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

//     const user = result[0];
//     const match = await bcrypt.compare(password, user.password);

//     if (!match) return res.status(401).json({ message: 'Invalid credentials' });

//     res.json({
//       message: 'Login successful',
//       role: user.role,
//       username: user.username,
//       fullname: user.fullname,
//       id: user.id,
//       contact: user.contact
//     });
//   });
// });
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    res.json({
      message: 'Login successful',
      role: user.role,
      username: user.username,
      fullname: user.fullname,
      id: user.id,
      contact: user.contact
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
});
// GET all users (including contact)
// inside your async route
// app.get('/users', async (req, res) => {
//   try {
//     const [rows] = await db.promise().query(`
//       SELECT id, fullname, username, role, contact
//       FROM users
//     `);
//     res.json(rows);
//   } catch (err) {
//     console.error('Error fetching users:', err);
//     res.status(500).json({ message: 'Failed to fetch users' });
//   }
// });
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

// app.put('/users/:id/role', (req, res) => {
//   const { id } = req.params;
//   const { role } = req.body;
//   db.query('UPDATE users SET role = ? WHERE id = ?', [role, id], (err) => {
//     if (err) return res.status(500).json({ message: 'Database error' });
//     res.json({ message: 'Role updated successfully' });
//   });
// });
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
// app.delete('/users/:id', (req, res) => {
//   const { id } = req.params;
//   db.query('DELETE FROM users WHERE id = ?', [id], (err) => {
//     if (err) return res.status(500).json({ message: 'Database error' });
//     res.json({ message: 'User deleted successfully' });
//   });
// });
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
// app.put('/users/:id/contact', (req, res) => {
//   const { id } = req.params;
//   const { contact } = req.body;

//   if (!contact || contact.trim() === '') {
//     return res.status(400).json({ message: 'Contact number is required' });
//   }

//   db.query('UPDATE users SET contact = ? WHERE id = ?', [contact, id], (err) => {
//     if (err) return res.status(500).json({ message: 'Failed to update contact' });
//     res.json({ message: 'Contact updated successfully' });
//   });
// });
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
// GET /users/:id - Fetch user details
// app.get('/users/:id', (req, res) => {
//   const { id } = req.params;

//   const sql = 'SELECT id, fullname, username, role, contact FROM users WHERE id = ?';
//   db.query(sql, [id], (err, results) => {
//     if (err) return res.status(500).json({ message: 'Database error' });
//     if (results.length === 0) return res.status(404).json({ message: 'User not found' });

//     res.json(results[0]);
//   });
// });
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
  const { name, category, variants, image } = req.body;

  try {
    // 1️⃣ Insert main product
    const [result] = await db.promise().query(
      'INSERT INTO products (name, category, image) VALUES (?, ?, ?)',
      [name, category, image || null]
    );
    const productId = result.insertId;

    // 2️⃣ Insert variants safely
    if (Array.isArray(variants)) {
      for (const v of variants) {
        const variantName = v.variantName; // frontend key
        const price = v.price;
        const quantity = v.qty; // frontend key
        const variantImage = Array.isArray(v.images) && v.images.length > 0 ? v.images[0] : null;

        if (!variantName || price == null || quantity == null) {
          continue;
        }

        try {
          const [insertVariant] = await db.promise().query(
            'INSERT INTO product_variants (product_id, variant_name, price, quantity, image) VALUES (?, ?, ?, ?, ?)',
            [productId, variantName, price, quantity, variantImage]
          );
        } catch (variantErr) {
          console.error('Failed to insert variant:', variantErr);
        }
      }
    }

    res.json({ message: 'Product added', id: productId });
  } catch (err) {
    console.error('Failed to add product:', err);
    res.status(500).json({ message: 'Failed to add product' });
  }
});

app.get('/products', async (req, res) => {
  try {
    const sql = `
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
    `;

    const [rows] = await db.promise().query(sql);

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
    console.error('Fetch products error:', err);
    res.status(500).json({ message: 'Failed to fetch products' });
  }
});

app.post('/products', async (req, res) => {
  const { name, category, image, variants } = req.body;

  if (!name) return res.status(400).json({ message: 'Product name is required' });

  try {
    const [result] = await db.promise().query(
      'INSERT INTO products (name, category, image) VALUES (?, ?, ?)',
      [name, category, image || null]
    );
    const productId = result.insertId;

    if (Array.isArray(variants)) {
      for (const v of variants) {
        await db.promise().query(
          'INSERT INTO product_variants (product_id, variant_name, price, quantity, image) VALUES (?, ?, ?, ?, ?)',
          [productId, v.variant_name, v.price, v.quantity, v.image || null]
        );
      }
    }

    res.json({ message: 'Product added', id: productId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to add product' });
  }
});

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

  const connection = await db.promise().getConnection();
  try {
    await connection.beginTransaction();

    // Delete variants first
    await connection.query('DELETE FROM product_variants WHERE product_id = ?', [id]);

    // Delete product
    const [result] = await connection.query('DELETE FROM products WHERE id = ?', [id]);

    await connection.commit();
    connection.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    await connection.rollback();
    connection.release();
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
    // Calculate total
    let total = 0;
    items.forEach(item => total += item.price * item.quantity);

    // Insert sale
    const [saleResult] = await db.promise().query(
      'INSERT INTO sales (user_id, total, status, customer_name, contact, payment_method, receipt_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, total, status, customer_name, contact, payment_method, receipt_url]
    );
    const saleId = saleResult.insertId;

    // Insert sale items
    for (const i of items) {
      let variantName = i.variantName || null;
      let variantImage = i.variantImage || null;
      let variantId = i.variantId || null;

      if (!variantId) {
        // Try to get first variant if product has variants
        const [variants] = await db.promise().query(
          'SELECT id, variant_name, image FROM product_variants WHERE product_id = ? ORDER BY id ASC LIMIT 1',
          [i.productId]
        );

        if (variants.length > 0) {
          variantId = variants[0].id;
          variantName = variantName || variants[0].variant_name;
          variantImage = variantImage || (variants[0].image
            ? (variants[0].image.startsWith('http') || variants[0].image.startsWith('data:image/')
                ? variants[0].image
                : `https://capstone-backend-kiax.onrender.com/uploads/${variants[0].image}`)
            : null);
        } else {
          // No variants, fallback to product
          const [rows] = await db.promise().query(
            'SELECT name, image FROM products WHERE id = ?',
            [i.productId]
          );
          if (rows.length > 0) {
            variantName = variantName || rows[0].name;
            variantImage = variantImage || (rows[0].image
              ? (rows[0].image.startsWith('http') || rows[0].image.startsWith('data:image/')
                  ? rows[0].image
                  : `https://capstone-backend-kiax.onrender.com/uploads/${rows[0].image}`)
              : null);
          }
        }
      } else {
        // Variant exists: fetch from variant table if missing
        if (!variantName || !variantImage) {
          const [rows] = await db.promise().query(
            'SELECT variant_name, image FROM product_variants WHERE id = ?',
            [variantId]
          );
          if (rows.length > 0) {
            variantName = variantName || rows[0].variant_name;
            variantImage = variantImage || (rows[0].image
              ? (rows[0].image.startsWith('http') || rows[0].image.startsWith('data:image/')
                  ? rows[0].image
                  : `https://capstone-backend-kiax.onrender.com/uploads/${rows[0].image}`)
              : null);
          }
        }
      }

      // Insert into sale_items
      await db.promise().query(
        `INSERT INTO sale_items 
        (sale_id, product_id, variant_id, quantity, price, variant_name, variant_image) 
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [saleId, i.productId, variantId, i.quantity, i.price, variantName, variantImage]
      );

      // Deduct inventory if variant
      if (variantId) {
        await db.promise().query(
          'UPDATE product_variants SET quantity = quantity - ? WHERE id = ?',
          [i.quantity, variantId]
        );
      }
    }

    res.json({ message: 'Sale completed', saleId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating sale' });
  }
});

// Get sales (all or by user)
app.get('/sales', async (req, res) => {
  const { userId } = req.query;
  try {
    let salesSql = 'SELECT id, total, created_at, status, contact, payment_method, receipt_url, customer_name, cancel_description FROM sales';
    const params = [];
    if (userId) {
      salesSql += ' WHERE user_id = ?';
      params.push(userId);
    }
    salesSql += ' ORDER BY created_at DESC';

    const [sales] = await db.promise().query(salesSql, params);

    const enrichedSales = await Promise.all(
      sales.map(async sale => {
        const [items] = await db.promise().query(`
          SELECT si.quantity, si.price, si.variant_name, si.variant_image,
                p.name AS product_name, p.image AS product_image,
                v.id AS variant_id, v.variant_name AS db_variant_name, v.image AS db_variant_image
          FROM sale_items si
          JOIN products p ON si.product_id = p.id
          LEFT JOIN product_variants v ON si.variant_id = v.id
          WHERE si.sale_id = ?
        `, [sale.id]);

        return { ...sale, items };
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
    const [sales] = await db.promise().query(`
      SELECT 
        s.id, s.total, s.created_at, s.status, s.payment_method,
        s.receipt_url, s.customer_name, s.contact, s.cancel_description,
        s.cancelled_by, u.fullname AS cancelled_by_name, u.role AS cancelled_by_role
      FROM sales s
      LEFT JOIN users u ON s.cancelled_by = u.id
      WHERE s.user_id = ?
      ORDER BY s.created_at DESC
    `, [userId]);

    const enrichedSales = await Promise.all(
      sales.map(async sale => {
        const [items] = await db.promise().query(`
          SELECT si.quantity, si.price, si.variant_name, si.variant_image,
                p.name AS product_name, p.image AS product_image,
                v.id AS variant_id, v.variant_name AS db_variant_name, v.image AS db_variant_image
          FROM sale_items si
          JOIN products p ON si.product_id = p.id
          LEFT JOIN product_variants v ON si.variant_id = v.id
          WHERE si.sale_id = ?
        `, [sale.id]);

        return { ...sale, items };
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
      await db.promise().query(
        'UPDATE sales SET status = ?, cancel_description = ?, cancelled_by = ? WHERE id = ?',
        [status, reason, cancelled_by, id]
      );
    } else {
      await db.promise().query(
        'UPDATE sales SET status = ? WHERE id = ?',
        [status, id]
      );
    }

    if (cancelled_by) {
      const [user] = await db.promise().query(
        'SELECT fullname, role FROM users WHERE id = ?',
        [cancelled_by]
      );
      if (user.length > 0) {
        return res.json({
          message: 'Status updated successfully',
          cancelled_by_name: user[0].fullname,
          cancelled_by_role: user[0].role
        });
      }
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
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query('UPDATE users SET password = ? WHERE id = ?', [hashed, id], (err) => {
      if (err) return res.status(500).json({ message: 'Failed to update password' });
      res.json({ success: true, message: 'Password updated successfully' });
    });
  } catch (error) {
    console.error('Hashing error:', error);
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
app.post('/chatbot', (req, res) => {
  const { message, userName } = req.body; // ✅ frontend should send username too
  const lower = message.toLowerCase();

  let reply = "Sorry, I don’t understand. Can you rephrase?";

  if (lower.includes("hello") || lower.includes("hi") || lower.includes("home")) {
    reply = `👋 Hi ${userName || "there"}! How can I help you today?`;
  } else if (lower.includes("price") || lower.includes("cost") || lower.includes("products")) {
    // ✅ Fetch products from DB
    db.query("SELECT name, category FROM products", (err, results) => {
      if (err) {
        console.error("❌ Query error:", err);
        return res.json({ reply: "⚠️ Error fetching product list." });
      }

      if (results.length > 0) {
        let productList = results
          .map(p => `🛒 ${p.name} – ₱${p.category}`)
          .join("\n");
        return res.json({ reply: productList });
      } else {
        return res.json({ reply: "⚠️ No products found in the database." });
      }
    });
    return; // ⬅️ stop execution here
  } else if (lower.includes("payment")) {
    reply = "💳 We accept Cash on Delivery or via GCash.";
  } else if (lower.includes("contact")) {
    reply = "☎️ You can reach us at 0912-345-6789 or support@yourshop.com.";
  } else if (lower.includes("location") || lower.includes("located")) {
    reply = "We are located at Liloan, Cebu";
  }

  res.json({ reply });
});

// Serve uploaded images
app.use('/uploads', express.static(uploadDir));

// Start server
// app.listen(5000, () => {
//   console.log('🚀 Server running at https://capstone-backend-kiax.onrender.com');
// });
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