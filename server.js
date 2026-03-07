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
import { Resend } from 'resend';
import pkg from 'pg';
const { Pool } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SEMAPHORE_API_KEY = process.env.SEMAPHORE_API_KEY;
const SENDER_ID = process.env.SEMAPHORE_SENDER_ID || 'SMSINFO';

//SMS
async function sendSms(to, message) {
  const url = 'https://api.semaphore.co/api/v4/messages';

  const params = new URLSearchParams();
  params.append('apikey', process.env.SEMAPHORE_API_KEY);
  params.append('number', to);
  params.append('message', message);
  params.append('sendername', process.env.SEMAPHORE_SENDER_ID || 'SMSINFO');

  const response = await fetch(url, {
    method: 'POST',
    body: params
  });

  const text = await response.text(); // 👈 read as text first

  try {
    return JSON.parse(text); // try parse if JSON
  } catch {
    console.log("SMS Response (not JSON):", text);
    return text; // return raw text instead of crashing
  }
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

//EMAIL OTP
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendOtpEmail(to, otp) {
  await resend.emails.send({
    from: 'Oscar D\'Great <onboarding@resend.dev>',
    to,
    subject: 'Your OTP Code - Oscar D\'Great',
    html: `
      <div style="font-family: Arial, sans-serif; background:#f4f4f4; padding:40px 0;">
        <div style="max-width:500px; margin:auto; background:white; border-radius:12px; padding:30px; text-align:center; box-shadow:0 8px 25px rgba(0,0,0,0.1);">
          
          <h2 style="color:#ee4d2d; margin-bottom:10px;">Oscar D'Great</h2>
          <p style="color:#777; margin-bottom:25px;">Pet Supplies Trading</p>

          <h3 style="margin-bottom:15px;">Email Verification</h3>

          <p style="color:#555; font-size:14px;">
            Use the OTP below to complete your login.
          </p>

          <div style="
            font-size:28px;
            font-weight:bold;
            letter-spacing:6px;
            margin:20px 0;
            color:#ee4d2d;
          ">
            ${otp}
          </div>

          <p style="font-size:13px; color:#999;">
            This code will expire in 10 minutes.
          </p>

          <hr style="margin:25px 0; border:none; border-top:1px solid #eee;">

          <p style="font-size:12px; color:#aaa;">
            If you did not request this, please ignore this email.
          </p>

        </div>
      </div>
    `
  });
}

//FORGOT PASSWORD
// FORGOT PASSWORD EMAIL
async function sendForgotPasswordEmail(to, otp) {
  await resend.emails.send({
    from: "Oscar D'Great <onboarding@resend.dev>",
    to,
    subject: "Password Reset OTP - Oscar D'Great",
    html: `
      <div style="font-family: Arial, sans-serif; background:#f4f4f4; padding:40px 0;">
        <div style="max-width:500px; margin:auto; background:white; border-radius:12px; padding:30px; text-align:center; box-shadow:0 8px 25px rgba(0,0,0,0.1);">
          
          <h2 style="color:#ee4d2d; margin-bottom:10px;">Oscar D'Great</h2>
          <p style="color:#777; margin-bottom:25px;">Pet Supplies Trading</p>

          <h3 style="margin-bottom:15px;">Password Reset Request</h3>

          <p style="color:#555; font-size:14px;">
            We received a request to reset your password.
            Use the OTP below to proceed with resetting your password.
          </p>

          <div style="
            font-size:28px;
            font-weight:bold;
            letter-spacing:6px;
            margin:20px 0;
            color:#ee4d2d;
          ">
            ${otp}
          </div>

          <p style="font-size:13px; color:#999;">
            This code will expire in 10 minutes.
          </p>

          <hr style="margin:25px 0; border:none; border-top:1px solid #eee;">

          <p style="font-size:12px; color:#aaa;">
            If you did not request a password reset, please ignore this email.
          </p>

        </div>
      </div>
    `
  });
}

async function createNotification({ userId, saleId, status, message }) {
  await db.query(
    `INSERT INTO notifications (user_id, sale_id, status, message, is_read)
     VALUES ($1, $2, $3, $4, false)`,
    [userId, saleId, status, message]
  );
}

//SEND-OTP 
app.post('/send-login-otp', async (req, res) => {
  const { username } = req.body;

  try {
    const result = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: 'Account not found. Please register.'
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      'UPDATE users SET otp_code = $1, otp_expiry = $2 WHERE username = $3',
      [otp, expiry, username]
    );

    await sendOtpEmail(username, otp);

    res.json({ message: 'OTP sent successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// FORGOT PASSWORD - SEND OTP
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const result = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: 'Account not found'
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      'UPDATE users SET otp_code = $1, otp_expiry = $2 WHERE username = $3',
      [otp, expiry, email]
    );

    await sendForgotPasswordEmail(email, otp);

    res.json({ message: 'Password reset OTP sent successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to send reset OTP' });
  }
});

// VERIFY FORGOT PASSWORD OTP
app.post('/verify-forgot-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const result = await db.query(
      'SELECT otp_code, otp_expiry FROM users WHERE username = $1',
      [email]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: 'Account not found' });

    const user = result.rows[0];

    if (user.otp_code !== otp)
      return res.status(400).json({ message: 'Invalid OTP' });

    if (new Date(user.otp_expiry) < new Date())
      return res.status(400).json({ message: 'OTP expired' });

    res.json({ message: 'OTP verified successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Verification failed' });
  }
});

// RESET PASSWORD
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({
      message: 'Password must be at least 6 characters'
    });
  }

  try {
    const hashed = await bcrypt.hash(newPassword, 10);

    await db.query(
      `UPDATE users 
       SET password = $1,
           otp_code = NULL,
           otp_expiry = NULL
       WHERE username = $2`,
      [hashed, email]
    );

    res.json({ message: 'Password reset successful' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Password reset failed' });
  }
});

//login-otp
// LOGIN WITH OTP
app.post('/login-otp', async (req, res) => {
  const { username, otp } = req.body;

  try {
    const result = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Account not found' });
    }

    const user = result.rows[0];

    if (!user.is_verified) {
      return res.status(403).json({
        message: 'Please verify your account first.'
      });
    }

    if (user.status === 'inactive') {
      return res.status(403).json({
        message: 'Your account has been deactivated.'
      });
    }

    if (user.otp_code !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (new Date(user.otp_expiry) < new Date()) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    await db.query(
      'UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE id = $1',
      [user.id]
    );

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        username: user.username
      },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // ✅ FIXED RESPONSE
    res.json({
      token,
      id: user.id,
      fullname: user.fullname,
      username: user.username,
      contact: user.contact,
      role: user.role
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'OTP login failed' });
  }
});

//REGISTER
app.post('/register', async (req, res) => {
  const {
    fullname,
    username,
    password,
    contact,
    role = 'user',
    province,
    municipality,
    barangay,
    street,
    block
  } = req.body;

  try {
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Staff/admin accounts created internally do not need customer OTP flow
    if (role === 'staff' || role === 'admin') {
      await db.query(
        `INSERT INTO users
        (fullname, username, password, role, contact,
         province, municipality, barangay, street, block,
         is_verified, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,'active')`,
        [
          fullname,
          username,
          hashedPassword,
          role,
          contact || null,
          province || null,
          municipality || null,
          barangay || null,
          street || null,
          block || null
        ]
      );

      return res.json({ message: `${role} account created successfully` });
    }

    // Customer registration with OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      `INSERT INTO users
      (fullname, username, password, role, contact,
       province, municipality, barangay, street, block,
       otp_code, otp_expiry, is_verified, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,false,'active')`,
      [
        fullname,
        username,
        hashedPassword,
        role,
        contact || null,
        province || null,
        municipality || null,
        barangay || null,
        street || null,
        block || null,
        otp,
        expiry
      ]
    );

    try {
      await sendOtpEmail(username, otp);
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
    }

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
// LOGIN
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

    if (!user.is_verified) {
      return res.status(403).json({
        message: 'Please verify your account using OTP before logging in.'
      });
    }

    if (user.status === 'inactive') {
      return res.status(403).json({
        message: 'Your account has been deactivated.'
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        username: user.username
      },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // ✅ FIXED RESPONSE
    res.json({
      message: 'Login successful',
      token,
      id: user.id,
      fullname: user.fullname,
      username: user.username,
      contact: user.contact,
      role: user.role
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
      SELECT id, fullname, username, role, contact, status
      FROM users
      ORDER BY id DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.put('/users/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['active', 'inactive'].includes(status)) {
    return res.status(400).json({ message: 'Invalid status' });
  }

  try {
    const result = await db.query(
      `UPDATE users
       SET status = $1
       WHERE id = $2
       RETURNING id, fullname, username, role, contact, status`,
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      message: `User status updated to ${status}`,
      user: result.rows[0],
    });
  } catch (err) {
    console.error('Status update error:', err);
    res.status(500).json({ message: 'Failed to update user status' });
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
      `SELECT id, fullname, username, role, contact, status
       FROM users
       WHERE id = $1`,
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
    await db.query(
      'UPDATE products SET name = $1, category = $2, image = $3 WHERE id = $4',
      [name, category, image || null, id]
    );

    const existingVariantsResult = await db.query(
      'SELECT id FROM product_variants WHERE product_id = $1',
      [id]
    );

    const existingIds = existingVariantsResult.rows.map(v => v.id);
    const sentIds = [];

    if (Array.isArray(variants)) {
      for (const v of variants) {
        const variantName = v.variantName || 'Original';
        const price = parseFloat(v.price) || 0;
        const qty = parseInt(v.qty, 10) || 0;
        const variantImage = v.images?.[0] || null;

        if (v.id) {
          await db.query(
            `UPDATE product_variants 
             SET variant_name = $1, price = $2, quantity = $3, image = $4
             WHERE id = $5`,
            [variantName, price, qty, variantImage, v.id]
          );
          sentIds.push(v.id);
        } else {
          const insertResult = await db.query(
            `INSERT INTO product_variants
             (product_id, variant_name, price, quantity, image)
             VALUES ($1,$2,$3,$4,$5)
             RETURNING id`,
            [id, variantName, price, qty, variantImage]
          );
          sentIds.push(insertResult.rows[0].id);
        }
      }
    }

    const idsToDelete = existingIds.filter(eid => !sentIds.includes(eid));

    if (idsToDelete.length > 0) {
      await db.query(
        `DELETE FROM product_variants WHERE id = ANY($1::int[])`,
        [idsToDelete]
      );
    }

    res.json({ message: 'Product updated successfully' });

  } catch (err) {
    console.error("UPDATE PRODUCT ERROR:", err);
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

    await createNotification({
      userId,
      saleId,
      status: 'processing',
      message: `Order #${saleId} has been placed successfully and is now being processed.`
    });

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
    const saleResult = await db.query(
      'SELECT id, user_id, status FROM sales WHERE id = $1',
      [id]
    );

    if (saleResult.rows.length === 0) {
      return res.status(404).json({ message: 'Sale not found' });
    }

    const sale = saleResult.rows[0];

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

    let message = '';

    if (status === 'processing') {
      message = `Order #${id} is now being prepared.`;
    } else if (status === 'to receive') {
      message = `Order #${id} is ready to receive. Please prepare for pickup or delivery.`;
    } else if (status === 'completed') {
      message = `Order #${id} has been completed. Thank you for ordering!`;
    } else if (status === 'cancelled') {
      message = `Order #${id} was cancelled${reason ? `: ${reason}` : '.'}`;
    } else {
      message = `Order #${id} status changed to ${status}.`;
    }

    await createNotification({
      userId: sale.user_id,
      saleId: sale.id,
      status,
      message
    });

    res.json({ message: 'Status updated successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update status' });
  }
});

// Get notifications for a user
app.get('/notifications/user/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `SELECT id, user_id, sale_id, status, message, is_read, created_at
       FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch notifications' });
  }
});

// Mark one notification as read
app.put('/notifications/:id/read', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      'UPDATE notifications SET is_read = true WHERE id = $1',
      [id]
    );

    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update notification' });
  }
});

// Mark all notifications as read for a user
app.put('/notifications/user/:id/read-all', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      'UPDATE notifications SET is_read = true WHERE user_id = $1',
      [id]
    );

    res.json({ message: 'All notifications marked as read' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update notifications' });
  }
});

// Delete one notification
app.delete('/notifications/:id', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      'DELETE FROM notifications WHERE id = $1',
      [id]
    );

    res.json({ message: 'Notification deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to delete notification' });
  }
});

// Clear all notifications for a user
app.delete('/notifications/user/:id/clear', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      'DELETE FROM notifications WHERE user_id = $1',
      [id]
    );

    res.json({ message: 'All notifications cleared' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to clear notifications' });
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
    if (
      lower.includes("hello") ||
      lower.includes("hi") ||
      lower.includes("home")
    ) {
      reply = `👋 Hi ${userName || "there"}! How can I help you today?`;

    } else if (
      lower.includes("price") ||
      lower.includes("cost") ||
      lower.includes("product") ||
      lower.includes("products")
    ) {
      const result = await db.query(`
        SELECT 
          p.id,
          p.name,
          p.category,
          p.image,
          MIN(pv.price) AS price
        FROM products p
        LEFT JOIN product_variants pv ON pv.product_id = p.id
        GROUP BY p.id, p.name, p.category, p.image
        ORDER BY p.name ASC
      `);

      const products = result.rows;

      if (products.length > 0) {
        reply = {
          type: "products",
          heading: "Available Products",
          items: products.map((p) => ({
            id: p.id,
            name: p.name,
            category: p.category,
            image: p.image || null,
            price: p.price
              ? `₱${Number(p.price).toFixed(2)}`
              : "No price available",
          })),
        };
      } else {
        reply = "⚠️ No products found in the database.";
      }

    } else if (
      lower.includes("track") ||
      lower.includes("order status") ||
      /^\d+$/.test(lower)
    ) {
      const orderMatch = lower.match(/\d+/);
      const orderId = orderMatch ? orderMatch[0] : null;

      if (!orderId) {
        reply = `📦 What is your order number?<br/><small>Example: 10</small>`;
      } else {
        const result = await db.query(
          `
          SELECT id, status, total, created_at, customer_name, contact, payment_method
          FROM sales
          WHERE id = $1
          `,
          [orderId]
        );

        if (result.rows.length === 0) {
          reply = "⚠️ Order not found.";
        } else {
          const order = result.rows[0];

          reply = {
            type: "order_status",
            order: {
              id: order.id,
              status: order.status,
              total: `₱${Number(order.total).toFixed(2)}`,
              created_at: new Date(order.created_at).toLocaleString(),
              customer_name: order.customer_name,
              contact: order.contact,
              payment_method: order.payment_method,
            },
          };
        }
      }
    } else if (lower.includes("payment")) {
      reply = "💳 We accept Cash on Delivery or via GCash.";

    } else if (lower.includes("contact")) {
      reply = "☎️ You can reach us at 0912-345-6789 or support@yourshop.com.";

    } else if (lower.includes("location") || lower.includes("located")) {
      reply = "📍 We are located at Liloan, Cebu.";
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

    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS contact TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS province TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS municipality TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS barangay TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS street TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS block TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_code TEXT`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_expiry TIMESTAMP`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'`);

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

    res.json({ message: 'Database initialized successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to initialize database' });
  }
});

app.get('/reset-users', async (req, res) => {
  try {
    await db.query('DROP TABLE IF EXISTS users CASCADE');
    res.json({ message: 'Users table dropped successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to drop users table' });
  }
});

app.get('/clear-users', async (req, res) => {
  try {
    await db.query('DELETE FROM users');
    res.json({ message: 'All users deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to delete users' });
  }
});

app.get("/set-role/:username/:role", async (req, res) => {
  const { username, role } = req.params;

  const allowedRoles = ["admin", "staff", "user"];

  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  try {
    await db.query(
      "UPDATE users SET role = $1 WHERE username = $2",
      [role, username]
    );

    res.json({ message: `User role updated to ${role}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to update role" });
  }
});

// NEW: Admin - count new orders since a timestamp
app.get("/admin/new-orders-count", async (req, res) => {
  try {
    const since = req.query.since; // ISO string
    // default: if no "since", count today's orders (or last 24h)
    const sinceDate = since ? new Date(since) : new Date(Date.now() - 24 * 60 * 60 * 1000);

    // You can change the status filter depending on your logic:
    // processing = new orders
    const result = await db.query(
      `SELECT COUNT(*)::int AS count
       FROM sales
       WHERE created_at > $1
         AND status = 'processing'`,
      [sinceDate]
    );

    res.json({ count: result.rows[0].count });
  } catch (err) {
    console.error("new-orders-count error:", err);
    res.status(500).json({ message: "Failed to count new orders" });
  }
});

await db.query(`
  CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    sale_id INTEGER REFERENCES sales(id) ON DELETE CASCADE,
    status TEXT,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);