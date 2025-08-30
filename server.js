const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

let cloudinary, multer, upload;
try {
  cloudinary = require('cloudinary').v2;
  multer = require('multer');
} catch (error) {
  console.log('⚠️  Cloudinary/Multer not installed yet - file upload disabled');
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname)); // Serve static files from root

// PostgreSQL connection pools
// Landing page database (existing)
const mainPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
    } : false
});

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ✅ Configure Cloudinary only if available
if (cloudinary && process.env.CLOUDINARY_CLOUD_NAME) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
  
  // Configure multer for file uploads
  const storage = multer.memoryStorage();
  upload = multer({
    storage: storage,
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed!'), false);
      }
    }
  });
} else {
  console.log('⚠️  Cloudinary not configured - using fallback upload handler');
  // Create a dummy upload middleware for now
  upload = {
    single: (fieldName) => (req, res, next) => {
      console.log('⚠️  File upload attempted but Cloudinary not configured');
      next();
    }
  };
}

// Helper function to upload to Cloudinary (only if configured)
const uploadToCloudinary = (buffer, originalName) => {
  if (!cloudinary) {
    return Promise.reject(new Error('Cloudinary not configured'));
  }
  
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'feedfast-attachments',
        resource_type: 'image',
        public_id: `${Date.now()}-${originalName.split('.')[0]}`,
        transformation: [
          { quality: 'auto' },
          { fetch_format: 'auto' }
        ]
      },
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result);
        }
      }
    );
    uploadStream.end(buffer);
  });
};

// ✅ Enhanced feedback endpoint with better error handling
app.post('/api/feedback', upload.single('attachment'), async (req, res) => {
  try {
    console.log('📝 Feedback submission received');
    const { client_name, branch_id, cust_name, cust_email, cust_phone, type, title, description } = req.body;
    
    // Validation - make sure these fields are required
    if (!client_name || !cust_name || !type || !title || !description) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields' 
      });
    }

    // Find client by name
    const clientQuery = `
      SELECT client_id, client_name, status 
      FROM clients 
      WHERE LOWER(REPLACE(client_name, ' ', '')) = LOWER(REPLACE($1, ' ', '')) 
      AND status = true
    `;
    const clientResult = await users.query(clientQuery, [client_name]);
    
    if (clientResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Client not found or inactive' 
      });
    }

    const client = clientResult.rows[0];
    let attachmentUrl = null;

    // Handle file upload if attachment exists and Cloudinary is configured
    if (req.file && cloudinary && process.env.CLOUDINARY_CLOUD_NAME) {
      try {
        console.log('🔄 Processing file upload:', req.file.originalname);
        const uploadResult = await uploadToCloudinary(req.file.buffer, req.file.originalname);
        attachmentUrl = uploadResult.secure_url;
        console.log('✅ File uploaded successfully:', attachmentUrl);
      } catch (uploadError) {
        console.error('❌ File upload failed:', uploadError);
        // Continue without attachment rather than failing completely
        console.log('⚠️ Continuing without file attachment...');
      }
    } else if (req.file && !cloudinary) {
      console.log('⚠️ File uploaded but Cloudinary not configured - skipping file storage');
    }

    // Create ticket
    const ticketQuery = `
      INSERT INTO tickets (
        client_id, branch_id, cust_name, cust_email, cust_phone, 
        type, title, description, attachment, status, submitted_at
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', NOW())
      RETURNING ticket_id
    `;

    const ticketValues = [
      client.client_id,
      branch_id || null,
      cust_name,
      cust_email || null,
      cust_phone || null,
      type,
      title,
      description,
      attachmentUrl
    ];

    const ticketResult = await users.query(ticketQuery, ticketValues);
    const ticketId = ticketResult.rows[0].ticket_id;

    // Update client's total_tickets counter
    await users.query(
      'UPDATE clients SET total_tickets = total_tickets + 1, updated_at = NOW() WHERE client_id = $1',
      [client.client_id]
    );

    console.log(`✅ Ticket created successfully: #${ticketId}`);

    res.json({
      success: true,
      message: 'Feedback submitted successfully!',
      ticket_id: ticketId,
      attachment_url: attachmentUrl
    });

  } catch (error) {
    console.error('❌ Feedback submission error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to submit feedback' 
    });
  }
});


// Add error handling middleware for multer errors
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large. Maximum size is 5MB.'
      });
    }
  } else if (error.message === 'Only image files are allowed!') {
    return res.status(400).json({
      success: false,
      error: 'Only image files are allowed.'
    });
  }
  next(error);
});

// Admin database (new)
const users = new Pool({
    ionString: process.env.ADMIN_DATABASE_URL, // You'll need to add this env variable
    ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
    } : false
});

// Test database ions
async function testions() {
    try {
        // Test main database
        const mainClient = await mainPool.();
        console.log('✅ Main database ed successfully');
        mainClient.release();
        
        // Test admin database
        const adminClient = await users.();
        console.log('✅ Admin database ed successfully');
        adminClient.release();
    } catch (error) {
        console.error('❌ Database ion failed:', error.message);
    }
}

// Initialize main database table
async function initDatabase() {
    try {
        await mainPool.query(`
            CREATE TABLE IF NOT EXISTS insightx_emails (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(50) DEFAULT 'landing_page'
            )
        `);
        console.log('✅ Main database table initialized successfully');
    } catch (error) {
        console.error('❌ Error initializing main database:', error);
    }
}

// Email validation function
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// JWT Middleware for protecting backoffice routes
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }
        req.users = user;
        next();
    });
}

// =============================================================================
// EXISTING LANDING PAGE ROUTES (Keep these exactly as they were)
// =============================================================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API endpoint for InsightX email submission
app.post('/api/submit-email', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        const query = 'INSERT INTO insightx_emails (email) VALUES ($1) RETURNING id, created_at';
        const result = await mainPool.query(query, [email.toLowerCase().trim()]);

        console.log(`📧 New email subscription: ${email}`);
        
        res.json({
            success: true,
            message: 'Email successfully submitted',
            data: {
                id: result.rows[0].id,
                email: email,
                created_at: result.rows[0].created_at
            }
        });

    } catch (error) {
        console.error('❌ Error submitting email:', error);
        
        if (error.code === '23505') {
            return res.status(409).json({
                success: false,
                message: 'This email is already registered for early access'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// API endpoint for email signup (backward compatibility)
app.post('/api/signup', (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({
            success: false,
            message: 'Email is required'
        });
    }
    
    if (!isValidEmail(email)) {
        return res.status(400).json({
            success: false,
            message: 'Please provide a valid email address'
        });
    }
    
    console.log('📝 New signup:', email);
    
    res.json({
        success: true,
        message: 'Thank you for signing up! We\'ll be in touch soon.'
    });
});

// API endpoint for contact form
app.post('/api/contact', (req, res) => {
    const { name, email, message } = req.body;
    
    if (!name || !email || !message) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }
    
    console.log('💬 New contact form submission:', { name, email, message });
    
    res.json({
        success: true,
        message: 'Thank you for your message! We\'ll get back to you soon.'
    });
});

// API endpoint to get all emails (for admin purposes)
app.get('/api/emails', async (req, res) => {
    try {
        const result = await mainPool.query(
            'SELECT id, email, created_at FROM insightx_emails ORDER BY created_at DESC'
        );
        
        res.json({
            success: true,
            count: result.rows.length,
            emails: result.rows
        });
    } catch (error) {
        console.error('❌ Error fetching emails:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// API endpoint to get email statistics
app.get('/api/stats', async (req, res) => {
    try {
        const totalResult = await mainPool.query('SELECT COUNT(*) as total FROM insightx_emails');
        const todayResult = await mainPool.query(
            'SELECT COUNT(*) as today FROM insightx_emails WHERE DATE(created_at) = CURRENT_DATE'
        );
        const weekResult = await mainPool.query(
            'SELECT COUNT(*) as week FROM insightx_emails WHERE created_at >= CURRENT_DATE - INTERVAL \'7 days\''
        );

        res.json({
            success: true,
            stats: {
                total: parseInt(totalResult.rows[0].total),
                today: parseInt(todayResult.rows[0].today),
                thisWeek: parseInt(weekResult.rows[0].week)
            }
        });
    } catch (error) {
        console.error('❌ Error fetching stats:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// =============================================================================
// NEW BACKOFFICE ROUTES
// =============================================================================

// Serve backoffice login page
app.get('/backoffice', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'backoffice-login.html'));
});

// Backoffice login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        // Find user in admin database
        const userQuery = await users.query(
            'SELECT * FROM adminbo WHERE email = $1',
            [email]
        );
        
        if (userQuery.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const user = userQuery.rows[0];
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            {
                userId: user.user_id,
                email: user.email,
                name: user.name
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log(`🔐 Admin login: ${email}`);
        
        res.json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                id: user.user_id,
                name: user.name,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// =============================================================================
// CLIENT AUTH ROUTES (ADD THESE TO YOUR SERVER.JS)
// =============================================================================

// Serve client login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'client-login.html'));
});

// Client login endpoint (reads from users table) - WITH DETAILED DEBUGGING
app.post('/api/auth/client-login', async (req, res) => {
    console.log('🔍 CLIENT LOGIN DEBUG - Request started');
    console.log('Request body:', req.body);
    console.log('Request headers:', req.headers);
    
    try {
        const { email, password } = req.body;
        console.log('📧 Extracted credentials:', { email: email, passwordLength: password?.length });
        
        if (!email || !password) {
            console.log('❌ Missing credentials');
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        console.log('🔍 About to query database...');
        console.log('Database pool status:', { 
            totalCount: users.totalCount,
            idleCount: users.idleCount,
            waitingCount: users.waitingCount 
        });
        
        // Test database ion first
        try {
            await users.query('SELECT 1 as test');
            console.log('✅ Database ion test passed');
        } catch (dbTestError) {
            console.error('❌ Database ion test failed:', dbTestError);
            throw new Error('Database connection failed');
        }
        
        // Find user in users table (client users)
        console.log('🔍 Executing user query...');
        const userQuery = await users.query(
            `SELECT 
                u.user_id, 
                u.client_id, 
                u.branch_id,
                u.user_name, 
                u.email, 
                u.password, 
                u.status, 
                u.role,
                c.client_name,
                c.status as client_status
            FROM users u
            JOIN clients c ON u.client_id = c.client_id
            WHERE u.email = $1`,
            [email]
        );
        
        console.log('📊 Query result:', {
            rowCount: userQuery.rows.length,
            firstRow: userQuery.rows[0] ? {
                user_id: userQuery.rows[0].user_id,
                email: userQuery.rows[0].email,
                status: userQuery.rows[0].status,
                client_status: userQuery.rows[0].client_status,
                role: userQuery.rows[0].role,
                client_name: userQuery.rows[0].client_name
            } : 'No rows returned'
        });
        
        if (userQuery.rows.length === 0) {
            console.log('❌ User not found with email:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const user = userQuery.rows[0];
        console.log('👤 User found:', user.email, 'Role:', user.role);
        
        // Check if user is active
        if (!user.status) {
            console.log('❌ User account is inactive:', user.email);
            return res.status(401).json({
                success: false,
                message: 'Account is inactive. Please contact administrator.'
            });
        }
        
        // Check if client is active
        if (!user.client_status) {
            console.log('❌ Client account is inactive:', user.client_name);
            return res.status(401).json({
                success: false,
                message: 'Client account is inactive. Please contact support.'
            });
        }
        
        console.log('🔐 Verifying password...');
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('🔐 Password verification result:', isValidPassword);
        
        if (!isValidPassword) {
            console.log('❌ Invalid password for user:', user.email);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        console.log('🎫 Generating JWT token...');
        // Generate JWT token with client info
        const token = jwt.sign(
            {
                userId: user.user_id,
                email: user.email,
                name: user.user_name,
                clientId: user.client_id,
                clientName: user.client_name,
                branchId: user.branch_id,
                role: user.role,
                type: 'client' // Important: distinguish from admin tokens
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log('🔄 Updating last_login timestamp...');
        // Update last_login timestamp
        await users.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1',
            [user.user_id]
        );
        
        console.log(`✅ Client login successful: ${email} (Client: ${user.client_name})`);
        
        const responseData = {
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                id: user.user_id,
                name: user.user_name,
                email: user.email,
                clientId: user.client_id,
                clientName: user.client_name,
                branchId: user.branch_id,
                role: user.role,
                type: 'client'
            }
        };
        
        console.log('📤 Sending response:', {
            success: responseData.success,
            message: responseData.message,
            user: responseData.user,
            tokenLength: responseData.token.length
        });
        
        res.json(responseData);
        
    } catch (error) {
        console.error('💥 CLIENT LOGIN ERROR - Full error details:');
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        console.error('Error code:', error.code);
        console.error('Error name:', error.name);
        
        // Check if it's a database error
        if (error.code) {
            console.error('🔍 Database error details:');
            console.error('- Code:', error.code);
            console.error('- Detail:', error.detail);
            console.error('- Hint:', error.hint);
            console.error('- Position:', error.position);
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error',
            debug: process.env.NODE_ENV === 'development' ? {
                error: error.message,
                stack: error.stack
            } : undefined
        });
    }
});

// Add this test endpoint to verify your database structure
app.get('/api/debug/test-db', async (req, res) => {
    try {
        console.log('🔍 Testing database structure...');
        
        // Test 1: Check if users table exists and has data
        const usersTest = await users.query(`
            SELECT 
                u.user_id, 
                u.email, 
                u.client_id, 
                u.status, 
                u.role,
                u.created_at
            FROM users u 
            LIMIT 5
        `);
        
        // Test 2: Check if clients table exists and has data  
        const clientsTest = await users.query(`
            SELECT 
                client_id, 
                client_name, 
                status 
            FROM clients 
            LIMIT 5
        `);
        
        // Test 3: Test the JOIN query
        const joinTest = await users.query(`
            SELECT 
                u.user_id, 
                u.email, 
                u.status as user_status,
                c.client_name,
                c.status as client_status
            FROM users u
            JOIN clients c ON u.client_id = c.client_id
            LIMIT 5
        `);
        
        res.json({
            success: true,
            tests: {
                users: {
                    count: usersTest.rows.length,
                    sample: usersTest.rows
                },
                clients: {
                    count: clientsTest.rows.length,
                    sample: clientsTest.rows
                },
                join: {
                    count: joinTest.rows.length,
                    sample: joinTest.rows
                }
            }
        });
        
    } catch (error) {
        console.error('💥 DB TEST ERROR:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            stack: error.stack
        });
    }
});

// Middleware for client token authentication
function authenticateClientToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }
        
        // Check if it's a client token
        if (user.type !== 'client') {
            return res.status(403).json({
                success: false,
                message: 'Invalid token type'
            });
        }
        
        req.users = user;
        next();
    });
}

// Client dashboard route (protected)
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'client-dashboard.html'));
});

// API endpoint to verify client token
app.get('/api/auth/client-verify', authenticateClientToken, (req, res) => {
    res.json({
        success: true,
        user: req.users
    });
});

// Function to generate feedback form HTML
function generateFeedbackFormHTML(client, branches) {
  const clientNameForUrl = client.client_name.toLowerCase().replace(/\s+/g, '');
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Feedback - ${client.client_name} | FeedFast</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1rem;
        }
        
        .form-container {
            padding: 40px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
            font-size: 1rem;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            font-family: inherit;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 120px;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        @media (max-width: 600px) {
            .form-row {
                grid-template-columns: 1fr;
            }
        }
        
        .required {
            color: #dc3545;
        }
        
        .feedback-types {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
        }
        
        .type-option {
            position: relative;
        }
        
        .type-option input[type="radio"] {
            position: absolute;
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .type-option label {
            display: block;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .type-option input[type="radio"]:checked + label {
            background: #667eea;
            border-color: #667eea;
            color: white;
        }
        
        .type-option label:hover {
            border-color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 8px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            width: 100%;
            margin-top: 20px;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .submit-btn:active {
            transform: translateY(0);
        }
        
        .submit-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .success-message {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        .error-message {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        .loading {
            display: none;
            text-align: center;
            color: #666;
            margin-top: 10px;
        }
        
        .powered-by {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9rem;
        }
        
        .powered-by a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .file-upload-area {
    position: relative;
    border: 2px dashed #e1e5e9;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    transition: border-color 0.3s ease;
    cursor: pointer;
}

.file-upload-area:hover {
    border-color: #667eea;
    background: rgba(102, 126, 234, 0.05);
}

.file-upload-area.dragover {
    border-color: #667eea;
    background: rgba(102, 126, 234, 0.1);
}

.file-upload-area input[type="file"] {
    position: absolute;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    opacity: 0;
    cursor: pointer;
}

.upload-placeholder {
    pointer-events: none;
}

.upload-note {
    font-size: 0.9rem;
    color: #666;
    margin-top: 5px;
}

.file-preview {
    position: relative;
    display: inline-block;
}

.file-preview img {
    max-width: 200px;
    max-height: 150px;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.remove-file {
    position: absolute;
    top: -10px;
    right: -10px;
    background: #dc3545;
    color: white;
    border: none;
    border-radius: 50%;
    width: 24px;
    height: 24px;
    cursor: pointer;
    font-size: 16px;
    line-height: 1;
}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Share Your Feedback</h1>
            <p>Help us improve our service for <strong>${client.client_name}</strong></p>
        </div>
        
        <div class="form-container">
            <div class="success-message" id="successMessage"></div>
            <div class="error-message" id="errorMessage"></div>
            
            <form id="feedbackForm">
                <div class="form-group">
                    <label>Feedback Type <span class="required">*</span></label>
                    <div class="feedback-types">
                        <div class="type-option">
                            <input type="radio" id="complaint" name="type" value="complaint" required>
                            <label for="complaint">Complaint</label>
                        </div>
                        <div class="type-option">
                            <input type="radio" id="suggestion" name="type" value="suggestion" required>
                            <label for="suggestion">Suggestion</label>
                        </div>
                        <div class="type-option">
                            <input type="radio" id="compliment" name="type" value="compliment" required>
                            <label for="compliment">Compliment</label>
                        </div>
                        <div class="type-option">
                            <input type="radio" id="inquiry" name="type" value="inquiry" required>
                            <label for="inquiry">Inquiry</label>
                        </div>
                    </div>
                </div>
                
                ${branches.length > 0 ? `
                <div class="form-group">
                    <label for="branch">Branch/Location</label>
                    <select name="branch_id" id="branch">
                        <option value="">Select a branch (optional)</option>
                        ${branches.map(branch => 
                          `<option value="${branch.branch_id}">${branch.branch_name} ${branch.branch_code ? '(' + branch.branch_code + ')' : ''}</option>`
                        ).join('')}
                    </select>
                </div>
                ` : ''}
                
                <div class="form-group">
                    <label for="title">Subject <span class="required">*</span></label>
                    <input type="text" id="title" name="title" required 
                           placeholder="Brief description of your feedback">
                </div>
                
                <div class="form-group">
                    <label for="description">Message <span class="required">*</span></label>
                    <textarea id="description" name="description" required 
                              placeholder="Please provide detailed information about your feedback..."></textarea>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="name">Your Name <span class="required">*</span></label>
                        <input type="text" id="name" name="cust_name" required 
                               placeholder="Enter your full name">
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="cust_email" 
                               placeholder="your.email@example.com">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="phone">Phone Number</label>
                    <input type="tel" id="phone" name="cust_phone" 
                           placeholder="Your phone number">
                </div>

                <div class="form-group">
    <label for="attachment">Attach Image (Optional)</label>
    <div class="file-upload-area" id="fileUploadArea">
        <input type="file" id="attachment" name="attachment" accept="image/*">
        <div class="upload-placeholder">
            <p>📷 Click to upload or drag & drop an image</p>
            <p class="upload-note">Max 5MB • JPG, PNG, GIF supported</p>
        </div>
        <div class="file-preview" id="filePreview" style="display: none;">
            <img id="previewImage" src="" alt="Preview">
            <button type="button" class="remove-file" id="removeFile">×</button>
        </div>
    </div>
</div>
                
                <button type="submit" class="submit-btn" id="submitBtn">
                    Submit Feedback
                </button>
                
                <div class="loading" id="loading">
                    Submitting your feedback...
                </div>
            </form>
        </div>
        
        <div class="powered-by">
            Powered by <a href="#" target="_blank">FeedFast</a>
        </div>
    </div>

    <script>
    const form = document.getElementById('feedbackForm');
    const submitBtn = document.getElementById('submitBtn');
    const loading = document.getElementById('loading');
    const successMessage = document.getElementById('successMessage');
    const errorMessage = document.getElementById('errorMessage');
    const fileInput = document.getElementById('attachment');
    const fileUploadArea = document.getElementById('fileUploadArea');
    const filePreview = document.getElementById('filePreview');
    const previewImage = document.getElementById('previewImage');
    const removeFileBtn = document.getElementById('removeFile');
    const uploadPlaceholder = fileUploadArea.querySelector('.upload-placeholder');

    // File upload handling
    fileInput.addEventListener('change', handleFileSelect);
    fileUploadArea.addEventListener('dragover', handleDragOver);
    fileUploadArea.addEventListener('dragleave', handleDragLeave);
    fileUploadArea.addEventListener('drop', handleDrop);
    removeFileBtn.addEventListener('click', removeFile);

    function handleFileSelect(e) {
        const file = e.target.files[0];
        if (file) {
            displayFilePreview(file);
        }
    }

    function handleDragOver(e) {
        e.preventDefault();
        fileUploadArea.classList.add('dragover');
    }

    function handleDragLeave(e) {
        e.preventDefault();
        fileUploadArea.classList.remove('dragover');
    }

    function handleDrop(e) {
        e.preventDefault();
        fileUploadArea.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (file.type.startsWith('image/')) {
                fileInput.files = files;
                displayFilePreview(file);
            } else {
                showError('Please select an image file only.');
            }
        }
    }

    function displayFilePreview(file) {
        if (file.size > 5 * 1024 * 1024) {
            showError('File size must be less than 5MB.');
            fileInput.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = function(e) {
            previewImage.src = e.target.result;
            uploadPlaceholder.style.display = 'none';
            filePreview.style.display = 'block';
        };
        reader.readAsDataURL(file);
    }

    function removeFile() {
        fileInput.value = '';
        filePreview.style.display = 'none';
        uploadPlaceholder.style.display = 'block';
    }

    function showError(message) {
        errorMessage.innerHTML = \`<strong>Error!</strong> \${message}\`;
        errorMessage.style.display = 'block';
        errorMessage.scrollIntoView({ behavior: 'smooth' });
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Clear previous messages
        successMessage.style.display = 'none';
        errorMessage.style.display = 'none';
        
        // Show loading
        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';
        loading.style.display = 'block';

        try {
            const formData = new FormData(form);
            formData.append('client_name', '${clientNameForUrl}');

            const response = await fetch('/api/feedback', {
                method: 'POST',
                body: formData // Use FormData instead of JSON for file uploads
            });

            const result = await response.json();

            if (result.success) {
                successMessage.innerHTML = \`
                    <strong>Thank you!</strong> Your feedback has been submitted successfully. 
                    Ticket ID: #\${result.ticket_id}
                    \${result.attachment_url ? '<br>📎 Image uploaded successfully!' : ''}
                \`;
                successMessage.style.display = 'block';
                form.reset();
                removeFile(); // Clear file preview
                
                // Scroll to success message
                successMessage.scrollIntoView({ behavior: 'smooth' });
            } else {
                throw new Error(result.error || 'Failed to submit feedback');
            }

        } catch (error) {
            console.error('Error:', error);
            showError(error.message || 'Failed to submit feedback. Please try again.');
        } finally {
            // Reset button state
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit Feedback';
            loading.style.display = 'none';
        }
    });
</script>
</body>
</html>
  `;
}

// =============================================================================
// UPDATED CLIENT MANAGEMENT ROUTES - Replace the existing ones in your server.js
// =============================================================================

// Helper function to generate admin email
function generateAdminEmail(clientName) {
    // Get first 3 letters, remove spaces and special chars
    const prefix = clientName.replace(/[^a-zA-Z]/g, '').substring(0, 3).toLowerCase();
    return `adm${prefix}@yopmail.com`;
}

// Helper function to hash password
async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

// Get all clients (protected route)
app.get('/api/clients', authenticateToken, async (req, res) => {
    try {
        const result = await users.query(`
            SELECT 
                client_id,
                client_name,
                total_branch,
                total_users,
                total_tickets,
                status,
                start_date,
                expiry_date,
                created_at,
                updated_at
            FROM clients 
            ORDER BY created_at DESC
        `);
        
        res.json({
            success: true,
            clients: result.rows
        });
    } catch (error) {
        console.error('❌ Error fetching clients:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching clients'
        });
    }
});

// =============================================================================
// FIXED USER MANAGEMENT ROUTES - Corrected database connections and variables
// =============================================================================

// Serve user management page
app.get('/usermanagement', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user-management.html'));
});

// Get all users for the authenticated client (FIXED)
app.get('/api/users/management', authenticateClientToken, async (req, res) => {
    try {
        // FIXED: Correct property name (removed extra 's')
        const clientId = req.users.clientId;
        
        // FIXED: Use correct database connection (assuming it's 'db' like other parts of your app)
        const result = await db.query(`
            SELECT 
                u.user_id,
                u.client_id,
                u.branch_id,
                u.user_name,
                u.email,
                u.status,
                u.role,
                u.phone,
                u.only_assigned_tickets,
                u.created_at,
                u.updated_at,
                u.last_login,
                u.created_by
            FROM users u
            WHERE u.client_id = $1
            ORDER BY u.created_at DESC
        `, [clientId]);
        
        console.log(`👥 Fetched ${result.rows.length} users for management (client ${clientId})`);
        
        res.json({
            success: true,
            users: result.rows,
            count: result.rows.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching users for management:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching users',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get single user details (FIXED)
app.get('/api/users/management/:userId', authenticateClientToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const clientId = req.users.clientId; // FIXED: Correct property name
        
        // FIXED: Use correct database connection
        const result = await db.query(`
            SELECT 
                u.user_id,
                u.client_id,
                u.branch_id,
                u.user_name,
                u.email,
                u.status,
                u.role,
                u.phone,
                u.only_assigned_tickets,
                u.created_at,
                u.updated_at,
                u.last_login,
                u.created_by
            FROM users u
            WHERE u.user_id = $1 AND u.client_id = $2
        `, [userId, clientId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found or access denied'
            });
        }
        
        res.json({
            success: true,
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Create new user (FIXED)
app.post('/api/users/management', authenticateClientToken, async (req, res) => {
    const client = await users.connect(); // FIXED: Use correct database connection
    
    try {
        await client.query('BEGIN');
        
        const clientId = req.users.clientId; // FIXED: Correct property name
        const createdBy = req.users.name || req.users.user_name || req.users.email;
        
        const {
            user_name,
            email,
            password,
            role,
            status,
            phone,
            branch_id, // This can now be an array or null (for all branches)
            only_assigned_tickets
        } = req.body;
        
        // Validation
        if (!user_name || !email || !password || !role) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Name, email, password, and role are required'
            });
        }

        if (user_name.trim().length === 0 || user_name.trim().length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'User name must be between 1 and 255 characters'
            });
        }

        if (!isValidEmail(email.trim())) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        if (password.length < 8 || password.length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Password must be between 8 and 255 characters'
            });
        }

        // Validate role
        const validRoles = ['client_admin', 'manager', 'staff'];
        if (!validRoles.includes(role)) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid role. Must be one of: ' + validRoles.join(', ')
            });
        }

        // Check if email already exists
        const existingUser = await client.query(
            'SELECT user_id FROM users WHERE email = $1',
            [email.trim().toLowerCase()]
        );
        
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: 'Email address already exists'
            });
        }

        // Validate branch IDs if provided (only validate if not null/empty)
        if (branch_id && Array.isArray(branch_id) && branch_id.length > 0) {
            const branchCheck = await client.query(
                'SELECT COUNT(*) as count FROM branches WHERE branch_id = ANY($1) AND client_id = $2 AND status = true',
                [branch_id, clientId]
            );
            
            if (parseInt(branchCheck.rows[0].count) !== branch_id.length) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    success: false,
                    message: 'One or more invalid branch assignments'
                });
            }
        }
        
        // Hash password
        const hashedPassword = await hashPassword(password);
        
        // Create user record - store branch_id as array or null
        const branchIdValue = (branch_id && Array.isArray(branch_id) && branch_id.length > 0) ? branch_id : null;
        
        const result = await client.query(`
            INSERT INTO users (
                client_id,
                branch_id,
                user_name,
                email,
                password,
                status,
                role,
                phone,
                created_by,
                only_assigned_tickets
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING 
                user_id,
                client_id,
                branch_id,
                user_name,
                email,
                status,
                role,
                phone,
                created_at,
                updated_at,
                created_by,
                only_assigned_tickets
        `, [
            clientId,
            branchIdValue,
            user_name.trim(),
            email.trim().toLowerCase(),
            hashedPassword,
            status !== undefined ? status : true, // Default to active
            role,
            phone ? phone.trim() : null,
            createdBy,
            only_assigned_tickets || false
        ]);
        
        const newUser = result.rows[0];

        // Update client's total_users count
        await client.query(
            'UPDATE clients SET total_users = total_users + 1, updated_at = CURRENT_TIMESTAMP WHERE client_id = $1',
            [clientId]
        );
        
        await client.query('COMMIT');
        
        console.log(`✅ New user created: ${newUser.user_name} (${newUser.email}) for client ${clientId}`);
        
        // Remove password from response
        delete newUser.password;
        
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: newUser
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error creating user:', error);
        
        // Handle specific PostgreSQL errors
        if (error.code === '23505') { // Unique constraint violation
            return res.status(409).json({
                success: false,
                message: 'Email address already exists'
            });
        }
        
        if (error.code === '22001') { // String data too long
            return res.status(400).json({
                success: false,
                message: 'One of the fields is too long. Please check your input.'
            });
        }

        if (error.code === '23503') { // Foreign key constraint violation
            return res.status(400).json({
                success: false,
                message: 'Invalid client or branch reference'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error while creating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        client.release();
    }
});

// Update user (FIXED)
app.put('/api/users/management/:userId', authenticateClientToken, async (req, res) => {
    const client = await users.connect(); // FIXED: Use correct database connection
    
    try {
        await client.query('BEGIN');
        
        const { userId } = req.params;
        const clientId = req.users.clientId; // FIXED: Correct property name
        
        const {
            user_name,
            email,
            role,
            status,
            phone,
            branch_id, // This can now be an array or null (for all branches)
            only_assigned_tickets
        } = req.body;
        
        // Validation
        if (!user_name || !email || !role) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Name, email, and role are required'
            });
        }

        if (user_name.trim().length === 0 || user_name.trim().length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'User name must be between 1 and 255 characters'
            });
        }

        if (!isValidEmail(email.trim())) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        // Validate role
        const validRoles = ['client_admin', 'manager', 'staff'];
        if (!validRoles.includes(role)) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid role. Must be one of: ' + validRoles.join(', ')
            });
        }

        // Check if user exists and belongs to this client
        const existingUser = await client.query(
            'SELECT user_id, email FROM users WHERE user_id = $1 AND client_id = $2',
            [userId, clientId]
        );
        
        if (existingUser.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'User not found or access denied'
            });
        }

        // Check if email already exists (excluding current user)
        const emailCheck = await client.query(
            'SELECT user_id FROM users WHERE email = $1 AND user_id != $2',
            [email.trim().toLowerCase(), userId]
        );
        
        if (emailCheck.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: 'Email address already exists'
            });
        }

        // Validate branch IDs if provided (only validate if not null/empty)
        if (branch_id && Array.isArray(branch_id) && branch_id.length > 0) {
            const branchCheck = await client.query(
                'SELECT COUNT(*) as count FROM branches WHERE branch_id = ANY($1) AND client_id = $2 AND status = true',
                [branch_id, clientId]
            );
            
            if (parseInt(branchCheck.rows[0].count) !== branch_id.length) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    success: false,
                    message: 'One or more invalid branch assignments'
                });
            }
        }
        
        // Update user record - store branch_id as array or null
        const branchIdValue = (branch_id && Array.isArray(branch_id) && branch_id.length > 0) ? branch_id : null;
        
        const result = await client.query(`
            UPDATE users SET
                user_name = $1,
                email = $2,
                role = $3,
                status = $4,
                phone = $5,
                branch_id = $6,
                only_assigned_tickets = $7,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $8 AND client_id = $9
            RETURNING 
                user_id,
                client_id,
                branch_id,
                user_name,
                email,
                status,
                role,
                phone,
                created_at,
                updated_at,
                last_login,
                created_by,
                only_assigned_tickets
        `, [
            user_name.trim(),
            email.trim().toLowerCase(),
            role,
            status !== undefined ? status : true,
            phone ? phone.trim() : null,
            branchIdValue,
            only_assigned_tickets || false,
            userId,
            clientId
        ]);
        
        await client.query('COMMIT');
        
        const updatedUser = result.rows[0];
        
        console.log(`📝 User updated: ${updatedUser.user_name} (ID: ${userId}) for client ${clientId}`);
        
        res.json({
            success: true,
            message: 'User updated successfully',
            data: updatedUser
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error updating user:', error);
        
        // Handle specific PostgreSQL errors
        if (error.code === '23505') {
            return res.status(409).json({
                success: false,
                message: 'Email address already exists'
            });
        }
        
        if (error.code === '22001') {
            return res.status(400).json({
                success: false,
                message: 'One of the fields is too long. Please check your input.'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error while updating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        client.release();
    }
});

// Toggle user status (FIXED)
app.patch('/api/users/management/:userId/status', authenticateClientToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const { status } = req.body;
        const clientId = req.users.clientId; // FIXED: Correct property name
        
        if (typeof status !== 'boolean') {
            return res.status(400).json({
                success: false,
                message: 'Status must be true or false'
            });
        }
        
        // Check if user exists and belongs to this client
        const existingUser = await db.query( // FIXED: Use correct database connection
            'SELECT user_id, user_name FROM users WHERE user_id = $1 AND client_id = $2',
            [userId, clientId]
        );
        
        if (existingUser.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found or access denied'
            });
        }
        
        // Don't allow deactivating yourself
        if (parseInt(userId) === req.users.userId && !status) {
            return res.status(400).json({
                success: false,
                message: 'You cannot deactivate your own account'
            });
        }
        
        const result = await db.query(` // FIXED: Use correct database connection
            UPDATE users 
            SET status = $1, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $2 AND client_id = $3
            RETURNING user_id, user_name, status
        `, [status, userId, clientId]);
        
        const updatedUser = result.rows[0];
        
        console.log(`🔄 User status updated: ${updatedUser.user_name} -> ${status ? 'Active' : 'Inactive'}`);
        
        res.json({
            success: true,
            message: `User ${status ? 'activated' : 'deactivated'} successfully`,
            data: updatedUser
        });
        
    } catch (error) {
        console.error('❌ Error updating user status:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while updating user status',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Delete user (FIXED)
app.delete('/api/users/management/:userId', authenticateClientToken, async (req, res) => {
    const client = await users.connect(); // FIXED: Use correct database connection
    
    try {
        await client.query('BEGIN');
        
        const { userId } = req.params;
        const clientId = req.users.clientId; // FIXED: Correct property name
        
        // Don't allow deleting yourself
        if (parseInt(userId) === req.users.userId) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'You cannot delete your own account'
            });
        }
        
        // Check if user exists and belongs to this client
        const existingUser = await client.query(
            'SELECT user_id, user_name FROM users WHERE user_id = $1 AND client_id = $2',
            [userId, clientId]
        );
        
        if (existingUser.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'User not found or access denied'
            });
        }
        
        // Check if user has assigned tickets
        const assignedTickets = await client.query(
            'SELECT COUNT(*) as count FROM tickets WHERE pic_ticket = $1 AND status NOT IN (\'resolved\', \'closed\')',
            [userId]
        );
        
        const activeTicketCount = parseInt(assignedTickets.rows[0].count);
        
        if (activeTicketCount > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: `Cannot delete user. They have ${activeTicketCount} active ticket(s) assigned. Please reassign these tickets first.`
            });
        }
        
        // Soft delete: set status to false and add deletion timestamp
        await client.query(`
            UPDATE users 
            SET status = false, 
                updated_at = CURRENT_TIMESTAMP,
                email = email || '_deleted_' || EXTRACT(EPOCH FROM NOW())
            WHERE user_id = $1
        `, [userId]);

        // Update client's total_users count (only count active users)
        await client.query(`
            UPDATE clients 
            SET total_users = (
                SELECT COUNT(*) FROM users 
                WHERE client_id = $1 AND status = true
            ),
            updated_at = CURRENT_TIMESTAMP
            WHERE client_id = $1
        `, [clientId]);
        
        await client.query('COMMIT');
        
        const userName = existingUser.rows[0].user_name;
        
        console.log(`🗑️ User soft deleted: ${userName} (ID: ${userId}) for client ${clientId}`);
        
        res.json({
            success: true,
            message: 'User deleted successfully'
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while deleting user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        client.release();
    }
});

// Reset user password (FIXED)
app.patch('/api/users/management/:userId/password', authenticateClientToken, async (req, res) => {
    const client = await users.connect(); // FIXED: Use correct database connection
    
    try {
        await client.query('BEGIN');
        
        const { userId } = req.params;
        const { password } = req.body;
        const clientId = req.users.clientId; // FIXED: Correct property name
        
        if (!password || password.length < 8 || password.length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Password must be between 8 and 255 characters'
            });
        }
        
        // Check if user exists and belongs to this client
        const existingUser = await client.query(
            'SELECT user_id, user_name FROM users WHERE user_id = $1 AND client_id = $2',
            [userId, clientId]
        );
        
        if (existingUser.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'User not found or access denied'
            });
        }
        
        // Hash new password
        const hashedPassword = await hashPassword(password);
        
        // Update password
        await client.query(
            'UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2',
            [hashedPassword, userId]
        );
        
        await client.query('COMMIT');
        
        const userName = existingUser.rows[0].user_name;
        
        console.log(`🔑 Password reset for user: ${userName} (ID: ${userId})`);
        
        res.json({
            success: true,
            message: 'Password updated successfully'
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error resetting password:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while resetting password',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        client.release();
    }
});

// =============================================================================
// REQUIRED HELPER FUNCTIONS - Add these if not already in your server.js
// =============================================================================

// Email validation function (add if missing)
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Password hashing function (add if missing)
async function hashPassword(password) {
    const bcrypt = require('bcryptjs');
    return await bcrypt.hash(password, 10);
}

// =============================================================================
// CLIENT TOKEN AUTHENTICATION MIDDLEWARE (add if missing)
// =============================================================================

// Client token authentication middleware
function authenticateClientToken(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }
    
    const token = authHeader.substring(7); // Remove "Bearer " prefix
    
    try {
        // MAKE SURE YOU HAVE JWT IMPORTED: const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Verify this is a client token (not admin token)
        if (decoded.type !== 'client') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token type'
            });
        }
        
        req.users = decoded;
        next();
    } catch (error) {
        console.error('❌ Client token verification failed:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
}

// =============================================================================
// END OF FIXED USER MANAGEMENT ROUTES
// =============================================================================



// =============================================================================
// BRANCH MANAGEMENT ROUTES - FIXED VERSION
// =============================================================================

// Serve branch management page (NOT protected - let client-side handle auth)
app.get('/branch', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'branch-management.html'));
});

// Get all branches for the authenticated client (API route - protected)
app.get('/api/branches', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        
        const result = await users.query(`
            SELECT 
                branch_id,
                client_id,
                branch_name,
                branch_code,
                address,
                phone,
                email,
                pic_name,
                pic_phone,
                pic_email,
                status,
                created_at,
                updated_at,
                created_by
            FROM branches 
            WHERE client_id = $1
            ORDER BY created_at DESC
        `, [clientId]);
        
        console.log(`📋 Fetched ${result.rows.length} branches for client ${clientId}`);
        
        res.json({
            success: true,
            branches: result.rows,
            count: result.rows.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching branches:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching branches'
        });
    }
});

// PATCH /api/tickets/:id/assign
app.patch('/api/tickets/:id/assign', authenticateClientToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { pic_ticket } = req.body;
        const clientId = req.users.client_id;
        
        const result = await adminDb.query(
            'UPDATE tickets SET pic_ticket = $1 WHERE ticket_id = $2 AND client_id = $3 RETURNING *',
            [pic_ticket, id, clientId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Ticket not found' });
        }
        
        res.json({ success: true, ticket: result.rows[0] });
    } catch (error) {
        console.error('Error assigning ticket:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Create new branch
app.post('/api/branches', authenticateClientToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const clientId = req.users.clientId;
        const createdBy = req.users.name || req.users.email;
        
        const {
            branch_name,
            branch_code,
            address,
            phone,
            email,
            pic_name,
            pic_phone,
            pic_email
        } = req.body;
        
        // Validation
        if (!branch_name || branch_name.trim().length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Branch name is required'
            });
        }

        if (branch_name.trim().length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Branch name is too long (max 255 characters)'
            });
        }

        // Validate email format if provided
        if (email && email.trim() && !isValidEmail(email.trim())) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid branch email address'
            });
        }

        // Validate PIC email format if provided
        if (pic_email && pic_email.trim() && !isValidEmail(pic_email.trim())) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid PIC email address'
            });
        }
        
        // Check if branch name already exists for this client (case-insensitive)
        const existingBranch = await client.query(
            'SELECT branch_id FROM branches WHERE client_id = $1 AND LOWER(branch_name) = LOWER($2)',
            [clientId, branch_name.trim()]
        );
        
        if (existingBranch.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: 'Branch name already exists for your organization'
            });
        }

        // Check if branch code already exists for this client (if provided)
        if (branch_code && branch_code.trim()) {
            const existingCode = await client.query(
                'SELECT branch_id FROM branches WHERE client_id = $1 AND LOWER(branch_code) = LOWER($2)',
                [clientId, branch_code.trim()]
            );
            
            if (existingCode.rows.length > 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({
                    success: false,
                    message: 'Branch code already exists for your organization'
                });
            }
        }
        
        // Create branch record
        const result = await client.query(`
            INSERT INTO branches (
                client_id,
                branch_name, 
                branch_code,
                address,
                phone,
                email,
                pic_name,
                pic_phone,
                pic_email,
                status,
                created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING 
                branch_id,
                client_id,
                branch_name,
                branch_code,
                address,
                phone,
                email,
                pic_name,
                pic_phone,
                pic_email,
                status,
                created_at,
                updated_at,
                created_by
        `, [
            clientId,
            branch_name.trim(),
            branch_code?.trim() || null,
            address?.trim() || null,
            phone?.trim() || null,
            email?.trim() || null,
            pic_name?.trim() || null,
            pic_phone?.trim() || null,
            pic_email?.trim() || null,
            true, // status - default active
            createdBy
        ]);
        
        const newBranch = result.rows[0];

        // Update client's total_branch count
        await client.query(
            'UPDATE clients SET total_branch = total_branch + 1, updated_at = CURRENT_TIMESTAMP WHERE client_id = $1',
            [clientId]
        );
        
        await client.query('COMMIT');
        
        console.log(`✅ New branch created: ${newBranch.branch_name} (ID: ${newBranch.branch_id}) for client ${clientId}`);
        
        res.status(201).json({
            success: true,
            message: 'Branch created successfully',
            data: newBranch
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error creating branch:', error);
        
        // Handle specific PostgreSQL errors
        if (error.code === '23505') { // Unique constraint violation
            return res.status(409).json({
                success: false,
                message: 'Branch name or code already exists'
            });
        }
        
        if (error.code === '22001') { // String data too long
            return res.status(400).json({
                success: false,
                message: 'One of the fields is too long. Please check your input.'
            });
        }

        if (error.code === '23503') { // Foreign key constraint violation
            return res.status(400).json({
                success: false,
                message: 'Invalid client reference'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error while creating branch'
        });
    } finally {
        client.release();
    }
});

// Update branch
app.put('/api/branches/:branchId', authenticateClientToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const { branchId } = req.params;
        const clientId = req.users.clientId;
        
        const {
            branch_name,
            branch_code,
            address,
            phone,
            email,
            pic_name,
            pic_phone,
            pic_email
        } = req.body;
        
        // Validation
        if (!branch_name || branch_name.trim().length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Branch name is required'
            });
        }

        if (branch_name.trim().length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Branch name is too long (max 255 characters)'
            });
        }

        // Validate email format if provided
        if (email && email.trim() && !isValidEmail(email.trim())) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid branch email address'
            });
        }

        // Validate PIC email format if provided
        if (pic_email && pic_email.trim() && !isValidEmail(pic_email.trim())) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid PIC email address'
            });
        }

        // Check if branch exists and belongs to this client
        const existingBranch = await client.query(
            'SELECT branch_id, branch_name FROM branches WHERE branch_id = $1 AND client_id = $2',
            [branchId, clientId]
        );
        
        if (existingBranch.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Branch not found or access denied'
            });
        }
        
        // Check if new branch name already exists for this client (excluding current branch)
        const duplicateName = await client.query(
            'SELECT branch_id FROM branches WHERE client_id = $1 AND LOWER(branch_name) = LOWER($2) AND branch_id != $3',
            [clientId, branch_name.trim(), branchId]
        );
        
        if (duplicateName.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: 'Branch name already exists for your organization'
            });
        }

        // Check if new branch code already exists for this client (if provided, excluding current branch)
        if (branch_code && branch_code.trim()) {
            const duplicateCode = await client.query(
                'SELECT branch_id FROM branches WHERE client_id = $1 AND LOWER(branch_code) = LOWER($2) AND branch_id != $3',
                [clientId, branch_code.trim(), branchId]
            );
            
            if (duplicateCode.rows.length > 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({
                    success: false,
                    message: 'Branch code already exists for your organization'
                });
            }
        }
        
        // Update branch record
        const result = await client.query(`
            UPDATE branches SET
                branch_name = $1,
                branch_code = $2,
                address = $3,
                phone = $4,
                email = $5,
                pic_name = $6,
                pic_phone = $7,
                pic_email = $8,
                updated_at = CURRENT_TIMESTAMP
            WHERE branch_id = $9 AND client_id = $10
            RETURNING 
                branch_id,
                client_id,
                branch_name,
                branch_code,
                address,
                phone,
                email,
                pic_name,
                pic_phone,
                pic_email,
                status,
                created_at,
                updated_at,
                created_by
        `, [
            branch_name.trim(),
            branch_code?.trim() || null,
            address?.trim() || null,
            phone?.trim() || null,
            email?.trim() || null,
            pic_name?.trim() || null,
            pic_phone?.trim() || null,
            pic_email?.trim() || null,
            branchId,
            clientId
        ]);
        
        await client.query('COMMIT');
        
        const updatedBranch = result.rows[0];
        
        console.log(`🔄 Branch updated: ${updatedBranch.branch_name} (ID: ${branchId}) for client ${clientId}`);
        
        res.json({
            success: true,
            message: 'Branch updated successfully',
            data: updatedBranch
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error updating branch:', error);
        
        // Handle specific PostgreSQL errors
        if (error.code === '23505') {
            return res.status(409).json({
                success: false,
                message: 'Branch name or code already exists'
            });
        }
        
        if (error.code === '22001') {
            return res.status(400).json({
                success: false,
                message: 'One of the fields is too long. Please check your input.'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error while updating branch'
        });
    } finally {
        client.release();
    }
});

// Update branch status (activate/deactivate)
app.patch('/api/branches/:branchId/status', authenticateClientToken, async (req, res) => {
    try {
        const { branchId } = req.params;
        const { status } = req.body;
        const clientId = req.users.clientId;
        
        if (typeof status !== 'boolean') {
            return res.status(400).json({
                success: false,
                message: 'Status must be true or false'
            });
        }
        
        // Check if branch exists and belongs to this client
        const existingBranch = await users.query(
            'SELECT branch_id, branch_name FROM branches WHERE branch_id = $1 AND client_id = $2',
            [branchId, clientId]
        );
        
        if (existingBranch.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Branch not found or access denied'
            });
        }
        
        const result = await users.query(`
            UPDATE branches 
            SET status = $1, updated_at = CURRENT_TIMESTAMP
            WHERE branch_id = $2 AND client_id = $3
            RETURNING branch_id, branch_name, status
        `, [status, branchId, clientId]);
        
        const updatedBranch = result.rows[0];
        
        console.log(`🔄 Branch status updated: ${updatedBranch.branch_name} -> ${status ? 'Active' : 'Inactive'}`);
        
        res.json({
            success: true,
            message: `Branch ${status ? 'activated' : 'deactivated'} successfully`,
            data: updatedBranch
        });
        
    } catch (error) {
        console.error('❌ Error updating branch status:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while updating branch status'
        });
    }
});

// Get single branch details
app.get('/api/branches/:branchId', authenticateClientToken, async (req, res) => {
    try {
        const { branchId } = req.params;
        const clientId = req.users.clientId;
        
        const result = await users.query(`
            SELECT 
                branch_id,
                client_id,
                branch_name,
                branch_code,
                address,
                phone,
                email,
                pic_name,
                pic_phone,
                pic_email,
                status,
                created_at,
                updated_at,
                created_by
            FROM branches 
            WHERE branch_id = $1 AND client_id = $2
        `, [branchId, clientId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Branch not found or access denied'
            });
        }
        
        res.json({
            success: true,
            branch: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching branch:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching branch'
        });
    }
});

// Delete branch (soft delete - set status to false instead of actual deletion)
app.delete('/api/branches/:branchId', authenticateClientToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const { branchId } = req.params;
        const clientId = req.users.clientId;
        
        // Check if branch exists and belongs to this client
        const existingBranch = await client.query(
            'SELECT branch_id, branch_name FROM branches WHERE branch_id = $1 AND client_id = $2',
            [branchId, clientId]
        );
        
        if (existingBranch.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Branch not found or access denied'
            });
        }
        
        // Soft delete: set status to false instead of actual deletion
        await client.query(
            'UPDATE branches SET status = false, updated_at = CURRENT_TIMESTAMP WHERE branch_id = $1',
            [branchId]
        );

        // Update client's total_branch count (only count active branches)
        await client.query(`
            UPDATE clients 
            SET total_branch = (
                SELECT COUNT(*) FROM branches 
                WHERE client_id = $1 AND status = true
            ),
            updated_at = CURRENT_TIMESTAMP
            WHERE client_id = $1
        `, [clientId]);
        
        await client.query('COMMIT');
        
        const branchName = existingBranch.rows[0].branch_name;
        
        console.log(`🗑️ Branch soft deleted: ${branchName} (ID: ${branchId}) for client ${clientId}`);
        
        res.json({
            success: true,
            message: 'Branch deactivated successfully'
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error deleting branch:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while deleting branch'
        });
    } finally {
        client.release();
    }
});

// =============================================================================
// END OF BRANCH MANAGEMENT ROUTES
// =============================================================================

// =============================================================================
// TICKET MANAGEMENT ROUTES - Add these to your existing server.js
// =============================================================================

// Serve ticket management page
app.get('/ticket', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'ticket-management.html'));
});

// Get all tickets for the authenticated client (API route - protected)
app.get('/api/tickets', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        
        const result = await users.query(`
            SELECT 
                t.ticket_id,
                t.client_id,
                t.branch_id,
                t.cust_name,
                t.cust_email,
                t.cust_phone,
                t.type,
                t.title,
                t.description,
                t.attachment,
                t.pic_ticket,
                t.status,
                t.submitted_at,
                t.responded_at,
                t.resolved_at,
                b.branch_name,
                u.user_name as pic_name
            FROM tickets t
            LEFT JOIN branches b ON t.branch_id = b.branch_id
            LEFT JOIN users u ON t.pic_ticket = u.user_id
            WHERE t.client_id = $1
            ORDER BY t.submitted_at DESC
        `, [clientId]);
        
        console.log(`🎫 Fetched ${result.rows.length} tickets for client ${clientId}`);
        
        res.json({
            success: true,
            tickets: result.rows,
            count: result.rows.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching tickets:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching tickets'
        });
    }
});

// Get single ticket details
app.get('/api/tickets/:ticketId', authenticateClientToken, async (req, res) => {
    try {
        const { ticketId } = req.params;
        const clientId = req.users.clientId;
        
        const result = await users.query(`
            SELECT 
                t.ticket_id,
                t.client_id,
                t.branch_id,
                t.cust_name,
                t.cust_email,
                t.cust_phone,
                t.type,
                t.title,
                t.description,
                t.attachment,
                t.pic_ticket,
                t.status,
                t.submitted_at,
                t.responded_at,
                t.resolved_at,
                b.branch_name,
                b.branch_code,
                u.user_name as pic_name
            FROM tickets t
            LEFT JOIN branches b ON t.branch_id = b.branch_id
            LEFT JOIN users u ON t.pic_ticket = u.user_id
            WHERE t.ticket_id = $1 AND t.client_id = $2
        `, [ticketId, clientId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Ticket not found or access denied'
            });
        }
        
        res.json({
            success: true,
            ticket: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching ticket:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching ticket'
        });
    }
});

// Update ticket status
app.patch('/api/tickets/:ticketId/status', authenticateClientToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const { ticketId } = req.params;
        const { status } = req.body;
        const clientId = req.users.clientId;
        
        // Validate status
        const validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
        if (!validStatuses.includes(status)) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid status. Must be one of: ' + validStatuses.join(', ')
            });
        }
        
        // Check if ticket exists and belongs to this client
        const existingTicket = await client.query(
            'SELECT ticket_id, status FROM tickets WHERE ticket_id = $1 AND client_id = $2',
            [ticketId, clientId]
        );
        
        if (existingTicket.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Ticket not found or access denied'
            });
        }
        
        const currentStatus = existingTicket.rows[0].status;
        
        // Prepare update fields
        let updateFields = ['status = $1', 'updated_at = CURRENT_TIMESTAMP'];
        let updateValues = [status];
        let valueIndex = 2;
        
        // Set timestamps based on status changes
        if (status === 'in_progress' && currentStatus === 'open') {
            updateFields.push(`responded_at = CURRENT_TIMESTAMP`);
        }
        
        if (status === 'resolved' && currentStatus !== 'resolved') {
            updateFields.push(`resolved_at = CURRENT_TIMESTAMP`);
        }
        
        // Update ticket status
        const result = await client.query(`
            UPDATE tickets 
            SET ${updateFields.join(', ')}
            WHERE ticket_id = $${valueIndex} AND client_id = $${valueIndex + 1}
            RETURNING ticket_id, status, responded_at, resolved_at
        `, [...updateValues, ticketId, clientId]);
        
        await client.query('COMMIT');
        
        const updatedTicket = result.rows[0];
        
        console.log(`📝 Ticket status updated: #${ticketId} -> ${status}`);
        
        res.json({
            success: true,
            message: `Ticket status updated to ${status}`,
            data: updatedTicket
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error updating ticket status:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while updating ticket status'
        });
    } finally {
        client.release();
    }
});

// Assign ticket to user
app.patch('/api/tickets/:ticketId/assign', authenticateClientToken, async (req, res) => {
    try {
        const { ticketId } = req.params;
        const { userId } = req.body;
        const clientId = req.users.clientId;
        
        // If userId is provided, validate that the user belongs to the same client
        if (userId) {
            const userCheck = await users.query(
                'SELECT user_id FROM users WHERE user_id = $1 AND client_id = $2 AND status = true',
                [userId, clientId]
            );
            
            if (userCheck.rows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid user assignment. User not found or inactive.'
                });
            }
        }
        
        // Check if ticket exists and belongs to this client
        const existingTicket = await users.query(
            'SELECT ticket_id FROM tickets WHERE ticket_id = $1 AND client_id = $2',
            [ticketId, clientId]
        );
        
        if (existingTicket.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Ticket not found or access denied'
            });
        }
        
        // Update ticket assignment
        const result = await users.query(`
            UPDATE tickets 
            SET pic_ticket = $1, updated_at = CURRENT_TIMESTAMP
            WHERE ticket_id = $2 AND client_id = $3
            RETURNING ticket_id, pic_ticket
        `, [userId || null, ticketId, clientId]);
        
        console.log(`👤 Ticket assigned: #${ticketId} -> User ${userId || 'Unassigned'}`);
        
        res.json({
            success: true,
            message: userId ? 'Ticket assigned successfully' : 'Ticket unassigned successfully',
            data: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Error assigning ticket:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while assigning ticket'
        });
    }
});

// Create new ticket (for testing purposes - normally this would be from public form)
app.post('/api/tickets', authenticateClientToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const clientId = req.users.clientId;
        
        const {
            branch_id,
            cust_name,
            cust_email,
            cust_phone,
            type,
            title,
            description,
            attachment
        } = req.body;
        
        // Validation
        if (!cust_name || !type || !title || !description) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Customer name, type, title, and description are required'
            });
        }
        
        // Validate type
        const validTypes = ['complaint', 'suggestion', 'compliment', 'inquiry'];
        if (!validTypes.includes(type)) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid type. Must be one of: ' + validTypes.join(', ')
            });
        }
        
        // Validate email format if provided
        if (cust_email && !isValidEmail(cust_email)) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }
        
        // If branch_id is provided, validate it belongs to this client
        if (branch_id) {
            const branchCheck = await client.query(
                'SELECT branch_id FROM branches WHERE branch_id = $1 AND client_id = $2 AND status = true',
                [branch_id, clientId]
            );
            
            if (branchCheck.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    success: false,
                    message: 'Invalid branch selection'
                });
            }
        }
        
        // Create ticket record
        const result = await client.query(`
            INSERT INTO tickets (
                client_id,
                branch_id,
                cust_name,
                cust_email,
                cust_phone,
                type,
                title,
                description,
                attachment,
                status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING 
                ticket_id,
                client_id,
                branch_id,
                cust_name,
                cust_email,
                cust_phone,
                type,
                title,
                description,
                attachment,
                status,
                submitted_at
        `, [
            clientId,
            branch_id || null,
            cust_name.trim(),
            cust_email?.trim() || null,
            cust_phone?.trim() || null,
            type,
            title.trim(),
            description.trim(),
            attachment?.trim() || null,
            'open' // Default status
        ]);
        
        const newTicket = result.rows[0];

        // Update client's total_tickets count
        await client.query(
            'UPDATE clients SET total_tickets = total_tickets + 1, updated_at = CURRENT_TIMESTAMP WHERE client_id = $1',
            [clientId]
        );
        
        await client.query('COMMIT');
        
        console.log(`✅ New ticket created: ${newTicket.title} (ID: ${newTicket.ticket_id}) for client ${clientId}`);
        
        res.status(201).json({
            success: true,
            message: 'Ticket created successfully',
            data: newTicket
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error creating ticket:', error);
        
        // Handle specific PostgreSQL errors
        if (error.code === '23503') { // Foreign key constraint violation
            return res.status(400).json({
                success: false,
                message: 'Invalid reference (client or branch not found)'
            });
        }
        
        if (error.code === '22001') { // String data too long
            return res.status(400).json({
                success: false,
                message: 'One of the fields is too long. Please check your input.'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error while creating ticket'
        });
    } finally {
        client.release();
    }
});

// Get ticket statistics for dashboard
app.get('/api/tickets/stats', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        
        const result = await users.query(`
            SELECT 
                status,
                COUNT(*) as count,
                type,
                DATE_TRUNC('day', submitted_at) as date
            FROM tickets 
            WHERE client_id = $1
            GROUP BY status, type, DATE_TRUNC('day', submitted_at)
            ORDER BY date DESC
        `, [clientId]);
        
        // Process the results into a more usable format
        const stats = {
            byStatus: {},
            byType: {},
            byDate: {},
            total: 0
        };
        
        result.rows.forEach(row => {
            // Count by status
            stats.byStatus[row.status] = (stats.byStatus[row.status] || 0) + parseInt(row.count);
            
            // Count by type
            stats.byType[row.type] = (stats.byType[row.type] || 0) + parseInt(row.count);
            
            // Count by date
            const dateKey = row.date.toISOString().split('T')[0];
            stats.byDate[dateKey] = (stats.byDate[dateKey] || 0) + parseInt(row.count);
            
            // Total count
            stats.total += parseInt(row.count);
        });
        
        res.json({
            success: true,
            stats: stats
        });
        
    } catch (error) {
        console.error('❌ Error fetching ticket stats:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching ticket statistics'
        });
    }
});

// Get users for ticket assignment dropdown
app.get('/api/users', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        
        const result = await users.query(`
            SELECT 
                user_id,
                user_name,
                email,
                role,
                status
            FROM users 
            WHERE client_id = $1 AND status = true
            ORDER BY user_name ASC
        `, [clientId]);
        
        res.json({
            success: true,
            users: result.rows,
            count: result.rows.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching users:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching users'
        });
    }
});

// Bulk update ticket statuses (for advanced operations)
app.patch('/api/tickets/bulk-update', authenticateClientToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const { ticketIds, status, assignTo } = req.body;
        const clientId = req.users.clientId;
        
        if (!ticketIds || !Array.isArray(ticketIds) || ticketIds.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Ticket IDs array is required'
            });
        }
        
        // Validate status if provided
        if (status) {
            const validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
            if (!validStatuses.includes(status)) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    success: false,
                    message: 'Invalid status. Must be one of: ' + validStatuses.join(', ')
                });
            }
        }
        
        // Validate assignTo user if provided
        if (assignTo) {
            const userCheck = await client.query(
                'SELECT user_id FROM users WHERE user_id = $1 AND client_id = $2 AND status = true',
                [assignTo, clientId]
            );
            
            if (userCheck.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    success: false,
                    message: 'Invalid user assignment. User not found or inactive.'
                });
            }
        }
        
        // Build update query dynamically
        let updateFields = ['updated_at = CURRENT_TIMESTAMP'];
        let updateValues = [];
        let valueIndex = 1;
        
        if (status) {
            updateFields.push(`status = $${valueIndex}`);
            updateValues.push(status);
            valueIndex++;
            
            // Add timestamp updates based on status
            if (status === 'in_progress') {
                updateFields.push('responded_at = CURRENT_TIMESTAMP');
            } else if (status === 'resolved') {
                updateFields.push('resolved_at = CURRENT_TIMESTAMP');
            }
        }
        
        if (assignTo !== undefined) {
            updateFields.push(`pic_ticket = $${valueIndex}`);
            updateValues.push(assignTo);
            valueIndex++;
        }
        
        // Create placeholders for ticket IDs
        const ticketPlaceholders = ticketIds.map((_, index) => `$${valueIndex + index}`).join(', ');
        
        // Update tickets
        const result = await client.query(`
            UPDATE tickets 
            SET ${updateFields.join(', ')}
            WHERE ticket_id IN (${ticketPlaceholders}) AND client_id = $${valueIndex + ticketIds.length}
            RETURNING ticket_id, status, pic_ticket
        `, [...updateValues, ...ticketIds, clientId]);
        
        await client.query('COMMIT');
        
        console.log(`📋 Bulk updated ${result.rows.length} tickets for client ${clientId}`);
        
        res.json({
            success: true,
            message: `Successfully updated ${result.rows.length} tickets`,
            data: result.rows
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error bulk updating tickets:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while bulk updating tickets'
        });
    } finally {
        client.release();
    }
});

// =============================================================================
// END OF TICKET MANAGEMENT ROUTES
// =============================================================================

// =============================================================================
// REPORTS AND ANALYTICS ROUTES - Add these to your existing server.js
// =============================================================================

// Serve reports page (protected by client authentication)
app.get('/report', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

// Analytics API endpoint - comprehensive report data
app.get('/api/reports/analytics', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        const { 
            days, 
            startDate, 
            endDate, 
            branchId, 
            type 
        } = req.query;

        console.log(`📊 Generating analytics report for client ${clientId}`);
        
        // Build date filter
        let dateFilter = '';
        let dateParams = [];
        let paramIndex = 2; // Starting from $2 since $1 will be clientId
        
        if (days && days !== 'custom') {
            dateFilter = `AND t.submitted_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'`;
        } else if (startDate && endDate) {
            dateFilter = `AND t.submitted_at >= $${paramIndex} AND t.submitted_at <= $${paramIndex + 1}`;
            dateParams.push(startDate, endDate + ' 23:59:59');
            paramIndex += 2;
        } else {
            // Default to last 30 days if no date filter specified
            dateFilter = `AND t.submitted_at >= CURRENT_DATE - INTERVAL '30 days'`;
        }
        
        // Build additional filters
        let additionalFilters = '';
        let additionalParams = [];
        
        if (branchId && branchId !== 'all') {
            additionalFilters += ` AND t.branch_id = $${paramIndex}`;
            additionalParams.push(branchId);
            paramIndex++;
        }
        
        if (type && type !== 'all') {
            additionalFilters += ` AND t.type = $${paramIndex}`;
            additionalParams.push(type);
            paramIndex++;
        }

        // Main query to get tickets with all necessary data
        const ticketsQuery = `
            SELECT 
                t.ticket_id,
                t.client_id,
                t.branch_id,
                t.cust_name,
                t.cust_email,
                t.cust_phone,
                t.type,
                t.title,
                t.description,
                t.status,
                t.submitted_at,
                t.responded_at,
                t.resolved_at,
                b.branch_name,
                b.branch_code,
                u.user_name as pic_name,
                EXTRACT(EPOCH FROM (
                    COALESCE(t.responded_at, NOW()) - t.submitted_at
                )) / 3600 as response_time_hours
            FROM tickets t
            LEFT JOIN branches b ON t.branch_id = b.branch_id
            LEFT JOIN users u ON t.pic_ticket = u.user_id
            WHERE t.client_id = $1 ${dateFilter} ${additionalFilters}
            ORDER BY t.submitted_at DESC
        `;

        const allParams = [clientId, ...dateParams, ...additionalParams];
        const ticketsResult = await users.query(ticketsQuery, allParams);
        const tickets = ticketsResult.rows;

        console.log(`📈 Found ${tickets.length} tickets for analysis`);

        // Calculate statistics
        const stats = calculateAnalyticsStats(tickets);

        // Prepare response
        const responseData = {
            success: true,
            data: {
                tickets: tickets,
                stats: stats,
                filters: {
                    dateRange: days || 'custom',
                    startDate: startDate,
                    endDate: endDate,
                    branchId: branchId || 'all',
                    type: type || 'all'
                },
                generatedAt: new Date().toISOString()
            }
        };

        res.json(responseData);

    } catch (error) {
        console.error('❌ Error generating analytics report:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while generating analytics report',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

// Helper function to calculate comprehensive statistics
function calculateAnalyticsStats(tickets) {
    const stats = {
        totalTickets: tickets.length,
        byStatus: {},
        byType: {},
        byBranch: {},
        avgResponseTime: 0,
        resolutionRate: 0,
        satisfactionScore: 0,
        // Additional metrics for change indicators (mock data for now)
        totalTicketsChange: Math.random() * 20 - 10, // Random change for demo
        responseTimeChange: Math.random() * 30 - 15,
        resolutionRateChange: Math.random() * 10 - 5,
        satisfactionChange: Math.random() * 15 - 7
    };

    if (tickets.length === 0) {
        return stats;
    }

    // Count by status
    tickets.forEach(ticket => {
        stats.byStatus[ticket.status] = (stats.byStatus[ticket.status] || 0) + 1;
    });

    // Count by type
    tickets.forEach(ticket => {
        stats.byType[ticket.type] = (stats.byType[ticket.type] || 0) + 1;
    });

    // Count by branch
    tickets.forEach(ticket => {
        const branchKey = ticket.branch_name || 'Unassigned';
        stats.byBranch[branchKey] = (stats.byBranch[branchKey] || 0) + 1;
    });

    // Calculate average response time (for tickets that have been responded to)
    const respondedTickets = tickets.filter(ticket => ticket.responded_at);
    if (respondedTickets.length > 0) {
        const totalResponseTime = respondedTickets.reduce((sum, ticket) => {
            return sum + (ticket.response_time_hours || 0);
        }, 0);
        stats.avgResponseTime = totalResponseTime / respondedTickets.length;
    }

    // Calculate resolution rate
    const resolvedTickets = tickets.filter(ticket => 
        ticket.status === 'resolved' || ticket.status === 'closed'
    );
    stats.resolutionRate = tickets.length > 0 ? 
        (resolvedTickets.length / tickets.length) * 100 : 0;

    // Calculate satisfaction score (based on compliments vs complaints ratio)
    const compliments = stats.byType.compliment || 0;
    const complaints = stats.byType.complaint || 0;
    const totalFeedback = compliments + complaints;
    
    if (totalFeedback > 0) {
        stats.satisfactionScore = (compliments / totalFeedback) * 100;
    } else {
        // If no complaints/compliments, base on resolution rate
        stats.satisfactionScore = stats.resolutionRate;
    }

    return stats;
}

// Summary statistics API - lightweight version for dashboards
app.get('/api/reports/summary', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        const { days = 30 } = req.query;

        const summaryQuery = `
            SELECT 
                COUNT(*) as total_tickets,
                COUNT(CASE WHEN status = 'resolved' OR status = 'closed' THEN 1 END) as resolved_tickets,
                COUNT(CASE WHEN type = 'complaint' THEN 1 END) as complaints,
                COUNT(CASE WHEN type = 'compliment' THEN 1 END) as compliments,
                AVG(
                    CASE 
                        WHEN responded_at IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (responded_at - submitted_at)) / 3600 
                    END
                ) as avg_response_hours
            FROM tickets 
            WHERE client_id = $1 
            AND submitted_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
        `;

        const result = await users.query(summaryQuery, [clientId]);
        const row = result.rows[0];

        const summary = {
            totalTickets: parseInt(row.total_tickets) || 0,
            resolvedTickets: parseInt(row.resolved_tickets) || 0,
            resolutionRate: row.total_tickets > 0 ? 
                (parseInt(row.resolved_tickets) / parseInt(row.total_tickets)) * 100 : 0,
            avgResponseTime: parseFloat(row.avg_response_hours) || 0,
            complaints: parseInt(row.complaints) || 0,
            compliments: parseInt(row.compliments) || 0,
            satisfactionScore: (parseInt(row.complaints) + parseInt(row.compliments)) > 0 ?
                (parseInt(row.compliments) / (parseInt(row.complaints) + parseInt(row.compliments))) * 100 : 0
        };

        res.json({
            success: true,
            data: summary,
            period: `Last ${days} days`
        });

    } catch (error) {
        console.error('❌ Error generating summary report:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while generating summary report'
        });
    }
});

// Top performers report - branches/users with best metrics
app.get('/api/reports/top-performers', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        const { days = 30, limit = 10 } = req.query;

        // Top performing branches by resolution rate
        const branchQuery = `
            SELECT 
                b.branch_name,
                b.branch_code,
                COUNT(t.ticket_id) as total_tickets,
                COUNT(CASE WHEN t.status IN ('resolved', 'closed') THEN 1 END) as resolved_tickets,
                ROUND(
                    (COUNT(CASE WHEN t.status IN ('resolved', 'closed') THEN 1 END)::decimal / 
                     NULLIF(COUNT(t.ticket_id), 0)) * 100, 
                    2
                ) as resolution_rate
            FROM branches b
            LEFT JOIN tickets t ON b.branch_id = t.branch_id 
                AND t.submitted_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
            WHERE b.client_id = $1 AND b.status = true
            GROUP BY b.branch_id, b.branch_name, b.branch_code
            HAVING COUNT(t.ticket_id) > 0
            ORDER BY resolution_rate DESC, total_tickets DESC
            LIMIT $2
        `;

        const branchResult = await users.query(branchQuery, [clientId, limit]);

        // Top performing users by response time
        const userQuery = `
            SELECT 
                u.user_name,
                u.email,
                COUNT(t.ticket_id) as handled_tickets,
                ROUND(
                    AVG(
                        EXTRACT(EPOCH FROM (t.responded_at - t.submitted_at)) / 3600
                    )::numeric, 
                    2
                ) as avg_response_hours
            FROM users u
            INNER JOIN tickets t ON u.user_id = t.pic_ticket
            WHERE u.client_id = $1 
                AND u.status = true
                AND t.responded_at IS NOT NULL
                AND t.submitted_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
            GROUP BY u.user_id, u.user_name, u.email
            HAVING COUNT(t.ticket_id) >= 3
            ORDER BY avg_response_hours ASC, handled_tickets DESC
            LIMIT $2
        `;

        const userResult = await users.query(userQuery, [clientId, limit]);

        res.json({
            success: true,
            data: {
                topBranches: branchResult.rows,
                topUsers: userResult.rows,
                period: `Last ${days} days`
            }
        });

    } catch (error) {
        console.error('❌ Error generating top performers report:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while generating top performers report'
        });
    }
});

// Trend analysis - tickets over time
app.get('/api/reports/trends', authenticateClientToken, async (req, res) => {
    try {
        const clientId = req.users.clientId;
        const { days = 30, groupBy = 'day' } = req.query;

        let dateFormat;
        switch (groupBy) {
            case 'hour':
                dateFormat = 'YYYY-MM-DD HH24:00:00';
                break;
            case 'week':
                dateFormat = 'YYYY-"W"WW';
                break;
            case 'month':
                dateFormat = 'YYYY-MM';
                break;
            default:
                dateFormat = 'YYYY-MM-DD';
        }

        const trendQuery = `
            SELECT 
                TO_CHAR(submitted_at, '${dateFormat}') as period,
                COUNT(*) as ticket_count,
                COUNT(CASE WHEN type = 'complaint' THEN 1 END) as complaints,
                COUNT(CASE WHEN type = 'suggestion' THEN 1 END) as suggestions,
                COUNT(CASE WHEN type = 'compliment' THEN 1 END) as compliments,
                COUNT(CASE WHEN type = 'inquiry' THEN 1 END) as inquiries
            FROM tickets
            WHERE client_id = $1 
                AND submitted_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
            GROUP BY TO_CHAR(submitted_at, '${dateFormat}')
            ORDER BY period ASC
        `;

        const result = await users.query(trendQuery, [clientId]);

        res.json({
            success: true,
            data: {
                trends: result.rows,
                groupBy: groupBy,
                period: `Last ${days} days`
            }
        });

    } catch (error) {
        console.error('❌ Error generating trend analysis:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while generating trend analysis'
        });
    }
});

// =============================================================================
// END OF REPORTS AND ANALYTICS ROUTES
// =============================================================================

// =============================================================================
// PUBLIC FEEDBACK FORM ROUTES - Add these after the ticket management routes
// =============================================================================

// Dynamic feedback route - serves feedback form for specific client
app.get('/feedback/:clientname', async (req, res) => {
  const { clientname } = req.params;
  
  try {
    // Query to find client by name (case-insensitive)
    const clientQuery = `
      SELECT client_id, client_name, status 
      FROM clients 
      WHERE LOWER(REPLACE(client_name, ' ', '')) = LOWER($1) 
      AND status = true
    `;
    
    const clientResult = await users.query(clientQuery, [clientname.toLowerCase()]);
    
    if (clientResult.rows.length === 0) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Client Not Found - FeedFast</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .error { color: #dc3545; }
          </style>
        </head>
        <body>
          <h1 class="error">Client Not Found</h1>
          <p>The feedback form for "${clientname}" is not available.</p>
          <p>Please check the URL or contact support.</p>
        </body>
        </html>
      `);
    }

    const client = clientResult.rows[0];
    
    // Get client's branches for dropdown
    const branchesQuery = `
      SELECT branch_id, branch_name, branch_code 
      FROM branches 
      WHERE client_id = $1 AND status = true 
      ORDER BY branch_name
    `;
    
    const branchesResult = await users.query(branchesQuery, [client.client_id]);
    const branches = branchesResult.rows;
    
    // Serve the feedback form HTML
    res.send(generateFeedbackFormHTML(client, branches));
    
  } catch (error) {
    console.error('❌ Error loading feedback form:', error);
    res.status(500).send('Internal server error');
  }
});

// API endpoint to submit feedback (PUBLIC - no authentication required)
app.post('/api/feedback', async (req, res) => {
  const {
    client_name,
    branch_id,
    cust_name,
    cust_email,
    cust_phone,
    type,
    title,
    description,
    attachment
  } = req.body;

  try {
    // Get client_id from client_name
    const clientQuery = `
      SELECT client_id FROM clients 
      WHERE LOWER(REPLACE(client_name, ' ', '')) = LOWER($1) 
      AND status = true
    `;
    
    const clientResult = await users.query(clientQuery, [client_name.toLowerCase()]);
    
    if (clientResult.rows.length === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }
    
    const client_id = clientResult.rows[0].client_id;
    
    // Insert ticket
    const insertTicketQuery = `
      INSERT INTO tickets (
        client_id, branch_id, cust_name, cust_email, cust_phone,
        type, title, description, attachment, status, submitted_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', NOW())
      RETURNING ticket_id
    `;
    
    const values = [
      client_id,
      branch_id || null,
      cust_name,
      cust_email || null,
      cust_phone || null,
      type,
      title,
      description,
      attachment || null
    ];
    
    const result = await users.query(insertTicketQuery, values);
    const ticket_id = result.rows[0].ticket_id;
    
    // Update client total_tickets count
    await users.query(
      'UPDATE clients SET total_tickets = total_tickets + 1 WHERE client_id = $1',
      [client_id]
    );
    
    console.log(`✅ Public feedback submitted: Ticket #${ticket_id} for client ${client_id}`);
    
    res.json({ 
      success: true, 
      message: 'Feedback submitted successfully',
      ticket_id: ticket_id
    });
    
  } catch (error) {
    console.error('❌ Error submitting feedback:', error);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

app.post('/api/clients', authenticateToken, async (req, res) => {
    const client = await users.connect();
    
    try {
        await client.query('BEGIN');
        
        const { client_name, expiry_date } = req.body;
        
        // Validation
        if (!client_name || !expiry_date) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Client name and expiry date are required'
            });
        }

        // Validate client name length
        if (client_name.length > 255) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Client name is too long (max 255 characters)'
            });
        }

        // Validate expiry date
        const expiryDateObj = new Date(expiry_date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        if (expiryDateObj <= today) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Expiry date must be in the future'
            });
        }
        
        // Check if client name already exists (case-insensitive)
        const existingClient = await client.query(
            'SELECT client_id FROM clients WHERE LOWER(client_name) = LOWER($1)',
            [client_name.trim()]
        );
        
        if (existingClient.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: 'Client name already exists'
            });
        }
        
        // Generate admin email
        const adminEmail = generateAdminEmail(client_name);
        
        // Check if admin email already exists in both tables
        const existingAdmin = await client.query(
            'SELECT user_id FROM adminbo WHERE email = $1 UNION SELECT user_id FROM users WHERE email = $1',
            [adminEmail]
        );
        
        if (existingAdmin.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: `Admin email ${adminEmail} already exists. Please choose a different client name.`
            });
        }
        
        // Create client record
        const clientResult = await client.query(`
            INSERT INTO clients (
                client_name, 
                expiry_date, 
                status, 
                total_branch, 
                total_users, 
                total_tickets
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING 
                client_id, 
                client_name, 
                start_date, 
                expiry_date, 
                status,
                total_branch,
                total_users,
                total_tickets,
                created_at
        `, [
            client_name.trim(), 
            expiry_date, 
            true,  // status - default active
            0,     // total_branch - default 0
            1,     // total_users - default 1 (the admin we're creating)
            0      // total_tickets - default 0
        ]);
        
        const newClient = clientResult.rows[0];
        
        // Create client admin account in adminbo table (for super admin management)
        const defaultPassword = '12345678';
        const hashedPassword = await hashPassword(defaultPassword);
        
        const adminResult = await client.query(`
            INSERT INTO adminbo (name, email, password, client_id)
            VALUES ($1, $2, $3, $4)
            RETURNING user_id, name, email, client_id
        `, [
            `${client_name.trim()} Admin`, 
            adminEmail, 
            hashedPassword, 
            newClient.client_id
        ]);
        
        const newAdmin = adminResult.rows[0];
        
        // *** NEW: Also create user record in users table for client login ***
        const clientUserResult = await client.query(`
            INSERT INTO users (
                client_id, 
                branch_id, 
                user_name, 
                email, 
                password, 
                status, 
                role, 
                created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING user_id, user_name, email, role
        `, [
            newClient.client_id,
            null,                                    // branch_id: null for all branches access
            `${client_name.trim()} Admin`,           // user_name
            adminEmail,                              // email (same as adminbo)
            hashedPassword,                          // password (same as adminbo)
            true,                                    // status: active
            'client_admin',                          // role
            'System'                                 // created_by
        ]);
        
        const newClientUser = clientUserResult.rows[0];
        
        await client.query('COMMIT');
        
        console.log(`✅ New client created: ${client_name} (ID: ${newClient.client_id})`);
        console.log(`✅ Admin created in adminbo: ${adminEmail}`);
        console.log(`✅ User created in users: ${adminEmail}`);
        
        res.status(201).json({
            success: true,
            message: 'Client and admin accounts created successfully',
            data: {
                client: {
                    client_id: newClient.client_id,
                    client_name: newClient.client_name,
                    start_date: newClient.start_date,
                    expiry_date: newClient.expiry_date,
                    status: newClient.status,
                    total_branch: newClient.total_branch,
                    total_users: newClient.total_users,
                    total_tickets: newClient.total_tickets,
                    created_at: newClient.created_at
                },
                admin: {
                    adminbo_id: newAdmin.user_id,
                    users_id: newClientUser.user_id,
                    name: newAdmin.name,
                    email: newAdmin.email,
                    password: defaultPassword, // Only show in response for setup purposes
                    client_id: newAdmin.client_id,
                    role: newClientUser.role
                }
            }
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error creating client:', error);
        
        // Handle specific PostgreSQL errors
        if (error.code === '23505') { // Unique constraint violation
            return res.status(409).json({
                success: false,
                message: 'Client name or admin email already exists'
            });
        }
        
        if (error.code === '22001') { // String data too long
            return res.status(400).json({
                success: false,
                message: 'One of the fields is too long. Please check your input.'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Server error while creating client'
        });
    } finally {
        client.release();
    }
});

// Update client status (protected route)
app.patch('/api/clients/:clientId/status', authenticateToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        const { status } = req.body;
        
        if (typeof status !== 'boolean') {
            return res.status(400).json({
                success: false,
                message: 'Status must be true or false'
            });
        }
        
        const result = await users.query(`
            UPDATE clients 
            SET status = $1, updated_at = CURRENT_TIMESTAMP
            WHERE client_id = $2
            RETURNING client_id, client_name, status
        `, [status, clientId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Client not found'
            });
        }
        
        const updatedClient = result.rows[0];
        
        console.log(`🔄 Client status updated: ${updatedClient.client_name} -> ${status ? 'Active' : 'Inactive'}`);
        
        res.json({
            success: true,
            message: 'Client status updated successfully',
            data: updatedClient
        });
        
    } catch (error) {
        console.error('❌ Error updating client status:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while updating client status'
        });
    }
});

// Protected backoffice dashboard route
app.get('/backoffice/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'backoffice-dashboard.html'));
});

// Protected API endpoint to verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: req.users
    });
});

// Protected API endpoint for admin logout (optional)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    // In a stateless JWT setup, logout is handled client-side by removing the token
    console.log(`🔓 Admin logout: ${req.users.email}`);
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

// =============================================================================
// SHARED ROUTES
// =============================================================================

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Page not found'
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!'
    });
});

// Add this temporary debug route to your server.js (remove it later)
app.get('/api/debug/token', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    console.log('Debug - Auth Header:', authHeader);
    console.log('Debug - Extracted Token:', token);
    console.log('Debug - JWT Secret exists:', !!process.env.JWT_SECRET);
    
    if (!token) {
        return res.json({
            success: false,
            message: 'No token provided',
            authHeader: authHeader
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Debug - Token decoded successfully:', decoded);
        
        res.json({
            success: true,
            message: 'Token is valid',
            decoded: decoded
        });
    } catch (error) {
        console.log('Debug - Token verification failed:', error.message);
        
        res.json({
            success: false,
            message: 'Token verification failed',
            error: error.message
        });
    }
});

// Serve client login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'client-login.html'));
});
async function updateUserTableSchema() {
    try {
        // Check if only_assigned_tickets column exists
        const columnCheck = await users.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'only_assigned_tickets'
        `);
        
        if (columnCheck.rows.length === 0) {
            // Add the column
            await users.query(`
                ALTER TABLE users 
                ADD COLUMN only_assigned_tickets BOOLEAN DEFAULT false
            `);
            console.log('✅ Added only_assigned_tickets column to users table');
        }
        
        // Also check if branch_id column can store arrays (should be integer array or null)
        const branchColumnCheck = await users.query(`
            SELECT data_type, udt_name
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'branch_id'
        `);
        
        if (branchColumnCheck.rows.length > 0) {
            const dataType = branchColumnCheck.rows[0].data_type;
            // If it's not already an array type, alter it
            if (dataType !== 'ARRAY') {
                await users.query(`
                    ALTER TABLE users 
                    ALTER COLUMN branch_id TYPE integer[] USING 
                    CASE 
                        WHEN branch_id IS NULL THEN NULL 
                        ELSE ARRAY[branch_id]
                    END
                `);
                console.log('✅ Updated branch_id column to support arrays in users table');
            }
        }
        
    } catch (error) {
        console.error('❌ Error updating user table schema:', error);
    }
}

// Initialize databases and start server
async function startServer() {
    await testConnections();
    await initDatabase();
    await updateUserTableSchema(); // Add this line
    
    app.listen(PORT, () => {
        console.log(`🚀 FeedFast server running on port ${PORT}`);
        console.log(`📱 Local: http://localhost:${PORT}`);
        console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
        console.log(`🏠 Landing Page: http://localhost:${PORT}`);
        console.log(`🔒 Back Office: http://localhost:${PORT}/backoffice`);
        console.log(`👤 User Management: http://localhost:${PORT}/usermanagement`);
        console.log(`📄 File Upload: ${cloudinary ? 'Enabled' : 'Disabled (install cloudinary/multer)'}`);
    });
}

startServer().catch(console.error);

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('⏹️  SIGTERM received, shutting down gracefully');
    await mainPool.end();
    await users.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('⏹️  SIGINT received, shutting down gracefully');
    await mainPool.end();
    await users.end();
    process.exit(0);
});
