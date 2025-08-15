const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

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

// Admin database (new)
const adminPool = new Pool({
    connectionString: process.env.ADMIN_DATABASE_URL, // You'll need to add this env variable
    ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
    } : false
});

// Test database connections
async function testConnections() {
    try {
        // Test main database
        const mainClient = await mainPool.connect();
        console.log('✅ Main database connected successfully');
        mainClient.release();
        
        // Test admin database
        const adminClient = await adminPool.connect();
        console.log('✅ Admin database connected successfully');
        adminClient.release();
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
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
        req.user = user;
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
        const userQuery = await adminPool.query(
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
// CLIENT MANAGEMENT ROUTES (Add these to your server.js)
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
        const result = await adminPool.query(`
            SELECT 
                client_id,
                client_name,
                total_branch,
                total_users,
                total_tickets,
                status,
                start_date,
                expiry_date,
                created_at
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

// Create new client with auto-generated super admin (protected route)
app.post('/api/clients', authenticateToken, async (req, res) => {
    const client = await adminPool.connect();
    
    try {
        await client.query('BEGIN');
        
        const { client_name, expiry_date } = req.body;
        
        if (!client_name || !expiry_date) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Client name and expiry date are required'
            });
        }
        
        // Check if client name already exists
        const existingClient = await client.query(
            'SELECT client_id FROM clients WHERE LOWER(client_name) = LOWER($1)',
            [client_name]
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
        
        // Check if admin email already exists
        const existingAdmin = await client.query(
            'SELECT user_id FROM adminbo WHERE email = $1',
            [adminEmail]
        );
        
        if (existingAdmin.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                message: `Admin email ${adminEmail} already exists. Please choose a different client name.`
            });
        }
        
        // Create client
        const clientResult = await client.query(`
            INSERT INTO clients (client_name, expiry_date)
            VALUES ($1, $2)
            RETURNING client_id, client_name, start_date, expiry_date, created_at
        `, [client_name, expiry_date]);
        
        const newClient = clientResult.rows[0];
        
        // Create super admin account for this client
        const defaultPassword = '12345678';
        const hashedPassword = await hashPassword(defaultPassword);
        
        const adminResult = await client.query(`
            INSERT INTO adminbo (name, email, password, client_id)
            VALUES ($1, $2, $3, $4)
            RETURNING user_id, name, email
        `, [`${client_name} Admin`, adminEmail, hashedPassword, newClient.client_id]);
        
        const newAdmin = adminResult.rows[0];
        
        await client.query('COMMIT');
        
        console.log(`✅ New client created: ${client_name} with admin: ${adminEmail}`);
        
        res.status(201).json({
            success: true,
            message: 'Client and admin account created successfully',
            data: {
                client: {
                    id: newClient.client_id,
                    name: newClient.client_name,
                    start_date: newClient.start_date,
                    expiry_date: newClient.expiry_date,
                    status: true,
                    total_branch: 0,
                    total_users: 0,
                    total_tickets: 0
                },
                admin: {
                    id: newAdmin.user_id,
                    name: newAdmin.name,
                    email: newAdmin.email,
                    password: defaultPassword // Only show in response for setup purposes
                }
            }
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error creating client:', error);
        
        if (error.code === '23505') {
            return res.status(409).json({
                success: false,
                message: 'Client with this name already exists'
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
        
        const result = await adminPool.query(`
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
        
        console.log(`📝 Client status updated: ${updatedClient.client_name} -> ${status ? 'Active' : 'Inactive'}`);
        
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
        user: req.user
    });
});

// Protected API endpoint for admin logout (optional)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    // In a stateless JWT setup, logout is handled client-side by removing the token
    console.log(`🔓 Admin logout: ${req.user.email}`);
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

// Initialize databases and start server
async function startServer() {
    await testConnections();
    await initDatabase();
    
    app.listen(PORT, () => {
        console.log(`🚀 FeedFast server running on port ${PORT}`);
        console.log(`📱 Local: http://localhost:${PORT}`);
        console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
        console.log(`🏠 Landing Page: http://localhost:${PORT}`);
        console.log(`🔐 Back Office: http://localhost:${PORT}/backoffice`);
    });
}

startServer().catch(console.error);

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('⏹️  SIGTERM received, shutting down gracefully');
    await mainPool.end();
    await adminPool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('⏹️  SIGINT received, shutting down gracefully');
    await mainPool.end();
    await adminPool.end();
    process.exit(0);
});
