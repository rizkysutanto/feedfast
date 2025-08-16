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
            totalCount: adminPool.totalCount,
            idleCount: adminPool.idleCount,
            waitingCount: adminPool.waitingCount 
        });
        
        // Test database connection first
        try {
            await adminPool.query('SELECT 1 as test');
            console.log('✅ Database connection test passed');
        } catch (dbTestError) {
            console.error('❌ Database connection test failed:', dbTestError);
            throw new Error('Database connection failed');
        }
        
        // Find user in users table (client users)
        console.log('🔍 Executing user query...');
        const userQuery = await adminPool.query(
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
        await adminPool.query(
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
        const usersTest = await adminPool.query(`
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
        const clientsTest = await adminPool.query(`
            SELECT 
                client_id, 
                client_name, 
                status 
            FROM clients 
            LIMIT 5
        `);
        
        // Test 3: Test the JOIN query
        const joinTest = await adminPool.query(`
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
        
        req.user = user;
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
        user: req.user
    });
});

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

app.post('/api/clients', authenticateToken, async (req, res) => {
    const client = await adminPool.connect();
    
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

// Serve client login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'client-login.html'));
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
