const express = require('express');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Serve static files
app.use(express.static(__dirname));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API endpoint for email signup (for future use)
app.post('/api/signup', (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email is required' 
        });
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Please provide a valid email address' 
        });
    }
    
    // Here you would typically save to database
    console.log('New signup:', email);
    
    res.json({ 
        success: true, 
        message: 'Thank you for signing up! We\'ll be in touch soon.' 
    });
});

// API endpoint for contact form (for future use)
app.post('/api/contact', (req, res) => {
    const { name, email, message } = req.body;
    
    if (!name || !email || !message) {
        return res.status(400).json({ 
            success: false, 
            message: 'All fields are required' 
        });
    }
    
    // Here you would typically save to database or send email
    console.log('New contact form submission:', { name, email, message });
    
    res.json({ 
        success: true, 
        message: 'Thank you for your message! We\'ll get back to you soon.' 
    });
});

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

// Start server
app.listen(PORT, () => {
    console.log(`🚀 InsightX Landing Page server running on port ${PORT}`);
    console.log(`📱 Local: http://localhost:${PORT}`);
    console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Add this to your existing server.js or create a new file for the API endpoint

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Serve static files

// PostgreSQL connection
const pool = new Pool({
    connectionString: 'postgresql://postgres:VzelCGdDkFwXNCFQOIghaDyxxRBOrexK@centerbeam.proxy.rlwy.net:18520/railway',
    ssl: {
        rejectUnauthorized: false
    }
});

// Initialize database table
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS insightx_emails (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(50) DEFAULT 'landing_page'
            )
        `);
        console.log('Database table initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
    }
}

// Email validation function
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// API endpoint for email submission
app.post('/api/submit-email', async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        // Insert email into database
        const query = 'INSERT INTO insightx_emails (email) VALUES ($1) RETURNING id, created_at';
        const result = await pool.query(query, [email.toLowerCase().trim()]);

        console.log(`New email subscription: ${email}`);
        
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
        console.error('Error submitting email:', error);
        
        // Handle duplicate email error
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

// API endpoint to get all emails (for admin purposes)
app.get('/api/emails', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, email, created_at FROM insightx_emails ORDER BY created_at DESC'
        );
        
        res.json({
            success: true,
            count: result.rows.length,
            emails: result.rows
        });
    } catch (error) {
        console.error('Error fetching emails:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// API endpoint to get email statistics
app.get('/api/stats', async (req, res) => {
    try {
        const totalResult = await pool.query('SELECT COUNT(*) as total FROM insightx_emails');
        const todayResult = await pool.query(
            'SELECT COUNT(*) as today FROM insightx_emails WHERE DATE(created_at) = CURRENT_DATE'
        );
        const weekResult = await pool.query(
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
        console.error('Error fetching stats:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Serve the HTML file
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index-7.html');
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Initialize database and start server
const PORT = process.env.PORT || 3000;

initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`InsightX server running on port ${PORT}`);
        console.log(`Visit http://localhost:${PORT} to view the landing page`);
    });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down gracefully...');
    await pool.end();
    process.exit(0);
});
