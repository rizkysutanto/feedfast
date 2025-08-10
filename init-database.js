const pool = require('./database');
const bcrypt = require('bcryptjs');

async function initializeDatabase() {
    try {
        console.log('🔄 Setting up database...');
        
        // Create the adminbo table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS adminbo (
                user_id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        console.log('✅ AdminBO table created');
        
        // Check if admin user already exists
        const existingAdmin = await pool.query(
            'SELECT * FROM adminbo WHERE email = $1',
            ['admin@feedfast.xyz']
        );
        
        if (existingAdmin.rows.length === 0) {
            // Create default admin user
            const hashedPassword = await bcrypt.hash('admin123', 10);
            
            await pool.query(
                'INSERT INTO adminbo (name, email, password) VALUES ($1, $2, $3)',
                ['Super Admin', 'admin@feedfast.xyz', hashedPassword]
            );
            
            console.log('✅ Default admin user created');
            console.log('📧 Email: admin@feedfast.xyz');
            console.log('🔑 Password: admin123');
            console.log('⚠️  Please change this password after first login!');
        } else {
            console.log('ℹ️  Admin user already exists');
        }
        
    } catch (error) {
        console.error('❌ Database setup error:', error);
    }
}

initializeDatabase();
