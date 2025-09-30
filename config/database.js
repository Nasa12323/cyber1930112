// backend/config/database.js
const mysql = require('mysql2');

// Create a connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Cyber@2263',
    database: process.env.DB_NAME || 'ips_charge_system_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Get a promise-based interface
const promisePool = pool.promise();

// Test the connection
promisePool.getConnection()
    .then(connection => {
        console.log('Connected to MySQL database successfully!');
        connection.release();
    })
    .catch(err => {
        console.error('Database connection failed:', err.message);
    });

module.exports = promisePool;