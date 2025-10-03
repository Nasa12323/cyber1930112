const mysql = require('mysql2');

// Create a connection pool instead of single connection
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'caboose.proxy.rlwy.net',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'KdWeKnVKYPpQEzKKscqLcJcwxvfKpLeN',
  database: process.env.DB_NAME || 'railway',
  port: process.env.DB_PORT || 18928,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
});

// Get promise-based version of the pool
const promisePool = pool.promise();

console.log('✅ Database connection pool created');

// Test the connection
promisePool.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully via pool');
    connection.release(); // release the connection back to the pool
  })
  .catch(err => {
    console.log('❌ Database connection failed:', err.message);
  });

// Handle pool errors
pool.on('error', (err) => {
  console.log('Database pool error:', err);
});

module.exports = promisePool;
