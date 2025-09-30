const mysql = require('mysql2');

// Use the DATABASE_URL from environment variables
const connection = mysql.createConnection(process.env.DATABASE_URL);

console.log('Attempting to connect to database...');
console.log('Host: caboose.proxy.rlwy.net');
console.log('Port: 18928');
console.log('Database: railway');

connection.connect((error) => {
  if (error) {
    console.log('Database connection failed:', error.message);
    console.log('Error details:', error);
  } else {
    console.log('✅ Database connected successfully!');
    
    // Test the connection with a simple query
    connection.execute('SELECT 1 + 1 AS result', (err, results) => {
      if (err) {
        console.log('Query test failed:', err.message);
      } else {
        console.log('✅ Database query test successful:', results);
      }
    });
  }
});

// Handle connection errors
connection.on('error', (err) => {
  console.log('Database error:', err);
});

module.exports = connection;
