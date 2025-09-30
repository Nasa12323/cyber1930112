USE ips_charge_system_db;

-- Drop the existing table (this will delete any existing data)
DROP TABLE IF EXISTS users;

-- Create the table with correct structure including ALL columns
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Verify the table structure
DESCRIBE users;

-- Show the table to confirm it's created
SHOW TABLES;