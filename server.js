const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const Docxtemplater = require("docxtemplater");
const PizZip = require("pizzip");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const SECRET = "supersecretkey";
const promisePool = require("./config/database");

const recordsFile = path.join(__dirname, "records.json");

// Helper functions
function readRecords() {
    if (!fs.existsSync(recordsFile)) return [];
    const data = fs.readFileSync(recordsFile);
    return JSON.parse(data);
}

function writeRecords(records) {
    fs.writeFileSync(recordsFile, JSON.stringify(records, null, 2));
}

// ========== DATABASE INITIALIZATION ==========
async function initializeDatabase() {
    try {
        console.log("🔄 Initializing database tables...");
        
        // Test database connection first using the pool
        const [testResult] = await promisePool.query("SELECT 1 + 1 AS result");
        console.log("✅ Database connection test passed:", testResult[0].result);
        
        // Create users table
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Users table created/verified");

        // Create charge_sheets table
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS charge_sheets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                form_type VARCHAR(100) NOT NULL,
                form_data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Charge sheets table created/verified");

        // Create additional tables
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS fir_records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fir_number VARCHAR(100) UNIQUE NOT NULL,
                police_station VARCHAR(255) NOT NULL,
                complainant_name VARCHAR(255) NOT NULL,
                accused_name VARCHAR(255),
                incident_date DATE,
                description TEXT,
                status VARCHAR(50) DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ FIR records table created/verified");

        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS case_hearings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                case_id INT,
                hearing_date DATE,
                next_hearing_date DATE,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Case hearings table created/verified");

        // Create a test user if no users exist
        const [users] = await promisePool.query("SELECT COUNT(*) as count FROM users");
        if (users[0].count === 0) {
            const testPassword = await bcrypt.hash("test123", 10);
            await promisePool.query(
                "INSERT INTO users (full_name, email, phone, password_hash) VALUES (?, ?, ?, ?)",
                ["Test User", "test@example.com", "1234567890", testPassword]
            );
            console.log("✅ Test user created (email: test@example.com, password: test123)");
        }

        console.log("🎉 Database initialization completed successfully!");
        
    } catch (error) {
        console.error("❌ Database initialization failed:", error.message);
        console.error("Error details:", error);
    }
}

// Initialize database when server starts
initializeDatabase();

// ========== DATABASE SETUP ENDPOINT ==========
app.post("/api/setup-database", async (req, res) => {
    try {
        console.log("Setting up database tables...");

        await promisePool.promise().query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("Users table created/verified");

        await promisePool.promise().query(`
            CREATE TABLE IF NOT EXISTS charge_sheets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                form_type VARCHAR(100) NOT NULL,
                form_data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("Charge sheets table created/verified");

        res.json({ success: true, message: "Database tables created successfully" });
    } catch (err) {
        console.error("Database setup error:", err);
        res.status(500).json({ success: false, message: "Error: " + err.message });
    }
});

// ========== CHECK USERS ENDPOINT ==========
app.get("/api/auth/check-users", async (req, res) => {
    try {
        const [tables] = await promisePool.promise().query("SHOW TABLES LIKE 'users'");

        if (tables.length === 0) {
            return res.json({ success: false, message: "Users table does not exist" });
        }

        const [columns] = await promisePool.promise().query("DESCRIBE users");
        const [users] = await promisePool.promise().query("SELECT COUNT(*) as count FROM users");
        const [userList] = await promisePool.promise().query(
            "SELECT id, full_name, email, phone, created_at FROM users LIMIT 5"
        );

        res.json({
            success: true,
            tableExists: true,
            totalUsers: users[0].count,
            tableStructure: columns,
            sampleUsers: userList
        });
    } catch (err) {
        console.error("Check users error:", err);
        res.status(500).json({ success: false, message: "Error: " + err.message });
    }
});

// ========== CREATE TEST USER ==========
app.post("/api/auth/create-test-user", async (req, res) => {
    try {
        const testEmail = "test@example.com";
        const testPassword = "test123";

        const [existing] = await promisePool.promise().query("SELECT id FROM users WHERE email=?", [testEmail]);
        if (existing.length > 0) {
            return res.json({ success: false, message: "Test user already exists" });
        }

        const hashedPassword = await bcrypt.hash(testPassword, 10);
        await promisePool.promise().query(
            "INSERT INTO users (full_name, email, phone, password_hash) VALUES (?,?,?,?)",
            ["Test User", testEmail, "1234567890", hashedPassword]
        );

        res.json({
            success: true,
            message: "Test user created",
            credentials: { email: testEmail, password: testPassword }
        });
    } catch (err) {
        console.error("Create test user error:", err);
        res.status(500).json({ success: false, message: "Error: " + err.message });
    }
});

// ========== LOGIN ENDPOINT ==========
app.post("/api/auth/login", async (req, res) => {
    console.log("=== LOGIN ATTEMPT ===");
    console.log("Request body:", req.body);

    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }

        console.log("Searching for user:", email);
        const [results] = await promisePool.promise().query("SELECT * FROM users WHERE email=?", [email]);
        console.log("Query results length:", results.length);

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const user = results[0];
        console.log("User found:", { id: user.id, email: user.email });

        const match = await bcrypt.compare(password, user.password_hash);
        console.log("Password match result:", match);

        if (!match) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "1h" });

        console.log("Login successful for user:", user.email);
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email
            }
        });
    } catch (err) {
        console.error("Login error details:", err);
        res.status(500).json({ success: false, message: "Network error. Please try again." });
    }
});

// ========== REGISTRATION ENDPOINT ==========
app.post("/api/auth/register", async (req, res) => {
    console.log("=== REGISTRATION ATTEMPT ===");
    console.log("Request body:", req.body);

    try {
        const { fullName, email, phone, password } = req.body;

        // Validate input
        if (!fullName || !email || !phone || !password) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        // Check if user already exists
        const [existingUsers] = await promisePool.promise().query(
            "SELECT id FROM users WHERE email = ? OR phone = ?",
            [email, phone]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: "Email or phone number already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user
        const [result] = await promisePool.promise().query(
            "INSERT INTO users (full_name, email, phone, password_hash) VALUES (?, ?, ?, ?)",
            [fullName, email, phone, hashedPassword]
        );

        console.log("User registered successfully:", email);
        res.json({
            success: true,
            message: "Registration successful! You can now login."
        });

    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({
            success: false,
            message: "Network error. Please try again."
        });
    }
});

// ========== OTHER ROUTES ==========
app.get("/api/records/:id", (req, res) => {
    try {
        const { id } = req.params;
        const records = readRecords();
        const record = records.find(r => String(r.id) === String(id));

        if (!record) {
            return res.status(404).json({ message: "Record not found" });
        }

        res.json(record);
    } catch (err) {
        console.error("Records error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/api/records", (req, res) => {
    try {
        const records = readRecords();
        const newRecord = {
            id: Date.now(),
            type: req.body.type || "Unknown",
            date: req.body.date || new Date().toLocaleDateString(),
            policeStation: req.body.policeStation || "",
            officerName: req.body.officerName || "",
            previewHTML: req.body.previewHTML || ""
        };

        records.push(newRecord);
        writeRecords(records);
        res.json({ message: "Record added", record: newRecord });
    } catch (err) {
        console.error("Add record error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// ========== ROOT ROUTE ==========
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
});
