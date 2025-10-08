const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const Docxtemplater = require("docxtemplater");
const PizZip = require("pizzip");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const SECRET = process.env.JWT_SECRET || "police_chargesheet_secret_2024";
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
        
        // Create users table with 2FA support
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                official_id VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                police_station VARCHAR(255) NOT NULL,
                designation VARCHAR(255) NOT NULL,
                role ENUM('station_officer', 'dsp', 'sp', 'investigating_officer') DEFAULT 'station_officer',
                two_factor_secret VARCHAR(255),
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Users table created/verified");

        // Create charge_sheets table
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS charge_sheets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                form_type VARCHAR(100) NOT NULL,
                form_data JSON NOT NULL,
                created_by INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        `);
        console.log("✅ Charge sheets table created/verified");

        console.log("🎉 Database initialization completed successfully!");
        
    } catch (error) {
        console.error("❌ Database initialization failed:", error.message);
        console.error("Error details:", error);
    }
}

// Initialize database when server starts
initializeDatabase();

// ========== AUTHENTICATION MIDDLEWARE ==========
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: "Access token required" });
    }

    jwt.verify(token, SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: "Invalid or expired token" });
        }
        req.user = user;
        next();
    });
};

// ========== REGISTRATION ENDPOINT (Direct registration - No approval needed) ==========
app.post("/api/auth/register", async (req, res) => {
    console.log("=== REGISTRATION REQUEST ===");
    console.log("Request body:", req.body);

    try {
        const { 
            official_id, 
            full_name, 
            email, 
            phone, 
            password, 
            police_station, 
            designation, 
            role 
        } = req.body;

        // Validate all required fields
        if (!official_id || !full_name || !email || !phone || !password || !police_station || !designation) {
            return res.status(400).json({ 
                success: false, 
                message: "All fields are required" 
            });
        }

        // Check if user already exists
        const [existingUsers] = await promisePool.query(
            "SELECT id FROM users WHERE email = ? OR official_id = ? OR phone = ?",
            [email, official_id, phone]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: "Email, Official ID or Phone number already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate 2FA secret
        const twoFactorSecret = speakeasy.generateSecret({
            name: `Puducherry Police (${official_id})`,
            issuer: "Puducherry Police Department"
        });

        // Insert user with 2FA secret
        const [result] = await promisePool.query(
            `INSERT INTO users (official_id, full_name, email, phone, password_hash, police_station, designation, role, two_factor_secret) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [official_id, full_name, email, phone, hashedPassword, police_station, designation, role || 'station_officer', twoFactorSecret.base32]
        );

        console.log("✅ User registered successfully:", email);

        // Generate QR code for 2FA setup
        const qrCodeUrl = await QRCode.toDataURL(twoFactorSecret.otpauth_url);

        res.json({
            success: true,
            message: "Registration successful! Please setup 2FA using the QR code.",
            qrCode: qrCodeUrl,
            secret: twoFactorSecret.base32, // For manual entry
            user_id: result.insertId
        });

    } catch (err) {
        console.error("❌ Registration error:", err);
        res.status(500).json({
            success: false,
            message: "Network error. Please try again."
        });
    }
});

// ========== VERIFY 2FA SETUP ==========
app.post("/api/auth/verify-2fa-setup", async (req, res) => {
    try {
        const { user_id, token } = req.body;

        if (!user_id || !token) {
            return res.status(400).json({
                success: false,
                message: "User ID and token are required"
            });
        }

        // Get user's 2FA secret
        const [users] = await promisePool.query(
            "SELECT two_factor_secret FROM users WHERE id = ?",
            [user_id]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const twoFactorSecret = users[0].two_factor_secret;

        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: twoFactorSecret,
            encoding: 'base32',
            token: token,
            window: 1 // Allow 1 step (30 seconds) before/after
        });

        if (verified) {
            // Enable 2FA for user
            await promisePool.query(
                "UPDATE users SET two_factor_enabled = TRUE WHERE id = ?",
                [user_id]
            );

            res.json({
                success: true,
                message: "2FA setup successfully! You can now login with your authenticator app."
            });
        } else {
            res.status(400).json({
                success: false,
                message: "Invalid verification code. Please try again."
            });
        }

    } catch (error) {
        console.error("❌ 2FA setup verification error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// ========== LOGIN ENDPOINT (Step 1: Verify Password) ==========
app.post("/api/auth/login", async (req, res) => {
    console.log("=== LOGIN ATTEMPT (Step 1) ===");

    try {
        const { official_id, password } = req.body;

        if (!official_id || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Official ID and password are required" 
            });
        }

        console.log("Searching for user with Official ID:", official_id);

        // Check user
        const [userResults] = await promisePool.query(
            "SELECT * FROM users WHERE official_id = ?", 
            [official_id]
        );

        if (userResults.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid Official ID or password" 
            });
        }

        const user = userResults[0];

        // Verify password
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid Official ID or password" 
            });
        }

        console.log("✅ Password correct, 2FA required for:", user.official_id);

        // Check if 2FA is enabled
        if (!user.two_factor_enabled) {
            return res.status(400).json({
                success: false,
                message: "Please complete 2FA setup first. Visit the setup page."
            });
        }

        // Generate temporary token for 2FA verification
        const tempToken = jwt.sign(
            { 
                id: user.id,
                step: '2fa_required'
            }, 
            SECRET, 
            { expiresIn: '5m' } // 5 minutes expiry
        );

        res.json({
            success: true,
            message: "Please enter your 2FA code from authenticator app",
            requires2FA: true,
            tempToken: tempToken,
            user: {
                id: user.id,
                official_id: user.official_id,
                full_name: user.full_name
            }
        });

    } catch (err) {
        console.error("❌ Login error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Network error. Please try again." 
        });
    }
});

// ========== VERIFY 2FA LOGIN (Step 2: Verify 2FA Code) ==========
app.post("/api/auth/verify-2fa-login", async (req, res) => {
    try {
        const { tempToken, twoFACode } = req.body;

        if (!tempToken || !twoFACode) {
            return res.status(400).json({
                success: false,
                message: "Temporary token and 2FA code are required"
            });
        }

        // Verify temporary token
        let decoded;
        try {
            decoded = jwt.verify(tempToken, SECRET);
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Session expired. Please login again."
            });
        }

        if (decoded.step !== '2fa_required') {
            return res.status(401).json({
                success: false,
                message: "Invalid token"
            });
        }

        // Get user's 2FA secret
        const [users] = await promisePool.query(
            "SELECT two_factor_secret, official_id, full_name, email, role, police_station, designation FROM users WHERE id = ?",
            [decoded.id]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const user = users[0];

        // Verify 2FA code
        const verified = speakeasy.totp.verify({
            secret: user.two_factor_secret,
            encoding: 'base32',
            token: twoFACode,
            window: 1 // Allow 1 step (30 seconds) before/after
        });

        if (!verified) {
            return res.status(401).json({
                success: false,
                message: "Invalid 2FA code. Please try again."
            });
        }

        // Generate final JWT token
        const finalToken = jwt.sign(
            { 
                id: user.id,
                official_id: user.official_id,
                email: user.email,
                name: user.full_name,
                role: user.role,
                police_station: user.police_station,
                designation: user.designation
            },
            SECRET,
            { expiresIn: "24h" }
        );

        console.log("✅ 2FA verified, login successful for:", user.official_id);

        res.json({
            success: true,
            message: "Login successful!",
            token: finalToken,
            user: {
                id: user.id,
                official_id: user.official_id,
                full_name: user.full_name,
                email: user.email,
                role: user.role,
                police_station: user.police_station,
                designation: user.designation
            }
        });

    } catch (error) {
        console.error("❌ 2FA login verification error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// ========== USER PROFILE & VERIFICATION ==========

// Verify token
app.get("/api/auth/verify", authenticateToken, async (req, res) => {
    try {
        res.json({
            success: true,
            user: req.user
        });
    } catch (error) {
        console.error("❌ Token verification error:", error);
        res.status(401).json({
            success: false,
            message: "Invalid token"
        });
    }
});

// Get user profile
app.get("/api/auth/profile", authenticateToken, async (req, res) => {
    try {
        const [users] = await promisePool.query(
            "SELECT official_id, full_name, email, phone, police_station, designation, role, two_factor_enabled FROM users WHERE id = ?",
            [req.user.id]
        );
        
        if (users.length > 0) {
            return res.json({
                success: true,
                user: users[0]
            });
        }

        res.status(404).json({
            success: false,
            message: "User not found"
        });

    } catch (error) {
        console.error("❌ Profile error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// ========== EXISTING ROUTES ==========
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

// ========== SERVE STATIC PAGES ==========
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/setup-2fa.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "setup-2fa.html"));
});

app.get("/dashboard.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/verify-2fa.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "verify-2fa.html"));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`🔐 2FA Authentication System Ready!`);
    console.log(`📱 Users need to scan QR code with Google Authenticator/Microsoft Authenticator`);
});
