const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const Docxtemplater = require("docxtemplater");
const PizZip = require("pizzip");
const { OAuth2Client } = require("google-auth-library");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const SECRET = process.env.JWT_SECRET || "supersecretkey";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || "http://localhost:8080";

const promisePool = require("./config/database");

const recordsFile = path.join(__dirname, "records.json");

// Initialize Google OAuth Client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Store pending approvals (in production, use Redis or database)
const pendingApprovals = new Map();

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
        
        // Create users table with Google OAuth support
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20),
                password_hash VARCHAR(255),
                google_id VARCHAR(255) UNIQUE,
                picture VARCHAR(500),
                role ENUM('station_officer', 'dsp', 'sp', 'investigating_officer') DEFAULT 'station_officer',
                police_station VARCHAR(255),
                designation VARCHAR(255),
                official_id VARCHAR(100) UNIQUE,
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                approved_by INT NULL,
                approved_at TIMESTAMP NULL,
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

        console.log("🎉 Database initialization completed successfully!");
        
    } catch (error) {
        console.error("❌ Database initialization failed:", error.message);
        console.error("Error details:", error);
    }
}

// Initialize database when server starts
initializeDatabase();

// ========== GOOGLE OAUTH ROUTES ==========

// Start Google OAuth flow
app.get("/api/auth/google", (req, res) => {
    const redirectUrl = process.env.NODE_ENV === 'production' 
        ? `${BASE_URL}/api/auth/google/callback`
        : 'http://localhost:8080/api/auth/google/callback';

    console.log('🔐 Starting Google OAuth with redirect:', redirectUrl);

    const url = googleClient.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
        ],
        redirect_uri: redirectUrl
    });
    
    res.redirect(url);
});

// Google OAuth callback
app.get("/api/auth/google/callback", async (req, res) => {
    try {
        const { code } = req.query;
        
        if (!code) {
            return res.redirect('/?error=no_code');
        }

        console.log('🔄 Received authorization code from Google');

        // Determine redirect URI based on environment
        const redirectUrl = process.env.NODE_ENV === 'production'
            ? `${BASE_URL}/api/auth/google/callback`
            : 'http://localhost:8080/api/auth/google/callback';

        // Exchange authorization code for tokens
        const { tokens } = await googleClient.getToken({
            code: code,
            redirect_uri: redirectUrl,
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET
        });
        
        console.log('✅ Successfully exchanged code for tokens');

        // Verify the ID token
        const ticket = await googleClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: GOOGLE_CLIENT_ID
        });
        
        const payload = ticket.getPayload();
        const { sub: googleId, email, name, picture } = payload;

        console.log('👤 User authenticated:', { email, name, googleId });

        // Check if user exists in database
        const [existingUsers] = await promisePool.query(
            "SELECT * FROM users WHERE google_id = ? OR email = ?", 
            [googleId, email]
        );

        if (existingUsers.length > 0) {
            const user = existingUsers[0];
            
            // Check if user is approved
            if (user.status !== 'approved') {
                return res.redirect('/?error=pending_approval');
            }

            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email,
                    name: user.full_name,
                    role: user.role
                },
                SECRET,
                { expiresIn: "24h" }
            );

            console.log('✅ Existing user, redirecting to dashboard');
            res.redirect(`${BASE_URL}/dashboard.html?token=${token}`);
            
        } else {
            // New user - store pending approval and redirect to profile completion
            const tempId = Math.random().toString(36).substring(2, 15);
            pendingApprovals.set(tempId, {
                googleId,
                email,
                name,
                picture,
                timestamp: Date.now()
            });

            console.log('🆕 New user, redirecting to profile completion');
            res.redirect(`${BASE_URL}/complete-profile.html?temp=${tempId}`);
        }
        
    } catch (error) {
        console.error('❌ Google OAuth error:', error);
        res.redirect(`${BASE_URL}/?error=auth_failed`);
    }
});

// Complete profile for new Google OAuth users
app.post("/api/auth/complete-profile", async (req, res) => {
    try {
        const { tempId, official_id, police_station, designation, role, phone } = req.body;
        
        console.log('📝 Completing profile for tempId:', tempId);

        // Get pending user data
        const pendingUser = pendingApprovals.get(tempId);
        if (!pendingUser) {
            return res.status(400).json({
                success: false,
                message: 'Session expired. Please try again.'
            });
        }

        // Check if official ID already exists
        const [existingOfficial] = await promisePool.query(
            "SELECT id FROM users WHERE official_id = ?",
            [official_id]
        );

        if (existingOfficial.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Official ID already registered'
            });
        }

        // Save user to database with pending status
        const [result] = await promisePool.query(
            `INSERT INTO users (google_id, email, full_name, picture, official_id, police_station, designation, role, phone, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [
                pendingUser.googleId,
                pendingUser.email,
                pendingUser.name,
                pendingUser.picture,
                official_id,
                police_station,
                designation,
                role,
                phone
            ]
        );

        // Clean up pending approval
        pendingApprovals.delete(tempId);

        console.log('✅ Profile saved, user ID:', result.insertId);

        res.json({
            success: true,
            message: 'Profile submitted for approval. You will be notified via email once approved by higher authorities.'
        });

    } catch (error) {
        console.error('❌ Complete profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Verify token endpoint
app.get("/api/auth/verify", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.json({ valid: false, message: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.json({ valid: false, message: 'Invalid token format' });
        }

        const decoded = jwt.verify(token, SECRET);
        
        // Get fresh user data from database
        const [users] = await promisePool.query(
            "SELECT id, full_name, email, role, police_station, designation, status FROM users WHERE id = ?",
            [decoded.id]
        );

        if (users.length === 0) {
            return res.json({ valid: false, message: 'User not found' });
        }

        const user = users[0];
        
        res.json({ 
            valid: true, 
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email,
                role: user.role,
                policeStation: user.police_station,
                designation: user.designation,
                status: user.status
            }
        });
        
    } catch (error) {
        console.error('❌ Token verification error:', error);
        res.json({ 
            valid: false, 
            message: 'Invalid token' 
        });
    }
});

// ========== EXISTING AUTH ENDPOINTS (UPDATED) ==========

// LOGIN ENDPOINT - Updated to check status
app.post("/api/auth/login", async (req, res) => {
    console.log("=== LOGIN ATTEMPT ===");
    console.log("Request body:", req.body);

    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }

        console.log("Searching for user:", email);
        const [results] = await promisePool.query(
            "SELECT * FROM users WHERE email = ? AND password_hash IS NOT NULL", 
            [email]
        );
        console.log("Query results length:", results.length);

        if (results.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid email or password. If you registered with Google, please use Google Sign In." 
            });
        }

        const user = results[0];
        
        // Check if user is approved
        if (user.status !== 'approved') {
            return res.status(401).json({
                success: false,
                message: "Your account is pending approval. Please contact administrator."
            });
        }

        console.log("User found:", { id: user.id, email: user.email, status: user.status });

        const match = await bcrypt.compare(password, user.password_hash);
        console.log("Password match result:", match);

        if (!match) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const token = jwt.sign({ 
            id: user.id, 
            email: user.email,
            role: user.role
        }, SECRET, { expiresIn: "24h" });

        console.log("Login successful for user:", user.email);
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email,
                role: user.role,
                policeStation: user.police_station,
                designation: user.designation
            }
        });
    } catch (err) {
        console.error("Login error details:", err);
        res.status(500).json({ success: false, message: "Network error. Please try again." });
    }
});

// REGISTRATION ENDPOINT - Updated for approval system
app.post("/api/auth/register", async (req, res) => {
    console.log("=== REGISTRATION ATTEMPT ===");
    console.log("Request body:", req.body);

    try {
        const { fullName, email, phone, password, official_id, police_station, designation, role } = req.body;

        // Validate input
        if (!fullName || !email || !phone || !password || !official_id || !police_station || !designation) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        // Check if user already exists
        const [existingUsers] = await promisePool.query(
            "SELECT id FROM users WHERE email = ? OR phone = ? OR official_id = ?",
            [email, phone, official_id]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: "Email, phone number or official ID already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user with pending status
        const [result] = await promisePool.query(
            "INSERT INTO users (full_name, email, phone, password_hash, official_id, police_station, designation, role, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            [fullName, email, phone, hashedPassword, official_id, police_station, designation, role || 'station_officer']
        );

        console.log("User registered successfully:", email);
        res.json({
            success: true,
            message: "Registration submitted for approval. You will be notified once approved by higher authorities."
        });

    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({
            success: false,
            message: "Network error. Please try again."
        });
    }
});

// ========== ADMIN APPROVAL ENDPOINTS ==========

// Get pending approvals (for DSP/SP roles)
app.get("/api/admin/pending-approvals", async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, message: "No token provided" });
        }

        const decoded = jwt.verify(token, SECRET);
        
        // Check if user has permission (DSP or SP)
        const [users] = await promisePool.query(
            "SELECT role FROM users WHERE id = ?",
            [decoded.id]
        );

        if (users.length === 0 || !['dsp', 'sp'].includes(users[0].role)) {
            return res.status(403).json({
                success: false,
                message: "Access denied. Only DSP/SP can approve registrations."
            });
        }

        const [pendingUsers] = await promisePool.query(
            `SELECT id, official_id, full_name, email, phone, role, police_station, designation, created_at 
             FROM users WHERE status = 'pending'`
        );

        res.json({
            success: true,
            data: pendingUsers
        });

    } catch (error) {
        console.error("Pending approvals error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// Approve/Reject user
app.post("/api/admin/approve-user", async (req, res) => {
    try {
        const { user_id, action } = req.body; // action: 'approve' or 'reject'
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ success: false, message: "No token provided" });
        }

        const decoded = jwt.verify(token, SECRET);
        
        // Check if user has permission
        const [users] = await promisePool.query(
            "SELECT role FROM users WHERE id = ?",
            [decoded.id]
        );

        if (users.length === 0 || !['dsp', 'sp'].includes(users[0].role)) {
            return res.status(403).json({
                success: false,
                message: "Access denied"
            });
        }

        const status = action === 'approve' ? 'approved' : 'rejected';
        
        await promisePool.query(
            'UPDATE users SET status = ?, approved_by = ?, approved_at = NOW() WHERE id = ?',
            [status, decoded.id, user_id]
        );

        res.json({
            success: true,
            message: `User ${status} successfully`
        });

    } catch (error) {
        console.error("Approve user error:", error);
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

// ========== ROOT ROUTE ==========
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Serve complete-profile page
app.get("/complete-profile.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "complete-profile.html"));
});

// Serve dashboard page
app.get("/dashboard.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`🌐 Production: ${BASE_URL}`);
    console.log(`🔐 Google OAuth: ${GOOGLE_CLIENT_ID ? '✅ Configured' : '❌ Not configured'}`);
});
