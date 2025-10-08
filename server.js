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
        
        // Create users table with approval system
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
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                approved_by INT NULL,
                approved_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Users table created/verified");

        // Create admin users table (for DSP/SP who can approve)
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                official_id VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('dsp', 'sp') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Admin users table created/verified");

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

        // Create default admin users if they don't exist
        const [adminCount] = await promisePool.query("SELECT COUNT(*) as count FROM admin_users");
        if (adminCount[0].count === 0) {
            const adminPassword = await bcrypt.hash("admin123", 10);
            await promisePool.query(
                "INSERT INTO admin_users (official_id, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                ["DSP001", "Deputy Superintendent", "dsp@puducherry.police.in", adminPassword, "dsp"]
            );
            
            const spPassword = await bcrypt.hash("admin123", 10);
            await promisePool.query(
                "INSERT INTO admin_users (official_id, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                ["SP001", "Superintendent", "sp@puducherry.police.in", spPassword, "sp"]
            );
            console.log("✅ Default admin users created (DSP001/SP001 - password: admin123)");
        }

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

const requireAdmin = (req, res, next) => {
    if (!req.user || !['dsp', 'sp'].includes(req.user.role)) {
        return res.status(403).json({ 
            success: false, 
            message: "Access denied. Admin privileges required." 
        });
    }
    next();
};

// ========== REGISTRATION ENDPOINT (Requires Approval) ==========
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

        // Insert user with pending status
        const [result] = await promisePool.query(
            `INSERT INTO users (official_id, full_name, email, phone, password_hash, police_station, designation, role, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [official_id, full_name, email, phone, hashedPassword, police_station, designation, role || 'station_officer']
        );

        console.log("✅ User registered successfully - Pending approval:", email);

        res.json({
            success: true,
            message: "Registration submitted successfully! Your account is pending approval from higher authorities. You will be notified via email once approved."
        });

    } catch (err) {
        console.error("❌ Registration error:", err);
        res.status(500).json({
            success: false,
            message: "Network error. Please try again."
        });
    }
});

// ========== LOGIN ENDPOINT (Only for approved users) ==========
app.post("/api/auth/login", async (req, res) => {
    console.log("=== LOGIN ATTEMPT ===");

    try {
        const { official_id, password } = req.body;

        if (!official_id || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Official ID and password are required" 
            });
        }

        console.log("Searching for user with Official ID:", official_id);

        // First check in admin users
        const [adminResults] = await promisePool.query(
            "SELECT * FROM admin_users WHERE official_id = ?", 
            [official_id]
        );

        let user = null;
        let isAdmin = false;

        if (adminResults.length > 0) {
            user = adminResults[0];
            isAdmin = true;
            console.log("👮 Admin user found:", user.official_id);
        } else {
            // Check in regular users (only approved ones)
            const [userResults] = await promisePool.query(
                "SELECT * FROM users WHERE official_id = ? AND status = 'approved'", 
                [official_id]
            );

            if (userResults.length === 0) {
                return res.status(401).json({ 
                    success: false, 
                    message: "Invalid credentials or account pending approval" 
                });
            }

            user = userResults[0];
            console.log("✅ Approved user found:", user.official_id);
        }

        // Verify password
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid Official ID or password" 
            });
        }

        // Generate JWT token
        const tokenPayload = {
            id: user.id,
            official_id: user.official_id,
            email: user.email,
            name: user.full_name,
            role: user.role,
            isAdmin: isAdmin
        };

        if (!isAdmin) {
            tokenPayload.police_station = user.police_station;
            tokenPayload.designation = user.designation;
        }

        const token = jwt.sign(tokenPayload, SECRET, { expiresIn: "24h" });

        console.log("✅ Login successful for:", user.official_id);

        res.json({
            success: true,
            message: "Login successful!",
            token: token,
            user: {
                id: user.id,
                official_id: user.official_id,
                full_name: user.full_name,
                email: user.email,
                role: user.role,
                police_station: user.police_station,
                designation: user.designation,
                isAdmin: isAdmin
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

// ========== ADMIN ENDPOINTS ==========

// Get pending approvals
app.get("/api/admin/pending-approvals", authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [pendingUsers] = await promisePool.query(
            `SELECT id, official_id, full_name, email, phone, police_station, designation, role, created_at 
             FROM users WHERE status = 'pending' ORDER BY created_at DESC`
        );

        res.json({
            success: true,
            data: pendingUsers
        });

    } catch (error) {
        console.error("❌ Pending approvals error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// Approve/Reject user
app.post("/api/admin/approve-user", authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { user_id, action, remarks } = req.body;

        if (!user_id || !action) {
            return res.status(400).json({
                success: false,
                message: "User ID and action are required"
            });
        }

        const status = action === 'approve' ? 'approved' : 'rejected';
        
        await promisePool.query(
            'UPDATE users SET status = ?, approved_by = ?, approved_at = NOW() WHERE id = ?',
            [status, req.user.id, user_id]
        );

        // Get user email for notification (in real implementation, send email)
        const [users] = await promisePool.query(
            "SELECT email, full_name FROM users WHERE id = ?",
            [user_id]
        );

        if (users.length > 0) {
            console.log(`📧 Notification: User ${users[0].email} has been ${status}`);
            // Here you would integrate with your email service
        }

        res.json({
            success: true,
            message: `User ${status} successfully`
        });

    } catch (error) {
        console.error("❌ Approve user error:", error);
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
        if (req.user.isAdmin) {
            const [admins] = await promisePool.query(
                "SELECT official_id, full_name, email, role FROM admin_users WHERE id = ?",
                [req.user.id]
            );
            
            if (admins.length > 0) {
                return res.json({
                    success: true,
                    user: { ...admins[0], isAdmin: true }
                });
            }
        } else {
            const [users] = await promisePool.query(
                "SELECT official_id, full_name, email, phone, police_station, designation, role, status FROM users WHERE id = ?",
                [req.user.id]
            );
            
            if (users.length > 0) {
                return res.json({
                    success: true,
                    user: users[0]
                });
            }
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

// ========== ROOT ROUTE ==========
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Serve admin dashboard
app.get("/admin-dashboard.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
});

// Serve user dashboard
app.get("/dashboard.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`🔐 TCS CodeVita-style authentication system ready!`);
    console.log(`👮 Default Admin Credentials:`);
    console.log(`   - DSP: Official ID: DSP001, Password: admin123`);
    console.log(`   - SP: Official ID: SP001, Password: admin123`);
});
