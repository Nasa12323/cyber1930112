// backend/routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const router = express.Router();

// User registration (for admin to create users)
router.post('/register', async (req, res) => {
    const { username, password, fullName, role, badgeNumber, station } = req.body;

    try {
        // Check if user already exists
        const [existingUsers] = await db.execute(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Username already exists'
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user
        const [result] = await db.execute(
            'INSERT INTO users (username, password, full_name, role, badge_number, station) VALUES (?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, fullName, role, badgeNumber, station]
        );

        res.json({
            success: true,
            message: 'User created successfully',
            userId: result.insertId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create user'
        });
    }
});

// User login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find user by username
        const [users] = await db.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const user = users[0];

        // Compare passwords
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Create session (in a real app, you'd use JWT or session cookies)
        // For simplicity, we'll just return user info (without password)
        const userInfo = {
            id: user.id,
            username: user.username,
            fullName: user.full_name,
            role: user.role,
            badgeNumber: user.badge_number,
            station: user.station
        };

        res.json({
            success: true,
            message: 'Login successful',
            user: userInfo
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});
// Add near the top with other imports
const PDFService = require('./services/pdfService');
const fs = require('fs');
const path = require('path');

// Create directory for generated PDFs if it doesn't exist
const pdfDir = path.join(__dirname, 'generated-pdfs');
if (!fs.existsSync(pdfDir)) {
    fs.mkdirSync(pdfDir);
}

// Professional PDF Generation endpoint
app.get('/api/generate-professional-pdf/:formType/:recordId', verifyToken, async (req, res) => {
    try {
        const { formType, recordId } = req.params;

        // Fetch the form data from database
        const [rows] = await db.execute(
            'SELECT * FROM charge_sheets WHERE id = ? AND created_by = ?',
            [recordId, req.userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Record not found' });
        }

        const record = rows[0];
        const formData = JSON.parse(record.form_data);

        // Generate unique filename with official naming convention
        const filename = `${formType}_${formData.firNo || recordId}_${Date.now()}.pdf`;
        const outputPath = path.join(pdfDir, filename);

        // Generate professional PDF based on form type
        let pdfPath;
        switch (formType) {
            case 'IIF-1':
                pdfPath = await PDFService.generateIIF1PDF(formData, outputPath);
                break;
            case 'IIF-2':
                pdfPath = await PDFService.generateIIF2PDF(formData, outputPath);
                break;
            case 'IIF-3':
                pdfPath = await PDFService.generateIIF3PDF(formData, outputPath);
                break;
            case 'IIF-4':
                pdfPath = await PDFService.generateIIF4PDF(formData, outputPath);
                break;
            case 'IIF-5':
                pdfPath = await PDFService.generateIIF5PDF(formData, outputPath);
                break;
            default:
                return res.status(400).json({ success: false, message: 'Invalid form type' });
        }

        // Send the PDF file with official filename
        res.download(pdfPath, filename, (err) => {
            if (err) {
                console.error('Error sending PDF:', err);
                res.status(500).json({ success: false, message: 'Failed to download PDF' });
            }
        });

    } catch (error) {
        console.error('PDF generation error:', error);
        res.status(500).json({ success: false, message: 'Failed to generate PDF' });
    }
});

// Word document generation endpoint (using HTML approach)
app.get('/api/generate-professional-word/:formType/:recordId', verifyToken, async (req, res) => {
    try {
        const { formType, recordId } = req.params;

        // Fetch the form data from database
        const [rows] = await db.execute(
            'SELECT * FROM charge_sheets WHERE id = ? AND created_by = ?',
            [recordId, req.userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Record not found' });
        }

        const record = rows[0];
        const formData = JSON.parse(record.form_data);

        // Generate HTML content with professional government styling
        const htmlContent = this.generateProfessionalFormHTML(formType, formData);

        // Set headers for Word document download
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        res.setHeader('Content-Disposition', `attachment; filename=${formType}_${formData.firNo || recordId}.docx`);

        // Send HTML that Word can open with professional styling
        res.send(this.wrapInProfessionalWordHTML(htmlContent));

    } catch (error) {
        console.error('Word generation error:', error);
        res.status(500).json({ success: false, message: 'Failed to generate Word document' });
    }
});

// Helper function to generate professional HTML for forms
function generateProfessionalFormHTML(formType, formData) {
    // This would generate the HTML representation of your form with professional styling
    return `
        <html>
        <head>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 0.5in; 
                    line-height: 1.4;
                    color: #000;
                }
                .header { 
                    text-align: center; 
                    border-bottom: 2px solid #000080; 
                    padding-bottom: 20px; 
                    margin-bottom: 30px; 
                }
                .header h1 {
                    color: #000080;
                    margin: 0;
                    font-size: 18pt;
                }
                .header h2 {
                    color: #000080;
                    margin: 5px 0;
                    font-size: 14pt;
                }
                .section { 
                    margin-bottom: 25px; 
                    page-break-inside: avoid;
                }
                .section-title { 
                    font-weight: bold; 
                    border-bottom: 1px solid #ccc; 
                    padding-bottom: 5px; 
                    margin-bottom: 15px; 
                    color: #000080;
                    font-size: 12pt;
                }
                .field { 
                    margin-bottom: 10px; 
                }
                .label { 
                    font-weight: bold; 
                    display: inline-block; 
                    width: 200px; 
                    vertical-align: top;
                }
                .value {
                    display: inline-block;
                    width: calc(100% - 220px);
                    vertical-align: top;
                }
                .signature-area {
                    margin-top: 50px;
                    page-break-inside: avoid;
                }
                .signature-line {
                    border-top: 1px solid #000;
                    width: 200px;
                    margin-top: 40px;
                }
                .footer {
                    margin-top: 50px;
                    font-size: 9pt;
                    color: #666;
                }
                @media print {
                    body { margin: 0.5in; }
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>GOVERNMENT OF INDIA</h1>
                <h2>MINISTRY OF HOME AFFAIRS</h2>
                <h2>${formType} - FIRST INFORMATION REPORT</h2>
            </div>
            
            <div class="section">
                <div class="section-title">1. BASIC INFORMATION</div>
                <div class="field"><span class="label">District:</span> <span class="value">${formData.district || 'Not specified'}</span></div>
                <div class="field"><span class="label">Police Station:</span> <span class="value">${formData.policeStation || 'Not specified'}</span></div>
                <div class="field"><span class="label">FIR No:</span> <span class="value">${formData.firNo || 'Not specified'}</span></div>
                <div class="field"><span class="label">Date:</span> <span class="value">${formData.firDate || 'Not specified'}</span></div>
            </div>
            
            <!-- Add more sections based on your form data -->
            
            <div class="signature-area">
                <div style="width: 45%; display: inline-block;">
                    <div class="signature-line"></div>
                    <div>Signature of Officer Incharge</div>
                    ${formData.officerName ? `<div>Name: ${formData.officerName}</div>` : ''}
                    ${formData.officerRank ? `<div>Rank: ${formData.officerRank}</div>` : ''}
                    ${formData.officerNo ? `<div>Badge No: ${formData.officerNo}</div>` : ''}
                </div>
                
                <div style="width: 45%; display: inline-block; margin-left: 5%;">
                    <div class="signature-line"></div>
                    <div>Signature of Complainant/Informant</div>
                </div>
            </div>
            
            <div class="footer">
                <p>Generated on: ${new Date().toLocaleString()}</p>
                <p>Official Use Only - Confidential</p>
            </div>
        </body>
        </html>
    `;
}

// Helper function to wrap HTML for Word compatibility with professional styling
function wrapInProfessionalWordHTML(html) {
    return `
        <html xmlns:o="urn:schemas-microsoft-com:office:office" 
              xmlns:w="urn:schemas-microsoft-com:office:word" 
              xmlns="http://www.w3.org/TR/REC-html40">
        <head>
            <meta charset="utf-8">
            <title>IPS Charge Sheet - Official Document</title>
            <!--[if gte mso 9]>
            <xml>
                <w:WordDocument>
                    <w:View>Print</w:View>
                    <w:Zoom>100</w:Zoom>
                    <w:DoNotOptimizeForBrowser/>
                </w:WordDocument>
            </xml>
            <![endif]-->
        </head>
        <body>
            ${html}
        </body>
        </html>
    `;
}

// Get current user info
router.get('/me', async (req, res) => {
    // This would normally check session/token
    // For now, we'll just return a placeholder
    res.json({
        success: true,
        user: {
            id: 1,
            username: 'demo',
            fullName: 'Demo User',
            role: 'officer',
            badgeNumber: '12345',
            station: 'Central Station'
        }
    });
});

module.exports = router;