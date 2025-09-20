// Vulnerable Express.js application for testing DefenSys
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Vulnerable: Hardcoded secrets
const JWT_SECRET = "mysecretkey123";
const DB_PASSWORD = "admin123";

// Vulnerable: CORS misconfiguration
app.use(cors({
    origin: "*",  // Allows all origins
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,  // Hardcoded password
    database: 'vulnerable_app'
});

// Vulnerable: SQL Injection endpoints
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    // Vulnerable: Direct string concatenation
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Vulnerable: Template string injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else if (results.length > 0) {
            // Vulnerable: Weak JWT secret
            const token = jwt.sign({ userId: results[0].id }, JWT_SECRET);
            res.json({ token, user: results[0] });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// Vulnerable: XSS endpoints
app.get('/profile/:username', (req, res) => {
    const username = req.params.username;
    // Vulnerable: innerHTML assignment
    const html = `<h1>Welcome ${username}</h1><p>Your profile information</p>`;
    res.send(html);
});

app.post('/comment', (req, res) => {
    const { comment } = req.body;
    // Vulnerable: Direct output without sanitization
    res.send(`<div class="comment">${comment}</div>`);
});

// Vulnerable: File upload
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
    // Vulnerable: No file type validation
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    res.json({ 
        message: 'File uploaded successfully',
        filename: req.file.filename,
        originalname: req.file.originalname
    });
});

// Vulnerable: Command injection
app.post('/ping', (req, res) => {
    const { host } = req.body;
    // Vulnerable: Direct command execution
    const { exec } = require('child_process');
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: error.message });
        } else {
            res.json({ output: stdout });
        }
    });
});

// Vulnerable: Information disclosure
app.get('/debug', (req, res) => {
    // Vulnerable: Debug information in production
    res.json({
        environment: process.env.NODE_ENV,
        version: process.version,
        platform: process.platform,
        memory: process.memoryUsage(),
        uptime: process.uptime()
    });
});

// Vulnerable: Weak authentication
app.get('/admin', (req, res) => {
    // Vulnerable: No authentication check
    res.json({ 
        message: 'Admin panel',
        users: ['admin', 'user1', 'user2'],
        settings: { debug: true, maintenance: false }
    });
});

// Vulnerable: Path traversal
app.get('/files/:filename', (req, res) => {
    const filename = req.params.filename;
    // Vulnerable: Direct file access without validation
    const filePath = path.join(__dirname, 'uploads', filename);
    res.sendFile(filePath);
});

// Error handling
app.use((err, req, res, next) => {
    // Vulnerable: Verbose error messages
    res.status(500).json({ 
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method
    });
});

app.listen(PORT, () => {
    console.log(`Vulnerable app running on port ${PORT}`);
    console.log('⚠️  This application contains intentional vulnerabilities for testing purposes');
});

module.exports = app;
