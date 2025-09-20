// Authentication and authorization vulnerabilities for testing

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();

// Vulnerable: Hardcoded secrets
const JWT_SECRET = "mysecretkey123";
const API_KEY = "sk-1234567890abcdef";
const DATABASE_PASSWORD = "admin123";

// Vulnerable: Weak JWT secret
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const token = jwt.sign({ username }, "weaksecret", { expiresIn: '1h' });
    res.json({ token });
});

// Vulnerable: No password hashing
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    // Store password in plain text
    const user = { username, password };
    res.json({ message: 'User created' });
});

// Vulnerable: Weak password policy
app.post('/change-password', (req, res) => {
    const { newPassword } = req.body;
    if (newPassword.length >= 4) { // Too weak
        res.json({ message: 'Password updated' });
    } else {
        res.json({ error: 'Password too short' });
    }
});

// Vulnerable: No authentication check
app.get('/admin/users', (req, res) => {
    // Missing authentication middleware
    res.json({ users: ['admin', 'user1', 'user2'] });
});

// Vulnerable: Weak session management
app.post('/login-session', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'admin') {
        req.session.userId = 1; // No session timeout
        res.json({ message: 'Logged in' });
    }
});

// Vulnerable: JWT with no expiration
app.post('/login-jwt', (req, res) => {
    const { username, password } = req.body;
    const token = jwt.sign({ username }, JWT_SECRET); // No expiration
    res.json({ token });
});

// Vulnerable: Algorithm none
app.post('/login-none', (req, res) => {
    const { username, password } = req.body;
    const token = jwt.sign({ username }, JWT_SECRET, { algorithm: 'none' });
    res.json({ token });
});

// Safe: Proper authentication (should not trigger)
app.post('/secure-login', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Vulnerable: API key in URL
app.get('/api/data', (req, res) => {
    const apiKey = req.query.api_key;
    if (apiKey === API_KEY) {
        res.json({ data: 'sensitive data' });
    }
});

// Vulnerable: CORS misconfiguration
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

module.exports = app;
