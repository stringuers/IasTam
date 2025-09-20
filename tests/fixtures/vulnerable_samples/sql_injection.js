// SQL Injection vulnerabilities for testing

const express = require('express');
const mysql = require('mysql');
const app = express();

// Vulnerable: Direct string concatenation
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    mysql.query(query, (err, results) => {
        res.json(results);
    });
});

// Vulnerable: Template string injection
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    mysql.query(query, (err, results) => {
        if (results.length > 0) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    });
});

// Vulnerable: String formatting
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    mysql.query(query, (err, results) => {
        res.json(results);
    });
});

// Safe: Parameterized query (should not trigger)
app.get('/safe-users/:id', (req, res) => {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = ?";
    mysql.query(query, [userId], (err, results) => {
        res.json(results);
    });
});

// Vulnerable: Dynamic table name
app.get('/table/:tableName', (req, res) => {
    const tableName = req.params.tableName;
    const query = `SELECT * FROM ${tableName}`;
    mysql.query(query, (err, results) => {
        res.json(results);
    });
});

module.exports = app;
