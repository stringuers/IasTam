// XSS vulnerabilities for testing

const express = require('express');
const app = express();

// Vulnerable: innerHTML assignment
app.get('/profile/:username', (req, res) => {
    const username = req.params.username;
    const html = `<h1>Welcome ${username}</h1>`;
    document.getElementById('content').innerHTML = html;
    res.send('Profile loaded');
});

// Vulnerable: document.write
app.get('/search', (req, res) => {
    const query = req.query.q;
    const script = `<script>document.write("Search results for: ${query}");</script>`;
    res.send(script);
});

// Vulnerable: eval usage
app.post('/execute', (req, res) => {
    const code = req.body.code;
    const result = eval(code);
    res.json({ result });
});

// Vulnerable: setTimeout with string
app.get('/delayed', (req, res) => {
    const message = req.query.message;
    setTimeout(`alert("${message}")`, 1000);
    res.send('Delayed execution');
});

// Vulnerable: Function constructor
app.post('/dynamic', (req, res) => {
    const funcBody = req.body.function;
    const func = new Function(funcBody);
    const result = func();
    res.json({ result });
});

// Safe: textContent usage (should not trigger)
app.get('/safe-profile/:username', (req, res) => {
    const username = req.params.username;
    const element = document.getElementById('username');
    element.textContent = username;
    res.send('Profile loaded safely');
});

// Vulnerable: dangerouslySetInnerHTML (React)
app.get('/react-component', (req, res) => {
    const userInput = req.query.input;
    const jsx = `
        <div dangerouslySetInnerHTML={{__html: "${userInput}"}} />
    `;
    res.send(jsx);
});

module.exports = app;
