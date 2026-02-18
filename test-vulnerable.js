// Test file with intentional issues for demonstrating Li Code Review

const express = require('express');
const app = express();

// SQL Injection vulnerability
app.get('/user', (req, res) => {
    const userId = req.query.id;
    db.query(`SELECT * FROM users WHERE id = ${userId}`);
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const q = req.query.q;
    document.getElementById('results').innerHTML = q;
});

// Eval usage
function processInput(data) {
    return eval(data);
}

// Hardcoded secret (redacted for demo purposes)
const api_key = "REPLACE_WITH_YOUR_REAL_KEY_NEVER_HARDCODE";

// Empty catch block
try {
    JSON.parse(data);
} catch (e) {}

// Loose equality
if (userId == null) {
    console.log("no user");
}

// Synchronous I/O
const config = require('fs').readFileSync('./config.json');

// N+1 query pattern
async function getUsers(ids) {
    for (const id of ids) {
        const user = await db.find({ id });
        results.push(user);
    }
}
