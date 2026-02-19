// Test fixture with intentional vulnerabilities for scanner testing
// DO NOT use this code in production!

const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const app = express();

// Secret: AWS Access Key
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Secret: API Key
const apiKey = "sk_live_abcdef1234567890abcdef";
const api_key = "ABCDEF1234567890GHIJKL";

// Secret: Hardcoded password
const password = "SuperSecret123!@#";
const dbPassword = "MyDatabaseP@ssw0rd123";

// Secret: Connection string
const mongoUrl = "mongodb://admin:password123@production-server:27017/mydb";
const pgUrl = "postgres://user:pass@host:5432/db";

// Secret: JWT token
const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";

// Secret: Private key
const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds...
-----END RSA PRIVATE KEY-----`;

// OWASP: SQL Injection via concatenation
app.get('/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
});

// OWASP: SQL Injection via template literal
app.get('/search', (req, res) => {
  db.query(`SELECT * FROM products WHERE name LIKE '%${req.body.search}%'`);
});

// OWASP: XSS via innerHTML
function renderComment(comment) {
  document.getElementById('comments').innerHTML = comment;
}

// OWASP: XSS via dangerouslySetInnerHTML
function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// OWASP: Command Injection
app.post('/convert', (req, res) => {
  exec(`convert ${req.body.filename} output.pdf`, (err, stdout) => {
    res.send(stdout);
  });
});

// OWASP: Path Traversal
app.get('/file', (req, res) => {
  const filePath = path.join('/uploads', req.query.name);
  fs.readFileSync(filePath);
});

// OWASP: SSRF
app.get('/proxy', (req, res) => {
  fetch(req.query.url).then(r => r.text()).then(data => res.send(data));
});

// OWASP: CORS wildcard
app.use(require('cors')({ origin: '*' }));

// Code Pattern: eval
function processInput(input) {
  return eval(input);
}

// Code Pattern: Function constructor
const dynamicFn = new Function('x', 'return x * 2');

// Code Pattern: Weak crypto
function hashPassword(pwd) {
  return crypto.createHash('md5').update(pwd).digest('hex');
}

function weakHash(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// Code Pattern: Math.random for token generation
function generateToken() {
  return Math.random().toString(36);
}

// Code Pattern: Disabled TLS
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });

// Code Pattern: Sensitive data logging
function login(user, pass) {
  console.log("Login attempt with password:", pass);
  console.log("Using apiKey:", apiKey);
}

// Code Pattern: Hardcoded port
app.listen(3000, () => console.log('Running'));
