// SAST benchmark — each block intentionally trips one bundled
// strix-* rule. The expected.yaml manifest pairs the line numbers
// with the matching rule_id.

const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const _ = require("lodash");

const app = express();
app.use(express.json());

// VULN 1: hardcoded JWT secret (CWE-798).
const JWT_SECRET = "supersecret-jwt-do-not-deploy";

// VULN 2: permissive CORS with credentials (CWE-1004).
const cors = require("cors");
app.use(cors({ origin: "*", credentials: true }));

// VULN 3: SQL injection via template literal (CWE-89).
app.get("/api/users/:id", async (req, res) => {
  const db = req.app.get("db");
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

// VULN 4: path traversal via params (CWE-22).
app.get("/api/files/:name", (req, res) => {
  fs.readFile(req.params.name, "utf-8", (err, data) => {
    if (err) return res.status(500).send(err.message);
    res.send(data);
  });
});

// VULN 5: eval on user input (CWE-94).
app.post("/api/calc", (req, res) => {
  const result = eval(req.body.expr);
  res.json({ result });
});

// VULN 6: SSRF via fetch from user URL (CWE-918).
app.post("/api/fetch", async (req, res) => {
  const r = await fetch(req.body.url);
  res.send(await r.text());
});

// VULN 7: mass assignment (CWE-915).
app.post("/api/users", async (req, res) => {
  const User = req.app.get("User");
  const u = await User.create(req.body);
  res.json(u);
});

// VULN 8: insecure random for crypto (CWE-338).
function generateToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

app.listen(process.env.PORT || 3030);
