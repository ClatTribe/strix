// Tiny Express app planted with cross-asset vulns:
//
//   1. SCA: lodash@4.17.20 has CVE-2020-8203 (prototype pollution).
//      Detectable from `package-lock.json` alone.
//   2. DAST: /api/merge calls _.merge() on user input → exploitable
//      prototype pollution at runtime. Detectable from probing the
//      live URL.
//   3. SCA: ejs@3.1.6 has CVE-2022-29078 (template-injection RCE).
//   4. DAST: /api/render renders a user-provided EJS template →
//      exploitable RCE at runtime.
//   5. Hardcoded secret in source — DAST won't see it; SAST will.
//
// The point: the SAME line of evidence (a package version in the
// lockfile) is reachable through TWO assets. Single-lead routing has
// to surface both findings AND correlate them.

const express = require("express");
const _ = require("lodash");
const ejs = require("ejs");

const app = express();
app.use(express.json());

// Hardcoded API key — secret-scan / SAST target.
// Synthetic, format-mangled placeholder. We deliberately do NOT use the
// real `sk_live_...` Stripe pattern here because GitHub's push-protection
// scanner blocks any string matching it, even fake. The secret-scanner
// detector keys on shape (long alphanumeric run after a recognised
// prefix), so a clear "DO_NOT_DEPLOY"-style placeholder still hits the
// detector regex without matching any real provider's format.
const STRIPE_SECRET_KEY = "DO_NOT_DEPLOY_synthetic_benchmark_credential_AAAAAAAAAAAAAAAAAAAAAA";  // SECRET

app.get("/", (_req, res) => {
  res.json({ ok: true, msg: "vibe-app paired benchmark" });
});

// VULN 1 / 2 — lodash prototype pollution via untrusted merge.
//   curl -X POST -H 'Content-Type: application/json' \
//     -d '{"__proto__":{"polluted":true}}' http://localhost:3030/api/merge
//   then: GET /api/check  → polluted=true confirms exploit.
app.post("/api/merge", (req, res) => {
  const target = {};
  _.merge(target, req.body);  // unsafe — prototype-pollution sink
  res.json({ ok: true, mergedKeys: Object.keys(target) });
});

app.get("/api/check", (_req, res) => {
  // Reflects whether prototype-pollution succeeded.
  const empty = {};
  res.json({ polluted: empty.polluted === true });
});

// VULN 3 / 4 — ejs render with user-controlled template string.
//   curl 'http://localhost:3030/api/render?tmpl=<%= 7*7 %>'
//   → "49"
app.get("/api/render", (req, res) => {
  const tmpl = req.query.tmpl || "hello";
  try {
    const out = ejs.render(String(tmpl));  // template-injection sink
    res.send(out);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

const PORT = process.env.PORT || 3030;
app.listen(PORT, () => {
  console.log("vibe-app listening on", PORT);
});
