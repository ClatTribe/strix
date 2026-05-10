// Tiny Express app — used to measure SCA reachability efficiency.
//
// Lockfile pins 6 vulnerable packages. App.js imports only 2 of
// them (lodash, ejs). The other 4 (express, ws, minimist, yargs)
// are in the lockfile but never imported from app.js.
//
// Wait — app.js *does* `require('express')` for the server.
// Re-read: import map is lodash + ejs + express. Three pkgs are
// truly unused (ws, minimist, yargs). So:
//
//   reachability=direct_import : 3  (lodash, ejs, express)
//   reachability=unused        : 3  (ws, minimist, yargs)
//
// With 6 high-severity CVEs seeded, raw scan shows 6 high
// findings. Reachability filtering demotes the 3 unused to low —
// 50% noise reduction on the high-severity tier.

const express = require("express");
const _ = require("lodash");
const ejs = require("ejs");

const app = express();

app.get("/", (_req, res) => {
  res.send(ejs.render("<p>hi <%= 'world' %></p>"));
});

app.post("/api/merge", (req, res) => {
  res.json(_.merge({}, req.body || {}));
});

app.listen(process.env.PORT || 3030);
