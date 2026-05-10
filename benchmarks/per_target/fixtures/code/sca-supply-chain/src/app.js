// Stub source for the supply-chain benchmark — keeps reachability
// honest: lodash + express are imported, the rest aren't (their
// status is reachability=unused). The benchmark scores the
// malicious + license findings; reachability is asserted in a
// different fixture (`sca-reachability/`).

const _ = require("lodash");
const express = require("express");

const app = express();
app.get("/", (_req, res) => res.send("ok"));
app.listen(process.env.PORT || 3030);
