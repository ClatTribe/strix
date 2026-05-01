"""Minimal Flask app with planted vulnerabilities.

This file is a benchmark fixture, not real code. Each route below contains
a deliberate, well-known security flaw. The line numbers of the planted
issues are pinned in expected.yaml — keep this file's line layout stable
when editing or update the manifest.
"""

import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
import urllib.request

from flask import Flask, redirect, request, session


app = Flask(__name__)

# Planted bug 1 (CWE-798): hardcoded secret in source. The literal below is
# a deliberately-fake high-entropy string for the benchmark — never a real key.
API_KEY = "BENCHMARK_FAKE_KEY_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
app.secret_key = "static-secret-change-me"

DB_PATH = "/tmp/bench.db"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            password_hash TEXT
        );
        INSERT OR IGNORE INTO users(id, name, email, password_hash)
        VALUES (1, 'alice', 'alice@example.com', 'fake'),
               (2, 'bob', 'bob@example.com', 'fake');
        """
    )
    conn.commit()
    conn.close()


@app.route("/search")
def search():
    # Planted bug 2 (CWE-89): SQL injection via string-formatted query.
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        f"SELECT id, name, email FROM users WHERE name = '{name}'"
    ).fetchall()
    conn.close()
    return {"results": rows}


@app.route("/ping")
def ping():
    # Planted bug 3 (CWE-78): OS command injection via shell=True.
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return {"stdout": out.stdout, "stderr": out.stderr}


@app.route("/fetch")
def fetch():
    # Planted bug 4 (CWE-918): SSRF — unrestricted user-controlled URL fetch.
    target = request.args.get("url", "")
    with urllib.request.urlopen(target, timeout=5) as r:
        return {"status": r.status, "body": r.read(4096).decode(errors="replace")}


@app.route("/api/users/<int:user_id>")
def get_user(user_id: int):
    # Planted bug 5 (CWE-639): IDOR — no check that session user owns this id.
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return {"user": row}


@app.route("/hello")
def hello():
    # Planted bug 6 (CWE-79): reflected XSS — unescaped user input echoed in HTML.
    name = request.args.get("name", "world")
    return f"<h1>Hello {name}</h1><p>Welcome.</p>"


@app.route("/restore", methods=["POST"])
def restore():
    # Planted bug 7 (CWE-502): insecure deserialization — pickle on user input.
    blob = request.form.get("state", "")
    state = pickle.loads(base64.b64decode(blob))
    return {"restored": str(state)}


@app.route("/files")
def files():
    # Planted bug 8 (CWE-22): path traversal — no sanitization of filename.
    filename = request.args.get("name", "readme.txt")
    full = os.path.join("uploads", filename)
    with open(full, "rb") as f:
        return f.read(), 200, {"Content-Type": "application/octet-stream"}


@app.route("/login")
def login_redirect():
    # Planted bug 9 (CWE-601): open redirect — user-controlled `next` is followed.
    next_url = request.args.get("next", "/")
    session["user_id"] = 1
    return redirect(next_url)


@app.route("/register", methods=["POST"])
def register():
    # Planted bug 10 (CWE-327): weak crypto — MD5 used for password hashing.
    name = request.form["name"]
    password = request.form["password"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO users(name, email, password_hash) VALUES (?, ?, ?)",
        (name, f"{name}@example.com", pw_hash),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
