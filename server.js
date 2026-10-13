const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("node:crypto");
const { promisify } = require("node:util");

const app = express();
const PORT = Number(process.env.PORT) || 5000;

// -------------------- SERVER CONFIGURATION --------------------

app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

const db = new Database("brandshield.sqlite");
const scrypt = promisify(crypto.scrypt);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        explanation TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

const scanColumns = db.prepare("PRAGMA table_info(scans)").all();
if (!scanColumns.some(column => column.name === "user_id")) {
    db.exec("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)");
}

db.exec("CREATE INDEX IF NOT EXISTS scans_user_id_id ON scans(user_id, id DESC)");
db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Date.now());

const insertScan = db.prepare(`
    INSERT INTO scans (
        user_id, scan_type, target, risk_score, risk_level, explanation
    )
    VALUES (?, ?, ?, ?, ?, ?)
`);

const SESSION_COOKIE = "brandshield_session";
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
const authRateLimits = new Map();
let lastRateLimitCleanup = 0;

function hashSessionToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function getSessionToken(req) {
    const cookies = (req.headers.cookie || "").split(";");

    for (const cookie of cookies) {
        const separator = cookie.indexOf("=");
        if (separator < 0) continue;

        if (cookie.slice(0, separator).trim() === SESSION_COOKIE) {
            return cookie.slice(separator + 1).trim();
        }
    }

    return null;
}

function setSessionCookie(res, token) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader(
        "Set-Cookie",
        `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DURATION_MS / 1000}${secure}`
    );
}

function clearSessionCookie(res) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader(
        "Set-Cookie",
        `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`
    );
}

function requireAuth(req, res, next) {
    const token = getSessionToken(req);
    if (!token || !/^[A-Za-z0-9_-]{40,60}$/.test(token)) {
        return res.status(401).json({ error: "Please log in to continue." });
    }

    const session = db.prepare(`
        SELECT users.id, users.email
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(hashSessionToken(token), Date.now());

    if (!session) {
        return res.status(401).json({ error: "Your session has expired. Please log in again." });
    }

    req.user = session;
    return next();
}

function limitAuthAttempts(maxAttempts, windowMs) {
    return (req, res, next) => {
        const now = Date.now();
        const key = `${req.path}:${req.socket.remoteAddress || "unknown"}`;
        const recentAttempts = (authRateLimits.get(key) || [])
            .filter(timestamp => now - timestamp < windowMs);

        if (now - lastRateLimitCleanup >= 60 * 1000) {
            lastRateLimitCleanup = now;
            for (const [attemptKey, timestamps] of authRateLimits) {
                if (!timestamps.some(timestamp => now - timestamp < 60 * 60 * 1000)) {
                    authRateLimits.delete(attemptKey);
                }
            }
        }

        if (recentAttempts.length >= maxAttempts) {
            authRateLimits.set(key, recentAttempts);
            res.setHeader(
                "Retry-After",
                Math.ceil((windowMs - (now - recentAttempts[0])) / 1000)
            );
            return res.status(429).json({
                error: "Too many attempts. Please wait before trying again."
            });
        }

        recentAttempts.push(now);
        authRateLimits.set(key, recentAttempts);
        return next();
    };
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const derivedKey = await scrypt(password, salt, 64);
    return `scrypt$${salt.toString("hex")}$${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
    const [algorithm, saltHex, hashHex] = storedHash.split("$");
    if (algorithm !== "scrypt" || !/^[0-9a-f]{32}$/i.test(saltHex) ||
        !/^[0-9a-f]{128}$/i.test(hashHex)) {
        return false;
    }

    const expected = Buffer.from(hashHex, "hex");
    const actual = await scrypt(password, Buffer.from(saltHex, "hex"), expected.length);
    return crypto.timingSafeEqual(actual, expected);
}

function createSession(userId, res) {
    const token = crypto.randomBytes(32).toString("base64url");
    db.prepare(`
        INSERT INTO sessions (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
    `).run(hashSessionToken(token), userId, Date.now() + SESSION_DURATION_MS);
    setSessionCookie(res, token);
}

// -------------------- RISK ANALYSIS ENGINE --------------------

// This is a basic rule-based educational scanner.
// It does not verify threats against live threat-intelligence databases.

function assessRisk(type, data) {
    let score = 0;
    const reasons = [];

    const add = (points, reason) => {
        score += points;
        reasons.push(reason);
    };

    const text = [
        data.message || "",
        data.url || "",
        data.username || "",
        data.bio || "",
        data.appName || "",
        data.developer || "",
        data.permissions || "",
        data.platform || ""
    ].join(" ").toLowerCase();

    // Suspicious URL patterns
    if (data.url) {
        try {
            const parsed = new URL(data.url);

            if (!["http:", "https:"].includes(parsed.protocol)) {
                add(50, "The URL uses an unexpected protocol.");
            }

            if (parsed.protocol === "http:") {
                add(10, "The URL does not use HTTPS.");
            }

            if (parsed.username || parsed.password) {
                add(30, "The URL contains embedded login credentials.");
            }

            if (parsed.hostname.startsWith("xn--") ||
                parsed.hostname.includes(".xn--")) {
                add(25, "The domain uses internationalized encoding that deserves checking.");
            }

            const hostParts = parsed.hostname.split(".");

            if (hostParts.length >= 6) {
                add(15, "The hostname has an unusually complex structure.");
            }

        } catch {
            add(25, "The submitted URL is not in a recognizable format.");
        }
    }

    // Common social engineering indicators
    const patterns = [
        {
            regex: /\b(otp|one[- ]time password)\b/i,
            points: 25,
            reason: "The content mentions an OTP or one-time password."
        },
        {
            regex: /\b(password|bank details|card number|cvv|pin)\b/i,
            points: 20,
            reason: "The content requests or mentions sensitive credentials."
        },
        {
            regex: /\b(won|winner|prize|lottery|free gift)\b/i,
            points: 15,
            reason: "The content contains an unexpected prize or reward claim."
        },
        {
            regex: /\b(urgent|immediately|act now|account blocked)\b/i,
            points: 15,
            reason: "The content uses urgency or account-threat language."
        },
        {
            regex: /\b(send money|pay fee|transfer money|claim reward)\b/i,
            points: 20,
            reason: "The content mentions a payment or reward claim."
        },
        {
            regex: /\b(verify your account|click here|limited time)\b/i,
            points: 10,
            reason: "The content uses a common call-to-action pattern."
        }
    ];

    for (const pattern of patterns) {
        if (pattern.regex.test(text)) {
            add(pattern.points, pattern.reason);
        }
    }

    // Social profile assessment
    if (type === "social") {
        if (data.impersonation === true) {
            add(35, "The user indicated possible brand or identity impersonation.");
        }

        if (data.accountAgeDays !== "" &&
            data.accountAgeDays !== undefined &&
            Number.isFinite(Number(data.accountAgeDays)) &&
            Number(data.accountAgeDays) < 30) {
            add(15, "The account is reported to be less than 30 days old.");
        }

        if (data.followers !== "" &&
            data.followers !== undefined &&
            Number.isFinite(Number(data.followers)) &&
            Number(data.followers) < 5) {
            add(5, "The account has very few reported followers.");
        }
    }

    // App assessment
    if (type === "app") {
        if (data.unofficialSource === true) {
            add(25, "The app was reported as coming from an unofficial source.");
        }

        if (data.impersonation === true) {
            add(30, "The app may be impersonating another brand.");
        }

        const permissions = String(data.permissions || "").toLowerCase();

        const riskyPermissions = [
            ["sms", "SMS access"],
            ["accessibility", "accessibility access"],
            ["contacts", "contacts access"],
            ["microphone", "microphone access"],
            ["location", "location access"],
            ["device admin", "device administrator access"]
        ];

        for (const [keyword, label] of riskyPermissions) {
            if (permissions.includes(keyword)) {
                add(8, `Review whether ${label} is necessary.`);
            }
        }
    }

    // Message and URL analysis can overlap, so cap the score.
    score = Math.min(100, score);

    let level = "Low";

    if (score >= 60) {
        level = "High";
    } else if (score >= 30) {
        level = "Medium";
    }

    if (reasons.length === 0) {
        reasons.push(
            "No configured warning patterns were detected. This does not prove the item is safe."
        );
    }

    return {
        score,
        level,
        reasons,
        advice: getAdvice(level)
    };
}

function getAdvice(level) {
    if (level === "High") {
        return [
            "Avoid clicking links or downloading files until independently verified.",
            "Never share OTPs, passwords, PINs, or banking details.",
            "Verify claims using the organization's official website or phone number."
        ];
    }

    if (level === "Medium") {
        return [
            "Check the sender and website address carefully.",
            "Look for independent confirmation from an official source.",
            "Do not share sensitive information unless you have verified the request."
        ];
    }

    return [
        "No configured warning patterns were found, but the item is not guaranteed safe.",
        "Check the sender and website address before taking action.",
        "Never share passwords, OTPs, or banking PINs."
    ];
}

// -------------------- VALIDATION --------------------

function validateInput(body, fields) {
    if (!body || typeof body !== "object" || Array.isArray(body)) {
        return "A JSON object is required.";
    }

    for (const field of fields) {
        if (typeof body[field] !== "string" || !body[field].trim()) {
            return `${field} is required.`;
        }

        if (body[field].length > 5000) {
            return `${field} must be 5000 characters or fewer.`;
        }
    }

    return null;
}

function saveResult(userId, type, target, result) {
    insertScan.run(
        userId,
        type,
        target.slice(0, 250),
        result.score,
        result.level,
        JSON.stringify({
            reasons: result.reasons,
            advice: result.advice
        })
    );
}

function runScan(userId, type, target, data) {
    const result = assessRisk(type, data);
    saveResult(userId, type, target, result);

    return {
        success: true,
        scanType: type,
        target,
        ...result,
        disclaimer:
            "Preliminary rule-based assessment only. It is not a guarantee that an item is safe or malicious."
    };
}

// -------------------- API ROUTES --------------------

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        application: "BrandShield AI",
        status: "running"
    });
});

app.post(
    "/api/auth/signup",
    limitAuthAttempts(6, 60 * 60 * 1000),
    async (req, res) => {
        if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
            return res.status(400).json({ error: "A JSON object is required." });
        }

        const email = typeof req.body.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";
        const password = req.body.password;

        if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: "Enter a valid email address." });
        }
        if (typeof password !== "string" || password.length < 12 || password.length > 128) {
            return res.status(400).json({
                error: "Password must be between 12 and 128 characters."
            });
        }
        if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) {
            return res.status(409).json({ error: "An account with that email already exists." });
        }

        const passwordHash = await hashPassword(password);
        let user;
        try {
            user = db.prepare(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)"
            ).run(email, passwordHash);
        } catch (error) {
            if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
                return res.status(409).json({
                    error: "An account with that email already exists."
                });
            }
            throw error;
        }

        createSession(user.lastInsertRowid, res);
        res.status(201).json({ user: { email } });
    }
);

app.post(
    "/api/auth/login",
    limitAuthAttempts(10, 15 * 60 * 1000),
    async (req, res) => {
        if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
            return res.status(400).json({ error: "A JSON object is required." });
        }

        const email = typeof req.body.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";
        const password = req.body.password;
        if (typeof password !== "string" || password.length < 1 || password.length > 128) {
            return res.status(400).json({ error: "Enter your email and password." });
        }

        const user = db.prepare(
            "SELECT id, email, password_hash FROM users WHERE email = ?"
        ).get(email);
        const passwordMatches = user
            ? await verifyPassword(password, user.password_hash)
            : (await scrypt(password, Buffer.alloc(16), 64), false);

        if (!passwordMatches) {
            return res.status(401).json({ error: "Email or password is incorrect." });
        }

        createSession(user.id, res);
        res.json({ user: { email: user.email } });
    }
);

app.get("/api/auth/me", requireAuth, (req, res) => {
    res.json({ user: { email: req.user.email } });
});

app.post("/api/auth/logout", (req, res) => {
    const token = getSessionToken(req);
    if (token && /^[A-Za-z0-9_-]{40,60}$/.test(token)) {
        db.prepare("DELETE FROM sessions WHERE token_hash = ?")
            .run(hashSessionToken(token));
    }
    clearSessionCookie(res);
    res.json({ success: true });
});

app.get("/api/stats", requireAuth, (req, res) => {
    const stats = db.prepare(`
        SELECT COUNT(*) AS total,
               COUNT(CASE WHEN risk_level = 'High' THEN 1 END) AS high,
               COUNT(CASE WHEN risk_level = 'Medium' THEN 1 END) AS medium,
               COUNT(CASE WHEN risk_level = 'Low' THEN 1 END) AS low
        FROM scans
        WHERE user_id = ?
    `).get(req.user.id);

    res.json(stats);
});

app.get("/api/history", requireAuth, (req, res) => {
    const history = db.prepare(`
        SELECT id, scan_type, target, risk_score,
               risk_level, explanation, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
    `).all(req.user.id);

    res.json(history.map(row => ({
        ...row,
        explanation: JSON.parse(row.explanation)
    })));
});

app.post("/api/scan/message", requireAuth, (req, res) => {
    const error = validateInput(req.body, ["message"]);

    if (error) {
        return res.status(400).json({ error });
    }

    const result = runScan(
        req.user.id,
        "message",
        "Submitted message",
        { message: req.body.message }
    );

    res.json(result);
});

app.post("/api/scan/link", requireAuth, (req, res) => {
    const error = validateInput(req.body, ["url"]);

    if (error) {
        return res.status(400).json({ error });
    }

    const result = runScan(
        req.user.id,
        "link",
        req.body.url,
        { url: req.body.url }
    );

    res.json(result);
});

app.post("/api/scan/social", requireAuth, (req, res) => {
    const error = validateInput(req.body, ["username"]);

    if (error) {
        return res.status(400).json({ error });
    }

    const result = runScan(
        req.user.id,
        "social",
        req.body.username,
        {
            username: req.body.username,
            platform: req.body.platform || "",
            url: req.body.url || "",
            bio: req.body.bio || "",
            accountAgeDays: req.body.accountAgeDays ?? "",
            followers: req.body.followers ?? "",
            impersonation: req.body.impersonation === true
        }
    );

    res.json(result);
});

app.post("/api/scan/app", requireAuth, (req, res) => {
    const error = validateInput(req.body, ["appName"]);

    if (error) {
        return res.status(400).json({ error });
    }

    const result = runScan(
        req.user.id,
        "app",
        req.body.appName,
        {
            appName: req.body.appName,
            developer: req.body.developer || "",
            url: req.body.url || "",
            permissions: req.body.permissions || "",
            unofficialSource: req.body.unofficialSource === true,
            impersonation: req.body.impersonation === true
        }
    );

    res.json(result);
});

// -------------------- FRONTEND --------------------

app.get("/", (req, res) => {
    res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BrandShield AI</title>

<style>
:root {
    --bg: #07111f;
    --panel: #101f33;
    --border: #263b53;
    --text: #eaf3ff;
    --muted: #9db0c8;
    --accent: #36d9ff;
    --green: #49e3a3;
    --red: #ff667c;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
}

.ambient-scene {
    position: fixed;
    z-index: 0;
    inset: 0;
    overflow: hidden;
    pointer-events: none;
    perspective: 1000px;
    background:
        radial-gradient(ellipse at 72% 38%, rgb(12 77 125 / 14%), transparent 48%),
        radial-gradient(ellipse at 22% 82%, rgb(8 99 139 / 10%), transparent 44%);
}

.ambient-orb {
    position: absolute;
    width: clamp(150px, 25vw, 360px);
    aspect-ratio: 1;
    border: 1px solid rgb(79 204 255 / 24%);
    border-radius: 50%;
    opacity: 0.24;
    transform-style: preserve-3d;
    filter: drop-shadow(0 0 35px rgb(0 174 255 / 28%));
}

.ambient-orb::before {
    content: "";
    position: absolute;
    inset: 8%;
    border: 1px solid rgb(107 224 255 / 28%);
    border-radius: inherit;
    transform: translateZ(24px);
}

.ambient-orb::after {
    content: "";
    position: absolute;
    inset: 20%;
    border-radius: inherit;
    background: radial-gradient(circle at 32% 28%, rgb(104 232 255 / 24%), rgb(16 92 168 / 9%) 48%, transparent 72%);
    box-shadow: inset -18px -12px 38px rgb(0 10 35 / 45%);
}

.ambient-orb-one {
    top: -110px;
    right: 4%;
    animation: ambient-drift-one 34s ease-in-out infinite;
}

.ambient-orb-two {
    bottom: -150px;
    left: 25%;
    width: clamp(180px, 32vw, 440px);
    opacity: 0.17;
    animation: ambient-drift-two 42s ease-in-out infinite;
}

.ambient-orbit {
    position: absolute;
    top: 46%;
    left: 57%;
    width: min(70vw, 880px);
    height: min(27vw, 300px);
    border: 1px solid rgb(54 217 255 / 20%);
    border-radius: 50%;
    opacity: 0.22;
    box-shadow: 0 0 24px rgb(0 190 255 / 12%), inset 0 0 24px rgb(0 190 255 / 10%);
    transform: translate(-50%, -50%) rotateX(68deg) rotateZ(-12deg);
    animation: ambient-orbit 38s linear infinite;
}

.ambient-orbit-two {
    width: min(58vw, 720px);
    height: min(22vw, 220px);
    border-color: rgb(91 130 255 / 18%);
    transform: translate(-50%, -50%) rotateX(68deg) rotateZ(18deg);
    animation-duration: 52s;
    animation-direction: reverse;
}

@keyframes ambient-drift-one {
    0%, 100% { transform: translate3d(0, 0, -80px) rotateY(-18deg) rotateX(12deg); }
    50% { transform: translate3d(-48px, 70px, 30px) rotateY(22deg) rotateX(-10deg); }
}

@keyframes ambient-drift-two {
    0%, 100% { transform: translate3d(0, 0, -100px) rotateY(20deg) rotateX(-8deg); }
    50% { transform: translate3d(52px, -58px, 20px) rotateY(-16deg) rotateX(14deg); }
}

@keyframes ambient-orbit {
    from { margin-left: -2%; }
    to { margin-left: 2%; }
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 18px 24px;
    background: #0b1728;
    border-bottom: 1px solid var(--border);
}

.logo {
    font-size: 22px;
    font-weight: bold;
    color: var(--accent);
}

.logo span {
    color: white;
}

header select {
    width: auto;
    min-width: 130px;
}

main {
    min-width: 0;
}

.app-layout {
    position: relative;
    z-index: 1;
    display: flex;
    min-height: 100vh;
}

.app-layout[hidden],
.auth-screen[hidden] {
    display: none !important;
}

.auth-screen {
    position: relative;
    z-index: 1;
    display: grid;
    min-height: 100vh;
    place-items: center;
    padding: 24px;
    background:
        radial-gradient(ellipse at 50% 35%, rgb(0 191 255 / 9%), transparent 48%),
        linear-gradient(180deg, rgb(4 16 32 / 34%), rgb(3 12 25 / 72%));
}

.auth-card {
    width: min(100%, 390px);
    padding: 32px 30px 26px;
    border: 1px solid rgb(54 217 255 / 24%);
    border-radius: 18px;
    background: linear-gradient(155deg, rgb(13 31 52 / 98%), rgb(5 19 36 / 98%));
    box-shadow: 0 24px 70px rgb(0 0 0 / 42%), 0 0 40px rgb(0 177 255 / 8%);
    animation: page-3d-enter 650ms cubic-bezier(0.2, 0.75, 0.25, 1) both;
}

.auth-brand {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 9px;
    margin-bottom: 25px;
    color: #dff8ff;
    font-size: 19px;
    font-weight: bold;
    letter-spacing: -0.4px;
}

.auth-brand-mark {
    display: inline-grid;
    width: 35px;
    height: 39px;
    place-items: center;
    color: var(--accent);
    filter: drop-shadow(0 0 8px rgb(0 199 255 / 55%));
}

.auth-brand-mark svg {
    width: 100%;
    height: 100%;
}

.auth-card h1 {
    margin: 0;
    color: #f3f8ff;
    font-size: 24px;
    text-align: center;
}

.auth-description {
    margin: 7px 0 23px;
    font-size: 12px;
    text-align: center;
}

.auth-field {
    position: relative;
    margin-top: 12px;
}

.auth-field-icon {
    position: absolute;
    top: 50%;
    left: 12px;
    display: inline-flex;
    width: 15px;
    height: 15px;
    color: #38c9f2;
    pointer-events: none;
    transform: translateY(-50%);
}

.auth-field-icon svg,
.password-toggle svg {
    width: 100%;
    height: 100%;
}

.auth-card .auth-field input {
    height: 43px;
    margin: 0;
    padding: 0 40px 0 37px;
    border-color: #244560;
    border-radius: 9px;
    background: rgb(4 18 34 / 76%);
    font-size: 13px;
}

.auth-card .auth-field input::placeholder {
    color: #9cb2c8;
}

.auth-card .auth-field input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgb(54 217 255 / 12%), 0 0 16px rgb(0 191 255 / 10%);
    transform: none;
}

.password-toggle {
    position: absolute;
    top: 50%;
    right: 11px;
    display: inline-flex;
    width: 20px;
    height: 22px;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 2px;
    background: transparent;
    color: #91abc4;
    transform: translateY(-50%);
}

.password-toggle:hover,
.password-toggle:active {
    background: transparent;
    box-shadow: none;
    transform: translateY(-50%);
}

.auth-card .auth-submit {
    width: 100%;
    min-height: 44px;
    margin-top: 14px;
    border-radius: 9px;
    background: linear-gradient(100deg, #00b9ef, #20dcf5);
    box-shadow: 0 7px 20px rgb(0 194 245 / 20%);
    color: #041526;
    font-size: 14px;
}

.auth-card .auth-submit:disabled {
    cursor: wait;
    opacity: 0.7;
}

.auth-mode-prompt {
    margin: 21px 0 0;
    color: #9db0c8;
    font-size: 12px;
    text-align: center;
}

.auth-mode-prompt button {
    margin: 0 0 0 4px;
    padding: 2px 0;
    background: transparent;
    color: #25d5f5;
    font-size: inherit;
    font-weight: bold;
}

.auth-mode-prompt button:hover {
    box-shadow: none;
    text-decoration: underline;
    transform: none;
}

.auth-security-note {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    margin: 15px 0 0;
    color: #738da7;
    font-size: 10px;
}

.auth-security-note svg {
    width: 12px;
    height: 12px;
    color: #32caee;
}

.auth-error {
    margin: 12px 0 0;
    color: #ff8b9c;
}

.visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
}

.account-controls {
    display: flex;
    align-items: center;
    gap: 12px;
}

.account-email {
    max-width: 260px;
    overflow: hidden;
    color: var(--muted);
    text-overflow: ellipsis;
    white-space: nowrap;
}

.account-controls button {
    width: auto;
    margin: 0;
    padding: 10px 14px;
}

.sidebar {
    width: 250px;
    flex: 0 0 250px;
    padding: 22px 15px;
    background: rgb(11 23 40 / 92%);
    border-right: 1px solid var(--border);
}

.sidebar .logo {
    display: block;
    margin: 0 10px 32px;
    line-height: 1.4;
}

.menu-title {
    margin: 22px 10px 10px;
    color: #849ab4;
    font-size: 11px;
    letter-spacing: 1px;
}

.nav-item {
    display: flex;
    width: 100%;
    align-items: center;
    margin: 4px 0;
    padding: 12px;
    border: 0;
    border-radius: 9px;
    background: transparent;
    color: #bdcde0;
    font-size: 14px;
    text-align: left;
    cursor: pointer;
}

.nav-item:hover,
.nav-item.active {
    background: #087eae;
    color: white;
}

.nav-item {
    transform: perspective(700px) translateZ(0);
    transition: transform 220ms ease, background-color 220ms ease, color 220ms ease;
}

.nav-item:hover {
    transform: perspective(700px) translateX(3px) rotateY(-2deg);
}

.nav-icon {
    position: relative;
    display: inline-flex;
    width: 38px;
    height: 38px;
    flex: 0 0 38px;
    align-items: center;
    justify-content: center;
    margin-right: 10px;
    border: 1px solid #2476a5;
    border-radius: 10px;
    background: linear-gradient(145deg, #123c61, #071525);
    box-shadow: 0 4px 0 #06101d, 0 0 12px #00bfff25;
    font-size: 21px;
    transform-style: preserve-3d;
    transition: scale 300ms ease, rotate 300ms ease, box-shadow 300ms ease;
}

.icon-shield { animation: shieldFloat 2.5s ease-in-out infinite; }
.icon-social { animation: socialPulse 2s ease-in-out infinite; }
.icon-app { animation: phoneFloat 2s ease-in-out infinite; }
.icon-url { animation: globeSpin 5s linear infinite; }
.icon-scam { animation: warningPulse 1.5s ease-in-out infinite; }
.icon-threat { animation: warningPulse 1.8s ease-in-out infinite; }
.icon-reports { animation: reportFloat 2.2s ease-in-out infinite; }

.nav-item:hover .nav-icon {
    scale: 1.12;
    rotate: y 20deg;
    box-shadow: 0 0 20px #00cfff80;
}

.nav-item.active .nav-icon {
    background: linear-gradient(145deg, #087eae, #064b78);
    border-color: #56e8ff;
}

.nav-icon::after {
    content: "";
    position: absolute;
    inset: -5px;
    border: 2px solid rgb(54 217 255 / 75%);
    border-radius: inherit;
    opacity: 0;
    pointer-events: none;
}

.nav-item.is-opening .nav-icon::after {
    animation: water-ripple 1200ms cubic-bezier(0.15, 0.6, 0.35, 1) both;
}

@keyframes water-ripple {
    0% {
        opacity: 0.85;
        transform: perspective(350px) scale(0.8) rotateX(65deg);
        box-shadow: 0 0 8px rgb(54 217 255 / 55%);
    }

    100% {
        opacity: 0;
        transform: perspective(350px) scale(1.9) rotateX(65deg);
        box-shadow: 0 0 22px rgb(54 217 255 / 0%);
    }
}

@keyframes shieldFloat {
    0%, 100% { transform: translateY(0) rotateY(0deg); }
    50% { transform: translateY(-4px) rotateY(12deg); }
}

@keyframes socialPulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.1); }
}

@keyframes phoneFloat {
    0%, 100% { transform: translateY(0) rotateZ(-3deg); }
    50% { transform: translateY(-4px) rotateZ(3deg); }
}

@keyframes globeSpin {
    0% { transform: perspective(300px) rotateY(0deg); }
    100% { transform: perspective(300px) rotateY(360deg); }
}

@keyframes warningPulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.12); }
}

@keyframes reportFloat {
    0%, 100% { transform: translateY(0) rotateX(0deg); }
    50% { transform: translateY(-3px) rotateX(12deg); }
}

.main-content {
    flex: 1;
    min-width: 0;
}

.main-content > main {
    width: auto;
    max-width: 1440px;
    margin: 24px auto;
    padding: 0 24px;
    perspective: 1400px;
}

.page {
    display: none;
}

.page.active-page {
    display: block;
    animation: page-3d-enter 650ms cubic-bezier(0.2, 0.75, 0.25, 1) both;
    transform-origin: top center;
}

@keyframes page-3d-enter {
    from {
        opacity: 0;
        transform: perspective(1400px) translateY(14px) translateZ(-45px) rotateX(2deg);
    }

    to {
        opacity: 1;
        transform: perspective(1400px) translateY(0) translateZ(0) rotateX(0);
    }
}

.page-title {
    margin-bottom: 22px;
}

.dashboard-history {
    margin-top: 22px;
}

.dashboard-history .history-row:nth-child(n + 6) {
    display: none;
}

.threat-stats {
    margin-top: 20px;
}

.threat-stats .card h2 {
    margin: 12px 0 0;
}

.hero {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    align-items: center;
    padding: 25px;
    background: linear-gradient(135deg, #102944, #101b30);
    border: 1px solid var(--border);
    border-radius: 20px;
}

h1 {
    font-size: clamp(27px, 4vw, 42px);
    margin: 0 0 15px;
}

p {
    line-height: 1.6;
}

.muted {
    color: var(--muted);
}

#shield {
    width: 100%;
    min-height: 280px;
    height: 100%;
    display: grid;
    place-items: center;
    border-radius: 14px;
    overflow: hidden;
    perspective: 1000px;
}

.stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 15px;
    margin: 22px 0;
}

.card, .tool {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 20px;
    min-width: 0;
    transform-style: preserve-3d;
    transition: transform 280ms ease, box-shadow 280ms ease, border-color 280ms ease;
}

.card:hover,
.tool:hover {
    transform: perspective(1000px) translateY(-4px) rotateX(1deg) rotateY(-0.6deg);
    border-color: #3c6589;
    box-shadow: 0 14px 28px rgb(0 0 0 / 24%);
}

.stat-number {
    font-size: 30px;
    font-weight: bold;
    margin-top: 12px;
}

.tools {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 18px;
}

.dashboard {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
    align-items: start;
    gap: 18px;
}

.history {
    margin-top: 0;
}

h2 {
    font-size: 20px;
    margin-top: 0;
}

.tool-heading {
    display: flex;
    align-items: center;
    gap: 11px;
}

.tool-icon {
    display: inline-grid;
    width: 42px;
    height: 42px;
    flex: 0 0 42px;
    place-items: center;
    border: 1px solid currentColor;
    border-radius: 12px;
    background: #091625;
    transform-style: preserve-3d;
    transition: transform 450ms ease;
}

.tool-heading:hover .tool-icon {
    transform: perspective(500px) rotateY(18deg) rotateX(-8deg) translateZ(5px);
}

.tool-icon svg {
    width: 21px;
    height: 21px;
    fill: none;
    stroke: currentColor;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-width: 1.8;
}

.message-icon { color: #c49bff; }
.link-icon { color: #36d9ff; }
.profile-icon { color: #ffb86b; }
.app-icon { color: #49e3a3; }
.history-icon { color: #8faeff; }

label {
    display: block;
    margin: 13px 0 6px;
    color: var(--muted);
    font-size: 14px;
}

input, textarea, select {
    width: 100%;
    padding: 12px;
    border-radius: 9px;
    border: 1px solid #314863;
    background: #091625;
    color: white;
    font: inherit;
    transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
}

input:focus,
textarea:focus,
select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgb(54 217 255 / 14%);
    transform: perspective(700px) translateZ(3px);
}

textarea {
    resize: vertical;
    min-height: 100px;
}

input[type="checkbox"] {
    width: auto;
    margin-right: 7px;
}

.check {
    display: flex;
    align-items: center;
    gap: 4px;
}

button {
    border: 0;
    padding: 12px 15px;
    margin-top: 12px;
    border-radius: 9px;
    background: var(--accent);
    color: #06111e;
    font-weight: bold;
    cursor: pointer;
    transform: perspective(700px) translateZ(0);
    transition: transform 180ms ease, filter 180ms ease, box-shadow 180ms ease;
}

button:hover {
    filter: brightness(1.1);
    transform: perspective(700px) translateY(-2px) rotateX(3deg) translateZ(3px);
    box-shadow: 0 7px 14px rgb(0 0 0 / 22%);
}

button:active {
    transform: perspective(700px) translateY(0) rotateX(0) translateZ(0);
    box-shadow: none;
}

.secondary {
    background: #253a53;
    color: white;
}

.result {
    margin-top: 15px;
    padding: 14px;
    border-radius: 10px;
    background: #091625;
    border: 1px solid var(--border);
    overflow-wrap: anywhere;
}

.result ul {
    padding-left: 22px;
    line-height: 1.6;
}

.score {
    font-size: 26px;
    font-weight: bold;
}

.high { color: var(--red); }
.medium { color: #ffcb68; }
.low { color: var(--green); }

.history-row {
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
    overflow-wrap: anywhere;
    transition: transform 200ms ease, padding 200ms ease;
}

.history-row:hover {
    padding-left: 5px;
    transform: perspective(700px) translateZ(3px) rotateY(-1deg);
}

@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        scroll-behavior: auto !important;
        transition-duration: 0.01ms !important;
    }

    .card:hover,
    .tool:hover,
    .nav-item:hover,
    .tool-heading:hover .tool-icon,
    button:hover,
    input:focus,
    textarea:focus,
    select:focus,
    .history-row:hover {
        transform: none;
    }

    .nav-icon {
        animation: none !important;
        scale: 1;
        rotate: none;
        transition: none;
    }

    .nav-item.is-opening .nav-icon::after {
        animation: none !important;
    }
}

.disclaimer {
    font-size: 12px;
    color: var(--muted);
    margin-top: 12px;
}

footer {
    text-align: center;
    padding: 25px;
    color: var(--muted);
}

@media(max-width: 800px) {
    .app-layout {
        display: block;
    }

    .sidebar {
        width: 100%;
        border-right: 0;
        border-bottom: 1px solid var(--border);
    }

    .sidebar .logo {
        margin-bottom: 16px;
    }

    .sidebar nav {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 2px 8px;
    }

    .menu-title {
        grid-column: 1 / -1;
    }

    .main-content > main {
        margin-top: 20px;
        padding: 0 16px;
    }

    .hero {
        grid-template-columns: 1fr;
    }

    .stats {
        grid-template-columns: repeat(2, 1fr);
    }

    .tools {
        grid-template-columns: 1fr;
    }

    #shield {
        max-height: 320px;
        object-fit: cover;
    }
}

@media(max-width: 420px) {
    .auth-screen {
        padding: 16px;
    }

    .auth-card {
        padding: 27px 22px 22px;
    }

    .sidebar nav {
        grid-template-columns: 1fr;
    }

    .main-content > header {
        padding: 14px 16px;
    }

    .stats {
        gap: 8px;
    }

    .card {
        padding: 13px;
    }

    .stat-number {
        font-size: 24px;
    }

    .account-controls {
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: 8px;
    }

    .account-email {
        max-width: 100%;
    }
}
</style>
</head>

<body>

<div class="ambient-scene" aria-hidden="true">
<span class="ambient-orb ambient-orb-one"></span>
<span class="ambient-orb ambient-orb-two"></span>
<span class="ambient-orbit"></span>
<span class="ambient-orbit ambient-orbit-two"></span>
</div>

<main class="auth-screen" id="authScreen">
    <section class="auth-card" aria-labelledby="authHeading">
        <div class="auth-brand">
            <span class="auth-brand-mark" aria-hidden="true">
                <svg viewBox="0 0 40 46" fill="none">
                    <path d="M20 2 36 8v12c0 11-6.8 19.2-16 24C10.8 39.2 4 31 4 20V8l16-6Z" fill="#073353" stroke="currentColor" stroke-width="2.4"/>
                    <path d="m12 22 5 5 11-12" stroke="#43e4ff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </span>
            <span>BrandShield AI</span>
        </div>
        <h1 id="authHeading">Welcome Back!</h1>
        <p class="auth-description muted" id="authDescription">Sign in to continue to your account</p>
        <form id="authForm">
            <label class="visually-hidden" for="authEmail">Email address</label>
            <div class="auth-field">
                <span class="auth-field-icon" aria-hidden="true">
                    <svg viewBox="0 0 20 20" fill="none">
                        <rect x="2.5" y="4" width="15" height="12" rx="2" stroke="currentColor" stroke-width="1.5"/>
                        <path d="m3.5 5.5 6.5 5 6.5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </span>
                <input id="authEmail" type="email" autocomplete="email" maxlength="254" placeholder="Email Address" required>
            </div>
            <label class="visually-hidden" for="authPassword">Password</label>
            <div class="auth-field">
                <span class="auth-field-icon" aria-hidden="true">
                    <svg viewBox="0 0 20 20" fill="none">
                        <rect x="4" y="8.5" width="12" height="9" rx="2" stroke="currentColor" stroke-width="1.5"/>
                        <path d="M6.5 8.5V6a3.5 3.5 0 0 1 7 0v2.5" stroke="currentColor" stroke-width="1.5"/>
                        <circle cx="10" cy="12.5" r="1" fill="currentColor"/>
                    </svg>
                </span>
                <input id="authPassword" type="password" autocomplete="current-password" placeholder="Password" required>
                <button class="password-toggle" id="passwordToggle" type="button" aria-label="Show password" aria-pressed="false" onclick="togglePasswordVisibility()">
                    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                        <path d="M2 10s2.8-5 8-5 8 5 8 5-2.8 5-8 5-8-5-8-5Z" stroke="currentColor" stroke-width="1.5"/>
                        <circle cx="10" cy="10" r="2.2" stroke="currentColor" stroke-width="1.5"/>
                    </svg>
                </button>
            </div>
            <p class="muted" id="passwordHint" hidden>Use at least 12 characters for your password.</p>
            <p class="auth-error" id="authError" role="alert" hidden></p>
            <button class="auth-submit" type="submit" id="authSubmit">Sign In</button>
        </form>
        <p class="auth-mode-prompt" id="authModePrompt">
            Don't have an account?
            <button type="button" id="authModeToggle" onclick="toggleAuthMode()">Sign Up</button>
        </p>
        <p class="auth-security-note">
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <rect x="3.5" y="7" width="9" height="7" rx="1.5" stroke="currentColor" stroke-width="1.3"/>
                <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor" stroke-width="1.3"/>
            </svg>
            Your scans are private to your account
        </p>
    </section>
</main>

<div class="app-layout" id="appLayout" hidden>
    <aside class="sidebar">
        <div class="logo">🛡️ BrandShield <span>AI</span></div>
        <nav aria-label="Main navigation">
            <p class="menu-title">MAIN MENU</p>
            <button class="nav-item active" data-page="dashboard" data-title="Dashboard" onclick="showPage('dashboard', this)"><span class="nav-icon icon-shield" aria-hidden="true">🛡️</span>Dashboard</button>

            <p class="menu-title">PROTECTION MODULES</p>
            <button class="nav-item" data-page="social" data-title="Social Monitoring" onclick="showPage('social', this)"><span class="nav-icon icon-social" aria-hidden="true">👤</span>Social Monitoring</button>
            <button class="nav-item" data-page="app" data-title="App Monitoring" onclick="showPage('app', this)"><span class="nav-icon icon-app" aria-hidden="true">📱</span>App Monitoring</button>
            <button class="nav-item" data-page="url" data-title="URL Monitoring" onclick="showPage('url', this)"><span class="nav-icon icon-url" aria-hidden="true">🌐</span>URL Monitoring</button>
            <button class="nav-item" data-page="message" data-title="Scam Message Checker" onclick="showPage('message', this)"><span class="nav-icon icon-scam" aria-hidden="true">⚠️</span>Scam Message Checker</button>

            <p class="menu-title">SECURITY</p>
            <button class="nav-item" data-page="threats" data-title="Threat Overview" onclick="showPage('threats', this)"><span class="nav-icon icon-threat" aria-hidden="true">🚨</span>Threat Overview</button>
            <button class="nav-item" data-page="reports" data-title="Audit Reports" onclick="showPage('reports', this)"><span class="nav-icon icon-reports" aria-hidden="true">📊</span>Audit Reports</button>
        </nav>
    </aside>

    <div class="main-content">
        <header>
            <div class="logo" id="pageTitle">Dashboard</div>
            <div class="account-controls">
                <span class="account-email" id="accountEmail"></span>
                <select id="language" aria-label="Choose language">
                    <option value="en-US">English</option>
                    <option value="te-IN">తెలుగు</option>
                    <option value="hi-IN">हिन्दी</option>
                </select>
                <button class="secondary" type="button" onclick="logout()">Sign out</button>
            </div>
        </header>

        <main>
            <section id="dashboard" class="page active-page">
                <section class="hero">
                    <div>
                        <h1 id="heroTitle">Your Digital Safety Assistant</h1>
                        <p id="heroText" class="muted">
                            Check suspicious messages, links, social profiles,
                            and mobile app information.
                        </p>
                        <button onclick="speakWelcome()" id="voiceButton">🔊 Hear Safety Instructions</button>
                        <button class="secondary" onclick="startVoiceInput()">🎙️ Speak a Message</button>
                        <p class="disclaimer">
                            This educational tool uses basic rules. Results are not
                            proof that an item is safe or malicious.
                        </p>
                    </div>
                    <div
                        id="shield"
                        role="img"
                        aria-label="Animated 3D BrandShield AI security shield"
                    ></div>
                </section>

                <section class="stats">
                    <div class="card">
                        <div class="muted">Total Scans</div>
                        <div class="stat-number" id="total">0</div>
                    </div>
                    <div class="card">
                        <div class="muted">High Risk</div>
                        <div class="stat-number high" id="high">0</div>
                    </div>
                    <div class="card">
                        <div class="muted">Medium Risk</div>
                        <div class="stat-number medium" id="medium">0</div>
                    </div>
                    <div class="card">
                        <div class="muted">Low Risk</div>
                        <div class="stat-number low" id="low">0</div>
                    </div>
                </section>

                <section class="tool dashboard-history">
                    <h2 class="tool-heading">
                        <span class="tool-icon history-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 2.6-6.4L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 2"/></svg>
                        </span>
                        Recent Scan History
                    </h2>
                    <button class="secondary" onclick="loadHistory()">Refresh History</button>
                    <div id="history"></div>
                </section>
            </section>

            <section id="social" class="page">
                <h1 class="page-title">👤 Social Monitoring</h1>
                <div class="tool">
                    <p class="muted">Check submitted social profile information.</p>
                    <label for="username">Username</label>
                    <input id="username" placeholder="Enter username">
                    <label for="platform">Platform</label>
                    <select id="platform">
                        <option>Instagram</option><option>Facebook</option><option>YouTube</option><option>X</option><option>Other</option>
                    </select>
                    <label for="profileUrl">Profile URL (optional)</label>
                    <input id="profileUrl" placeholder="https://example.com/profile">
                    <label for="bio">Profile bio (optional)</label>
                    <textarea id="bio" placeholder="Enter publicly available bio text"></textarea>
                    <label for="age">Account age in days (optional)</label>
                    <input id="age" type="number" min="0" placeholder="e.g. 90">
                    <label for="followers">Follower count (optional)</label>
                    <input id="followers" type="number" min="0" placeholder="e.g. 100">
                    <label class="check">
                        <input type="checkbox" id="impersonation">
                        Possible impersonation reported by user
                    </label>
                    <button onclick="scanSocial()">Check Profile</button>
                    <div id="socialResult" class="result" hidden></div>
                </div>
            </section>

            <section id="app" class="page">
                <h1 class="page-title">📱 App Monitoring</h1>
                <div class="tool">
                    <p class="muted">Review app details and reported permissions.</p>
                    <label for="appName">App name</label>
                    <input id="appName" placeholder="Enter app name">
                    <label for="developer">Developer (optional)</label>
                    <input id="developer" placeholder="Developer name">
                    <label for="appUrl">Official store or app URL (optional)</label>
                    <input id="appUrl" placeholder="https://example.com/app">
                    <label for="permissions">Permissions shown by the device (optional)</label>
                    <textarea id="permissions" placeholder="Example: SMS, contacts, location"></textarea>
                    <label class="check">
                        <input type="checkbox" id="unofficialSource">
                        Downloaded from an unofficial source
                    </label>
                    <label class="check">
                        <input type="checkbox" id="appImpersonation">
                        Possible brand impersonation
                    </label>
                    <button onclick="scanApp()">Check App</button>
                    <div id="appResult" class="result" hidden></div>
                </div>
            </section>

            <section id="url" class="page">
                <h1 class="page-title">🔗 URL Monitoring</h1>
                <div class="tool">
                    <p class="muted">Review the structure of a submitted URL.</p>
                    <label for="link">Website URL</label>
                    <input id="link" placeholder="https://example.com">
                    <button onclick="scanLink()">Check Link</button>
                    <div id="linkResult" class="result" hidden></div>
                </div>
            </section>

            <section id="message" class="page">
                <h1 class="page-title">💬 Scam Message Checker</h1>
                <div class="tool">
                    <p class="muted">Check a suspicious SMS or message.</p>
                    <label for="messageText">Message text</label>
                    <textarea id="messageText" placeholder="Paste the suspicious message here"></textarea>
                    <button onclick="scanMessage()">Check Message</button>
                    <div id="messageResult" class="result" hidden></div>
                </div>
            </section>

            <section id="threats" class="page">
                <h1 class="page-title">⚠️ Threat Overview</h1>
                <p class="muted">Review the number of scans in each risk category.</p>
                <section class="stats threat-stats">
                    <div class="card"><div class="muted">Total Scans</div><h2 id="threatTotal">0</h2></div>
                    <div class="card"><div class="muted">High Risk</div><h2 class="high" id="threatHigh">0</h2></div>
                    <div class="card"><div class="muted">Medium Risk</div><h2 class="medium" id="threatMedium">0</h2></div>
                    <div class="card"><div class="muted">Low Risk</div><h2 class="low" id="threatLow">0</h2></div>
                </section>
            </section>

            <section id="reports" class="page">
                <h1 class="page-title">📊 Audit Reports</h1>
                <div class="tool">
                    <p class="muted">Review previous scan results.</p>
                    <button class="secondary" onclick="loadHistory()">Refresh Reports</button>
                    <div id="reportHistory"></div>
                </div>
            </section>
        </main>

        <footer>
            BrandShield AI — Digital Risk Protection Platform
            <p>Educational prototype. Always independently verify important security warnings.</p>
        </footer>
    </div>
</div>

<script type="module">
import * as THREE from
    "https://cdn.jsdelivr.net/npm/three@0.178.0/build/three.module.js";

const container = document.getElementById("shield");

try {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(
        55,
        container.clientWidth / container.clientHeight,
        0.1,
        100
    );
    camera.position.z = 5;

    const renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: true
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);

    const shieldShape = new THREE.Shape();
    shieldShape.moveTo(0, 1.4);
    shieldShape.lineTo(1.05, 1.0);
    shieldShape.lineTo(0.9, 0);
    shieldShape.lineTo(0.45, -0.75);
    shieldShape.lineTo(0, -1.05);
    shieldShape.lineTo(-0.45, -0.75);
    shieldShape.lineTo(-0.9, 0);
    shieldShape.lineTo(-1.05, 1.0);
    shieldShape.closePath();

    const shieldGeometry = new THREE.ExtrudeGeometry(shieldShape, {
        depth: 0.18,
        bevelEnabled: true,
        bevelSegments: 3,
        steps: 1,
        bevelSize: 0.07,
        bevelThickness: 0.07
    });
    const shieldMaterial = new THREE.MeshStandardMaterial({
        color: 0x16bff2,
        metalness: 0.65,
        roughness: 0.22,
        emissive: 0x064c77,
        emissiveIntensity: 0.65
    });
    group.add(new THREE.Mesh(shieldGeometry, shieldMaterial));

    const points = [];
    for (let i = 0; i < 350; i++) {
        points.push(
            (Math.random() - 0.5) * 7,
            (Math.random() - 0.5) * 5,
            (Math.random() - 0.5) * 3
        );
    }

    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute(
        "position",
        new THREE.Float32BufferAttribute(points, 3)
    );
    const particles = new THREE.Points(
        particleGeometry,
        new THREE.PointsMaterial({
            color: 0x50ddff,
            size: 0.025,
            transparent: true,
            opacity: 0.8
        })
    );
    scene.add(particles);

    scene.add(new THREE.AmbientLight(0xffffff, 1.8));
    const light = new THREE.PointLight(0x31cfff, 35);
    light.position.set(2, 3, 4);
    scene.add(light);

    const reducedMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    );

    function animate() {
        requestAnimationFrame(animate);

        if (!reducedMotion.matches) {
            group.rotation.y += 0.008;
            group.rotation.x = Math.sin(Date.now() * 0.0005) * 0.08;
            particles.rotation.y += 0.0006;
        }

        renderer.render(scene, camera);
    }

    function resizeShield() {
        if (!container.clientWidth || !container.clientHeight) return;

        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    }

    window.addEventListener("resize", resizeShield);
    animate();
} catch (error) {
    container.textContent = "3D shield unavailable in this browser.";
    console.error("Unable to render the 3D security shield:", error);
}
</script>

<script>
const $ = id => document.getElementById(id);

let latestVoiceText = "";
let authMode = "login";

function setAuthMode(mode) {
    authMode = mode;
    const isSignup = mode === "signup";
    $("authHeading").textContent = isSignup ? "Create Account" : "Welcome Back!";
    $("authDescription").textContent = isSignup
        ? "Create an account to keep your scans private"
        : "Sign in to continue to your account";
    $("authSubmit").textContent = isSignup ? "Create Account" : "Sign In";
    $("authModePrompt").firstChild.textContent = isSignup
        ? "Already have an account?"
        : "Don't have an account?";
    $("authModeToggle").textContent = isSignup ? "Sign In" : "Sign Up";
    $("authPassword").autocomplete = isSignup ? "new-password" : "current-password";
    $("passwordHint").hidden = !isSignup;
    $("authError").hidden = true;
    $("authPassword").type = "password";
    $("passwordToggle").setAttribute("aria-label", "Show password");
    $("passwordToggle").setAttribute("aria-pressed", "false");
}

function toggleAuthMode() {
    setAuthMode(authMode === "login" ? "signup" : "login");
}

function togglePasswordVisibility() {
    const isVisible = $("authPassword").type === "text";
    $("authPassword").type = isVisible ? "password" : "text";
    $("passwordToggle").setAttribute("aria-label", isVisible ? "Show password" : "Hide password");
    $("passwordToggle").setAttribute("aria-pressed", String(!isVisible));
}

function showAuthenticated(email) {
    $("authScreen").hidden = true;
    $("appLayout").hidden = false;
    $("accountEmail").textContent = email;
    $("authForm").reset();
    window.dispatchEvent(new Event("resize"));
    refreshStats();
    loadHistory();
}

function showSignedOut(message) {
    $("appLayout").hidden = true;
    $("authScreen").hidden = false;
    $("accountEmail").textContent = "";
    $("authForm").reset();
    setAuthMode("login");

    if (message) {
        $("authError").textContent = message;
        $("authError").hidden = false;
    }

    for (const id of ["total", "high", "medium", "low", "threatTotal", "threatHigh", "threatMedium", "threatLow"]) {
        $(id).textContent = "0";
    }
    for (const id of ["history", "reportHistory"]) {
        $(id).replaceChildren();
    }
    for (const id of ["messageResult", "linkResult", "socialResult", "appResult"]) {
        $(id).replaceChildren();
        $(id).hidden = true;
    }
    for (const id of ["messageText", "link", "username", "profileUrl", "bio", "age", "followers", "appName", "developer", "appUrl", "permissions"]) {
        $(id).value = "";
    }
    for (const id of ["impersonation", "unofficialSource", "appImpersonation"]) {
        $(id).checked = false;
    }
    latestVoiceText = "";
    document.querySelectorAll(".page").forEach(page => {
        page.classList.toggle("active-page", page.id === "dashboard");
    });
    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle("active", button.dataset.page === "dashboard");
    });
    $("pageTitle").textContent = "Dashboard";
}

async function bootstrapAuth() {
    try {
        const result = await api("/api/auth/me");
        showAuthenticated(result.user.email);
    } catch (error) {
        if (error.status !== 401) {
            console.error("Unable to check the current account:", error);
            $("authError").textContent = "Unable to connect to BrandShield AI. Please try again.";
            $("authError").hidden = false;
        }
    }
}

async function logout() {
    try {
        await api("/api/auth/logout", {});
        showSignedOut();
    } catch (error) {
        alert(error.message);
    }
}

$("authForm").addEventListener("submit", async event => {
    event.preventDefault();
    $("authError").hidden = true;
    $("authSubmit").disabled = true;

    try {
        const result = await api(
            authMode === "signup" ? "/api/auth/signup" : "/api/auth/login",
            {
                email: $("authEmail").value.trim(),
                password: $("authPassword").value
            }
        );
        showAuthenticated(result.user.email);
    } catch (error) {
        $("authError").textContent = error.message;
        $("authError").hidden = false;
    } finally {
        $("authSubmit").disabled = false;
        $("authSubmit").textContent = authMode === "signup" ? "Create Account" : "Sign In";
    }
});

function showPage(pageId, clickedButton) {
    document.querySelectorAll(".page").forEach(page => {
        page.classList.toggle("active-page", page.id === pageId);
    });

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.remove("is-opening");
        const isActive = button === clickedButton;
        button.classList.toggle("active", isActive);
        if (isActive) {
            button.setAttribute("aria-current", "page");
        } else {
            button.removeAttribute("aria-current");
        }
    });

    if (clickedButton && !window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    ).matches) {
        void clickedButton.offsetWidth;
        clickedButton.classList.add("is-opening");
        window.setTimeout(() => {
            clickedButton.classList.remove("is-opening");
        }, 1300);
    }

    const title = clickedButton?.dataset.title;
    if (title) {
        $("pageTitle").textContent = title;
    }

    if (pageId === "dashboard" || pageId === "reports") {
        loadHistory();
    }

    if (pageId === "dashboard" || pageId === "threats") {
        refreshStats();
    }
}

async function api(path, data) {
    const response = await fetch(path, {
        method: data ? "POST" : "GET",
        headers: data ? { "Content-Type": "application/json" } : {},
        body: data ? JSON.stringify(data) : undefined,
        credentials: "same-origin"
    });

    const result = await response.json();

    if (!response.ok) {
        const error = new Error(result.error || "Request failed");
        error.status = response.status;
        if (
            response.status === 401 &&
            !path.startsWith("/api/auth/")
        ) {
            showSignedOut("Your session has expired. Please sign in again.");
        }
        throw error;
    }

    return result;
}

function showResult(id, result) {
    const box = $(id);
    box.hidden = false;

    const scoreClass = result.level.toLowerCase();

    box.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Risk assessment";

    const score = document.createElement("div");
    score.className = "score " + scoreClass;
    score.textContent = result.level + " — " + result.score + "/100";

    const reasonsTitle = document.createElement("strong");
    reasonsTitle.textContent = "Indicators";

    const reasons = document.createElement("ul");

    for (const reason of result.reasons) {
        const item = document.createElement("li");
        item.textContent = reason;
        reasons.appendChild(item);
    }

    const adviceTitle = document.createElement("strong");
    adviceTitle.textContent = "Recommended actions";

    const advice = document.createElement("ul");

    for (const message of result.advice) {
        const item = document.createElement("li");
        item.textContent = message;
        advice.appendChild(item);
    }

    const disclaimer = document.createElement("p");
    disclaimer.className = "disclaimer";
    disclaimer.textContent = result.disclaimer;

    box.append(
        heading,
        score,
        reasonsTitle,
        reasons,
        adviceTitle,
        advice,
        disclaimer
    );

    latestVoiceText =
        result.level + " risk assessment. " +
        result.reasons.join(". ") + ". " +
        result.advice.join(". ");

    refreshStats();
    loadHistory();
}

async function doScan(path, data, resultId) {
    try {
        const result = await api(path, data);
        showResult(resultId, result);
    } catch (error) {
        alert(error.message);
    }
}

function scanMessage() {
    const message = $("messageText").value.trim();

    if (!message) {
        alert("Please enter a message.");
        return;
    }

    doScan(
        "/api/scan/message",
        { message },
        "messageResult"
    );
}

function scanLink() {
    const url = $("link").value.trim();

    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    doScan(
        "/api/scan/link",
        { url },
        "linkResult"
    );
}

function scanSocial() {
    const username = $("username").value.trim();

    if (!username) {
        alert("Please enter a username.");
        return;
    }

    doScan(
        "/api/scan/social",
        {
            username,
            platform: $("platform").value,
            url: $("profileUrl").value.trim(),
            bio: $("bio").value.trim(),
            accountAgeDays: $("age").value,
            followers: $("followers").value,
            impersonation: $("impersonation").checked
        },
        "socialResult"
    );
}

function scanApp() {
    const appName = $("appName").value.trim();

    if (!appName) {
        alert("Please enter an app name.");
        return;
    }

    doScan(
        "/api/scan/app",
        {
            appName,
            developer: $("developer").value.trim(),
            url: $("appUrl").value.trim(),
            permissions: $("permissions").value.trim(),
            unofficialSource: $("unofficialSource").checked,
            impersonation: $("appImpersonation").checked
        },
        "appResult"
    );
}

async function refreshStats() {
    try {
        const stats = await api("/api/stats");

        $("total").textContent = stats.total;
        $("high").textContent = stats.high;
        $("medium").textContent = stats.medium;
        $("low").textContent = stats.low;
        $("threatTotal").textContent = stats.total;
        $("threatHigh").textContent = stats.high;
        $("threatMedium").textContent = stats.medium;
        $("threatLow").textContent = stats.low;
    } catch (error) {
        console.error(error);
    }
}

function renderHistory(container, history) {
    container.replaceChildren();

    if (history.length === 0) {
        container.textContent = "No scans have been performed yet.";
        return;
    }

    for (const row of history) {
        const entry = document.createElement("div");
        entry.className = "history-row";

        const title = document.createElement("strong");
        title.textContent =
            row.scan_type.toUpperCase() + " — " + row.target;

        const detail = document.createElement("div");
        detail.className = row.risk_level.toLowerCase();
        detail.textContent =
            row.risk_level + " risk (" + row.risk_score + "/100)";

        const date = document.createElement("small");
        date.className = "muted";
        date.textContent = row.created_at;

        entry.append(title, document.createElement("br"), detail, date);
        container.appendChild(entry);
    }
}

async function loadHistory() {
    try {
        const history = await api("/api/history");
        renderHistory($("history"), history.slice(0, 5));
        renderHistory($("reportHistory"), history);
    } catch (error) {
        console.error(error);
    }
}

// -------------------- MULTILINGUAL VOICE --------------------

const translations = {
    "en-US": {
        title: "Your Digital Safety Assistant",
        text: "Check suspicious messages, links, social profiles, and mobile app information.",
        welcome: "Welcome to BrandShield AI. Never share your password, bank PIN, or one-time password. Verify suspicious messages using official sources."
    },
    "te-IN": {
        title: "మీ డిజిటల్ భద్రత సహాయకుడు",
        text: "అనుమానాస్పద సందేశాలు, లింకులు, సోషల్ ప్రొఫైల్స్ మరియు మొబైల్ యాప్ వివరాలను పరిశీలించండి.",
        welcome: "బ్రాండ్ షీల్డ్ ఏ ఐ కి స్వాగతం. మీ పాస్‌వర్డ్, బ్యాంక్ పిన్ లేదా ఓటీపీని ఎవరికీ చెప్పకండి. అనుమానాస్పద సందేశాలను అధికారిక వనరుల ద్వారా ధృవీకరించండి."
    },
    "hi-IN": {
        title: "आपका डिजिटल सुरक्षा सहायक",
        text: "संदिग्ध संदेशों, लिंक, सोशल प्रोफाइल और मोबाइल ऐप की जानकारी जाँचें।",
        welcome: "ब्रांडशील्ड एआई में आपका स्वागत है। अपना पासवर्ड, बैंक पिन या ओटीपी किसी को न बताएं। संदिग्ध संदेशों की आधिकारिक स्रोतों से जाँच करें।"
    }
};

$("language").addEventListener("change", () => {
    const language = $("language").value;
    const translation = translations[language];

    $("heroTitle").textContent = translation.title;
    $("heroText").textContent = translation.text;
});

function speakText(text) {
    if (!("speechSynthesis" in window)) {
        alert("Your browser does not support voice output.");
        return;
    }

    window.speechSynthesis.cancel();

    const language = $("language").value;
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = language;
    utterance.rate = 0.85;
    utterance.pitch = 1;

    utterance.onstart = () => {
        console.log("Voice started:", language);
    };

    utterance.onerror = event => {
        console.error("Speech error:", event.error);
        alert("Voice playback failed. Check your browser's voice settings.");
    };

    const voices = window.speechSynthesis.getVoices();
    const languagePrefix = language.split("-")[0].toLowerCase();
    const matchingVoice = voices.find(voice =>
        voice.lang.toLowerCase() === language.toLowerCase()
    ) || voices.find(voice =>
        voice.lang.toLowerCase().startsWith(languagePrefix + "-")
    );

    if (matchingVoice) {
        utterance.voice = matchingVoice;
    }

    window.speechSynthesis.speak(utterance);
}

function speakWelcome() {
    const language = $("language").value;
    const messages = {
        "en-US": "Welcome to BrandShield AI. Never share your password or one-time password. Check suspicious messages before clicking links.",
        "te-IN": "బ్రాండ్ షీల్డ్ ఏ ఐ కి స్వాగతం. మీ పాస్‌వర్డ్ లేదా ఓటీపీని ఎవరికీ చెప్పకండి. అనుమానాస్పద లింకులను తెరవకండి. అధికారిక వెబ్‌సైట్ ద్వారా సమాచారాన్ని ధృవీకరించండి.",
        "hi-IN": "ब्रांडशील्ड एआई में आपका स्वागत है। अपना पासवर्ड या ओटीपी किसी को न बताएं। संदिग्ध लिंक न खोलें। आधिकारिक वेबसाइट से जानकारी की पुष्टि करें।"
    };

    speakText(messages[language] || messages["en-US"]);
}

function startVoiceInput() {
    const SpeechRecognition =
        window.SpeechRecognition ||
        window.webkitSpeechRecognition;

    if (!SpeechRecognition) {
        alert(
            "Voice input is not supported in this browser. " +
            "Try Chrome or type your message manually."
        );
        return;
    }

    const recognition = new SpeechRecognition();

    recognition.lang = $("language").value;
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    recognition.onstart = () => {
        console.log("Listening for speech:", recognition.lang);
    };

    recognition.onresult = event => {
        $("messageText").value =
            event.results[0][0].transcript;
        const messageButton = document.querySelector('[data-page="message"]');
        showPage("message", messageButton);
    };

    recognition.onerror = event => {
        console.error("Recognition error:", event.error);
        alert("Voice input error: " + event.error);
    };

    recognition.onend = () => {
        console.log("Voice recognition stopped.");
    };

    try {
        recognition.start();
    } catch (error) {
        console.error("Unable to start voice recognition:", error);
        alert("Could not start voice input. Check microphone permission and try again.");
    }
}

// Allow the speech result to be read aloud.
document.addEventListener("click", event => {
    if (event.target.id === "readLastResult") {
        speakText(latestVoiceText);
    }
});

bootstrapAuth();
</script>

</body>
</html>`);
});

// -------------------- ERROR HANDLING --------------------

app.use((err, req, res, next) => {
    console.error(err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(400).json({
        error: "The request could not be processed."
    });
});

// -------------------- START SERVER --------------------

app.listen(PORT, () => {
    console.log(`BrandShield AI running at http://localhost:${PORT}`);
    console.log("Press Ctrl+C to stop the server.");
});