import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import OpenAI from "openai";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import sqlite3 from "sqlite3";
import { GoogleAuth, OAuth2Client } from "google-auth-library";
import { getAudioDurationInSeconds } from "get-audio-duration";

dotenv.config();

// --- DATABASE SETUP ---
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error("FATAL: Could not connect to database.", err.message);
        process.exit(1);
    }
    console.log("Database connected.");
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        google_id TEXT UNIQUE,
        subscription_active BOOLEAN DEFAULT FALSE,
        subscription_expiry INTEGER DEFAULT 0,
        free_seconds_remaining INTEGER NOT NULL DEFAULT 600,
        free_trial_claimed BOOLEAN DEFAULT FALSE
    )`);
});

// Helpers
function dbGet(query, params) {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}
function dbRun(query, params) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: "uploads/" });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const googleClient = new OAuth2Client();
app.use(bodyParser.json());

// --- DATABASE RESET ENDPOINT ---
const RESET_PASSWORD = process.env.DB_RESET_PASSWORD;
if (RESET_PASSWORD) {
    app.get(`/reset-database/${RESET_PASSWORD}`, (req, res) => {
        console.log("!!! DATABASE RESET INITIATED !!!");
        db.close((err) => {
            if (err) return res.status(500).send("Could not close DB.");
            fs.unlink('./users.db', (err) => {
                if (err) return res.status(500).send("Could not delete DB file.");
                res.send("Database reset. Service will restart.");
                process.exit(1);
            });
        });
    });
}

// --- PUBLIC ROUTES ---
app.get("/", (_req, res) => res.send("OK"));

// Google auth
app.post("/auth/google", async (req, res) => {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "Google ID Token is required." });

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { sub: googleId, email } = payload;
        if (!email) return res.status(400).json({ error: "Email not available from Google account." });

        let user = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);

        if (!user) {
            // brand new user → free trial
            const result = await dbRun(
                `INSERT INTO users (email, google_id, subscription_active, subscription_expiry, free_seconds_remaining, free_trial_claimed)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [email, googleId, 0, 0, 600, 1]
            );
            user = await dbGet(`SELECT * FROM users WHERE id = ?`, [result.lastID]);
        } else if (!user.free_trial_claimed) {
            // existing user who never claimed trial
            await dbRun(
                `UPDATE users SET free_seconds_remaining = ?, free_trial_claimed = ? WHERE id = ?`,
                [600, 1, user.id]
            );
            user = await dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "30d" }
        );
        res.json({ token });
    } catch (error) {
        console.error("Google token verification failed:", error);
        res.status(401).json({ error: "Invalid Google ID Token." });
    }
});

// --- AUTH MIDDLEWARE ---
const authGuard = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized: No token." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Forbidden: Invalid token." });
        req.user = user;
        next();
    });
};

// --- STATUS ROUTE ---
app.get("/status", authGuard, async (req, res) => {
    const { userId, email } = req.user;
    if (email === process.env.DEV_BYPASS_EMAIL) {
        return res.json({ isSubscribed: true, freeSecondsRemaining: 999999 });
    }
    try {
        const user = await dbGet(
            `SELECT subscription_active, subscription_expiry, free_seconds_remaining 
             FROM users WHERE id = ?`,
            [userId]
        );
        if (!user) return res.status(404).json({ error: "User not found." });

        const now = Date.now();
        const stillSubscribed = !!user.subscription_active && user.subscription_expiry > now;

        res.json({
            isSubscribed: stillSubscribed,
            freeSecondsRemaining: user.free_seconds_remaining ?? 0,
            expiry: user.subscription_expiry
        });
    } catch (err) {
        console.error("Database error on /status:", err.message);
        return res.status(500).json({ error: "Database error." });
    }
});

// --- VERIFY PURCHASE ---
app.post("/verify-purchase", authGuard, async (req, res) => {
    const { purchaseToken, subscriptionId } = req.body;
    const { userId } = req.user;
    if (!purchaseToken || !subscriptionId) {
        return res.status(400).json({ error: "Purchase token and subscription ID required." });
    }
    try {
        const auth = new GoogleAuth({
            credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
            scopes: "https://www.googleapis.com/auth/androidpublisher",
        });
        const client = await auth.getClient();
        const packageName = process.env.ANDROID_PACKAGE_NAME;
        const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/subscriptions/${subscriptionId}/tokens/${purchaseToken}`;
        const googleResponse = await client.request({ url });
        const data = googleResponse.data;

        if (data && data.purchaseState === 0) {
            const expiry = parseInt(data.expiryTimeMillis, 10);

            await dbRun(
                `UPDATE users 
                 SET subscription_active = ?, subscription_expiry = ? 
                 WHERE id = ?`,
                [expiry > Date.now() ? 1 : 0, expiry, userId]
            );

            res.json({ message: "Subscription verified successfully.", expiry });
        } else {
            res.status(400).json({ error: "Invalid purchase token." });
        }
    } catch (error) {
        console.error("Google API Error:", error.response?.data?.error || error.message);
        res.status(500).json({ error: "Failed to verify purchase with Google." });
    }
});

// --- TRANSCRIBE ---
app.post("/transcribe", authGuard, async (req, res) => {
    const { userId, email } = req.user;
    try {
        const user = await dbGet(
            `SELECT subscription_active, subscription_expiry, free_seconds_remaining 
             FROM users WHERE id = ?`,
            [userId]
        );
        if (!user) return res.status(404).json({ error: "User not found." });

        const now = Date.now();
        const isDeveloper = (email === process.env.DEV_BYPASS_EMAIL);
        const isSubscriber = !!user.subscription_active && user.subscription_expiry > now;
        const hasFreeTime = user.free_seconds_remaining > 0;

        if (isDeveloper || isSubscriber || hasFreeTime) {
            await proceedWithTranscription(req, res, {
                isFreeTierUser: !isSubscriber && !isDeveloper,
                userId,
                secondsLeft: user.free_seconds_remaining
            });
        } else {
            return res.status(403).json({ error: "Subscription or free trial required." });
        }
    } catch (err) {
        console.error("Database error in /transcribe:", err.message);
        return res.status(500).json({ error: "Database error." });
    }
});

async function proceedWithTranscription(req, res, usageInfo) {
    const uploadMiddleware = upload.single("audio");
    uploadMiddleware(req, res, async (uploadErr) => {
        if (!req.file) return res.status(400).json({ error: "No audio file uploaded." });
        const tempPath = req.file.path;
        const finalPath = path.join("uploads", req.file.filename + path.extname(req.file.originalname));
        try {
            fs.renameSync(tempPath, finalPath);
            const durationInSeconds = await getAudioDurationInSeconds(finalPath);
            const roundedDuration = Math.ceil(durationInSeconds);

            if (usageInfo.isFreeTierUser && usageInfo.secondsLeft < roundedDuration) {
                return res.status(403).json({ error: "Not enough free time remaining." });
            }

            const transcription = await openai.audio.transcriptions.create({
                file: fs.createReadStream(finalPath),
                model: "whisper-1"
            });

            if (usageInfo.isFreeTierUser) {
                const newTime = Math.max(0, usageInfo.secondsLeft - roundedDuration);
                await dbRun(`UPDATE users SET free_seconds_remaining = ? WHERE id = ?`, [newTime, usageInfo.userId]);
            }
            res.json({ text: transcription.text || "" });
        } catch (transcribeErr) {
            console.error("Transcription error:", transcribeErr);
            res.status(500).json({ error: "Transcription failed." });
        } finally {
            if (fs.existsSync(finalPath)) fs.unlinkSync(finalPath);
        }
    });
}

app.listen(port, () => console.log(`🚀 Backend running on port ${port}`));
