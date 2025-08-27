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
import { GoogleAuth } from "google-auth-library"; // <-- NEW: Import Google Auth

dotenv.config();

// --- DATABASE SETUP (Unchanged) ---
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) { console.error("Error opening database", err.message); } 
    else {
        console.log("Database connected.");
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, subscription_active BOOLEAN DEFAULT FALSE
        )`);
    }
});

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: "uploads/" });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
app.use(bodyParser.json());

// --- PUBLIC ROUTES (Unchanged) ---
app.get("/", (_req, res) => res.send("OK"));
app.post("/register", async (req, res) => { /* ... (register code is unchanged) ... */ });
app.post("/login", (req, res) => { /* ... (login code is unchanged) ... */ });

// --- AUTHENTICATION MIDDLEWARE (Unchanged) ---
const authGuard = (req, res, next) => { /* ... (authGuard code is unchanged) ... */ };


// --- NEW SECURE ROUTE: VERIFY GOOGLE PLAY PURCHASE ---
app.post("/verify-purchase", authGuard, async (req, res) => {
    const { purchaseToken, subscriptionId } = req.body;
    const { userId } = req.user;

    if (!purchaseToken || !subscriptionId) {
        return res.status(400).json({ error: "Purchase token and subscription ID are required." });
    }

    try {
        // --- This section securely talks to Google's servers ---
        const auth = new GoogleAuth({
            credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
            scopes: "https://www.googleapis.com/auth/androidpublisher",
        });
        const client = await auth.getClient();

        const packageName = process.env.ANDROID_PACKAGE_NAME;
        const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/subscriptions/${subscriptionId}/tokens/${purchaseToken}`;
        
        const googleResponse = await client.request({ url });

        // If the purchase is valid, Google sends back purchase details
        if (googleResponse.data && googleResponse.data.purchaseState === 0) {
            // --- Update our database to mark the user as a subscriber ---
            const sql = `UPDATE users SET subscription_active = TRUE WHERE id = ?`;
            db.run(sql, [userId], function(err) {
                if (err) {
                    return res.status(500).json({ error: "Failed to update subscription status." });
                }
                res.json({ message: "Subscription verified successfully." });
            });
        } else {
            // If the purchase is invalid, expired, or refunded
            res.status(400).json({ error: "Invalid purchase token." });
        }
    } catch (error) {
        console.error("Google API Error:", error.response?.data?.error || error.message);
        res.status(500).json({ error: "Failed to verify purchase with Google." });
    }
});


// --- UPDATED SECURE ROUTE: TRANSCRIBE ---
app.post("/transcribe", authGuard, (req, res) => {
    const { userId } = req.user;

    // --- FINAL CHECK: Is this user a paying customer? ---
    const sql = `SELECT subscription_active FROM users WHERE id = ?`;
    db.get(sql, [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: "User not found." });
        }
        if (!user.subscription_active) {
            return res.status(403).json({ error: "Forbidden: Active subscription required." }); // <-- The final lock!
        }

        // If the user is a subscriber, proceed with transcription
        const uploadMiddleware = upload.single("audio");
        uploadMiddleware(req, res, async (uploadErr) => {
            if (!req.file) { return res.status(400).json({ error: "No audio file uploaded." }); }
            const tempPath = req.file.path;
            const finalPath = path.join("uploads", req.file.filename + path.extname(req.file.originalname));
            try {
                fs.renameSync(tempPath, finalPath);
                const transcription = await openai.audio.transcriptions.create({
                    file: fs.createReadStream(finalPath),
                    model: "whisper-1",
                });
                res.json({ text: transcription.text || "" });
            } catch (transcribeErr) {
                console.error(transcribeErr);
                res.status(500).json({ error: "Transcription failed." });
            } finally {
                if (fs.existsSync(finalPath)) { fs.unlinkSync(finalPath); }
            }
        });
    });
});

app.listen(port, () => console.log(`🚀 Backend running on port ${port}`));
