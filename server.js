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

dotenv.config();

// --- DATABASE SETUP (using a simple file-based SQLite database) ---
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error("Error opening database", err.message);
    } else {
        console.log("Database connected.");
        // Create the users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            subscription_active BOOLEAN DEFAULT FALSE
        )`);
    }
});

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: "uploads/" });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// --- MIDDLEWARE ---
app.use(bodyParser.json()); // To parse JSON bodies from requests

// --- PUBLIC ROUTES (No authentication needed) ---

app.get("/", (_req, res) => res.send("OK"));

// 1. User Registration Route
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (email, password) VALUES (?, ?)`;
    db.run(sql, [email, hashedPassword], function(err) {
        if (err) {
            // "UNIQUE constraint failed" means the email is already taken
            if (err.message.includes("UNIQUE")) {
                return res.status(409).json({ error: "Email already exists." });
            }
            return res.status(500).json({ error: "Database error." });
        }
        res.status(201).json({ message: "User created successfully." });
    });
});

// 2. User Login Route
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        // --- Create the JWT (the "keycard") ---
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET, // A secret key for signing tokens
            { expiresIn: '30d' } // Token is valid for 30 days
        );

        res.json({ token });
    });
});


// --- AUTHENTICATION MIDDLEWARE (The "Guard") ---
// This function will run before any secure route.
const authGuard = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Forbidden: Invalid token." });
        }
        req.user = user; // Add the user info (userId, email) to the request object
        next(); // If the token is valid, proceed to the next function (the transcribe logic)
    });
};


// --- SECURE ROUTE (Requires a valid token) ---

app.post("/transcribe", authGuard, (req, res) => { // NOTE: authGuard is added here!
    // For now, we only check if the user is authenticated.
    // LATER, we will add a check for subscription status here.
    
    // --- The transcription logic is the same as before ---
    const uploadMiddleware = upload.single("audio");
    uploadMiddleware(req, res, async (err) => {
        if (!req.file) {
            return res.status(400).json({ error: "No audio file uploaded." });
        }

        const tempPath = req.file.path;
        const finalPath = path.join("uploads", req.file.filename + path.extname(req.file.originalname));

        try {
            fs.renameSync(tempPath, finalPath);
            const transcription = await openai.audio.transcriptions.create({
                file: fs.createReadStream(finalPath),
                model: "whisper-1",
            });
            res.json({ text: transcription.text || "" });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Transcription failed." });
        } finally {
            if (fs.existsSync(finalPath)) {
                fs.unlinkSync(finalPath);
            }
        }
    });
});

app.listen(port, () => console.log(`🚀 Backend running on port ${port}`));
