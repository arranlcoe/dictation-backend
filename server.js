import express from "express";
import multer from "multer";
import fs from "fs";
import OpenAI from "openai";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: "uploads/" });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.get("/", (_req, res) => res.send("OK"));

app.post("/transcribe", upload.single("audio"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No audio uploaded" });

    const transcription = await openai.audio.transcriptions.create({
      file: fs.createReadStream(req.file.path),
      model: "whisper-1"
    });

    fs.unlink(req.file.path, () => {});
    res.json({ text: transcription.text || "" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Transcription failed" });
  }
});

app.listen(port, () => console.log(`🚀 Backend running on port ${port}`));
