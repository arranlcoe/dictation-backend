import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path"; // We need this to handle file extensions
import OpenAI from "openai";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: "uploads/" });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.get("/", (_req, res) => res.send("OK"));

app.post("/transcribe", upload.single("audio"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No audio uploaded" });
  }

  const tempPath = req.file.path;
  // Create a new path that includes the original file extension
  const finalPath = path.join("uploads", req.file.filename + path.extname(req.file.originalname));

  try {
    // Rename the file to include its extension (e.g., .m4a)
    fs.renameSync(tempPath, finalPath);

    const transcription = await openai.audio.transcriptions.create({
      file: fs.createReadStream(finalPath), // Send the renamed file
      model: "whisper-1",
    });

    res.json({ text: transcription.text || "" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Transcription failed" });
  } finally {
    // Clean up the file after we're done with it
    if (fs.existsSync(finalPath)) {
      fs.unlinkSync(finalPath);
    }
  }
});

app.listen(port, () => console.log(`🚀 Backend running on port ${port}`));
