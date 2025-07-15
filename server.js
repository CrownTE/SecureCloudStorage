require("dotenv").config();
const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const cors = require("cors");
const { ec: EC } = require("elliptic");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// AWS SDK v3 imports
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } = require("@aws-sdk/client-s3");

const app = express();
const port = process.env.PORT || 5000;

// AWS S3 client configuration
const s3Client = new S3Client({
  region: "eu-north-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({
  origin: ['http://localhost:3000', 'https://secure-cloud-storage-rouge.vercel.app'],
  credentials: true,
}));
app.use(express.json());

// ECC + AES Key Setup
const ec = new EC("p256");
let aesKey;
let keyPair;

function loadKeysFromEnv() {
  if (!process.env.AES_KEY) {
    throw new Error('AES_KEY environment variable is not defined');
  }
  if (!process.env.EC_PRIVATE_KEY) {
    throw new Error('EC_PRIVATE_KEY environment variable is not defined');
  }
  
  aesKey = Buffer.from(process.env.AES_KEY, "hex");
  keyPair = ec.keyFromPrivate(process.env.EC_PRIVATE_KEY);
}
loadKeysFromEnv();

// 🔐 Token Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 📄 File User Persistence
function loadUsers() {
  if (!fs.existsSync("users.json")) fs.writeFileSync("users.json", "[]");
  const users = JSON.parse(fs.readFileSync("users.json", "utf8"));
  return users.filter(u => u.username && u.password);
}
function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

// 🔐 Auth Routes
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  if (users.find(u => u.username === username)) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  saveUsers(users);
  res.json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// 📤 Upload (to user-specific folder)
app.post("/upload", authenticateToken, upload.single("file"), async (req, res) => {
  try {
    const username = req.user.username;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    const encrypted = Buffer.concat([iv, cipher.update(req.file.buffer), cipher.final()]);

    const key = `${username}/encrypted-${Date.now()}-${req.file.originalname}`;
    
    const command = new PutObjectCommand({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: key,
      Body: encrypted,
    });

    const data = await s3Client.send(command);
    const fileUrl = `https://${process.env.AWS_BUCKET_NAME}.s3.eu-north-1.amazonaws.com/${key}`;
    
    res.json({ message: "File uploaded", fileUrl });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// 📄 List files for the logged-in user
app.get("/files", authenticateToken, async (req, res) => {
  try {
    const prefix = `${req.user.username}/`;

    const command = new ListObjectsV2Command({
      Bucket: process.env.AWS_BUCKET_NAME,
      Prefix: prefix,
    });

    const data = await s3Client.send(command);
    const files = (data.Contents || []).map(obj => obj.Key.replace(prefix, ""));
    
    res.json({ files });
  } catch (err) {
    console.error("List files error:", err);
    res.status(500).json({ error: "Error listing files" });
  }
});

// 📥 Download user's own file
app.get("/download/:filename", authenticateToken, async (req, res) => {
  try {
    const key = `${req.user.username}/${req.params.filename}`;

    const command = new GetObjectCommand({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: key,
    });

    const data = await s3Client.send(command);
    
    // Convert stream to buffer for v3
    const chunks = [];
    for await (const chunk of data.Body) {
      chunks.push(chunk);
    }
    const buffer = Buffer.concat(chunks);

    const iv = buffer.slice(0, 16);
    const encrypted = buffer.slice(16);
    const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    res.set("Content-Disposition", `attachment; filename="${req.params.filename.replace("encrypted-", "")}"`);
    res.send(decrypted);
  } catch (err) {
    console.error("Download error:", err);
    res.status(404).json({ error: "File not found" });
  }
});

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
