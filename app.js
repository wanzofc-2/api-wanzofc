const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');  // Untuk melayani file statis
const settings = require('./setting');  // Menggunakan settings.js untuk konfigurasi
const app = express();
const PORT = process.env.PORT || 50000;
const SECRET_KEY = settings.tokens;

app.use(bodyParser.json());

// Fungsi untuk membaca users.json
const readUsers = () => {
  const data = fs.readFileSync('users.json', 'utf8');
  return JSON.parse(data);
};

// Fungsi untuk menulis ke users.json
const writeUsers = (users) => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};

// Menyajikan file statis (index.html, signup.html, signin.html, dan style.css)
app.use(express.static(__dirname)); // Secara langsung menggunakan direktori utama

// Route untuk menampilkan index.html saat mengakses root URL
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Route untuk Sign Up
app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const users = readUsers();
    const existingUser = users.find(u => u.username === username);

    if (existingUser) {
        return res.status(400).send({ message: 'Username already exists.' });
    }

    // Encrypt password before saving
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).send({ message: 'Error hashing password.' });
        }

        users.push({ username, password: hashedPassword });
        writeUsers(users);  // Menyimpan data ke file
        res.status(200).send({ message: 'User registered successfully!' });
    });
});

// Route untuk Sign In
app.post('/signin', (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(404).send({ message: 'User not found.' });
  }

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (!isMatch) {
      return res.status(401).send({ message: 'Invalid password.' });
    }

    const token = jwt.sign({ id: username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Route untuk mendapatkan API key untuk Instagram, YouTube, atau TikTok
app.post('/get-api-key', verifyToken, (req, res) => {
    const feature = req.body.feature;

    if (!feature) {
        return res.status(400).send({ message: 'Feature is required.' });
    }

    const apiKey = 'wanzofc'; // API key yang dapat digunakan semua orang

    if (feature === 'instagram') {
        res.json({
            message: 'Instagram API key generated successfully.',
            apiKey,
            feature: 'Instagram'
        });
    } else if (feature === 'youtube') {
        res.json({
            message: 'YouTube API key generated successfully.',
            apiKey,
            feature: 'YouTube'
        });
    } else if (feature === 'tiktok') {
        res.json({
            message: 'TikTok API key generated successfully.',
            apiKey,
            feature: 'TikTok'
        });
    } else {
        res.status(400).send({ message: 'Invalid feature.' });
    }
});

// Middleware untuk validasi token JWT
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send({ message: 'No token provided.' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Failed to authenticate token.' });
    req.userId = decoded.id;
    next();
  });
}

// Run the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
