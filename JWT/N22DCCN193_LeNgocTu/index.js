require('dotenv').config();
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const express = require('express')
const sqlite3 = require('sqlite3')

const db = new sqlite3.Database('./database.db')
const app = express()
app.use(express.json());


const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;


// create table if net exists
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
});

// jwt middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.userId = decoded.userId;
        next();
    });
};

// API
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword],
            function (err) {
                if (err) {
                    return res.status(400).json({ message: 'Username already exists' });
                }
                res.status(201).json({ message: 'User registered', userId: this.lastID });
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: user.id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

        res.json({ accessToken, refreshToken });
    });
});

app.post('/refresh-token', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token required' });
    }

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });

        const accessToken = jwt.sign({ userId: user.userId }, JWT_SECRET, { expiresIn: '15m' });
        res.json({ accessToken });
    });
});

app.get('/who-am-i', authenticateToken, (req, res) => {
    res.json({ message: 'Your user id:', user: req.userId });
});

// Run server
app.listen(PORT, ()=>{
    console.log("Server run on port", PORT);

    // show all user in data bases
    console.log("Users in database:")
    db.all("SELECT * FROM users", [], (err, rows)=>{
        if (err) {
            console.error('Error querying users:', err.message);
            return;
        }
        console.table(rows);
    })
})
