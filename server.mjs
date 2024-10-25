import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_secret_key'; // Change this to a strong secret
const COOKIE_NAME = 'token';
const COOKIE_MAX_AGE = 15 * 60 * 1000; // 15 minutes

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public')); // Serve static files from the "public" directory

// Initialize SQLite database
const dbPromise = open({
    filename: './database.sqlite',
    driver: sqlite3.Database
});

// Create the user_tokens table if it doesn't exist
const initializeDatabase = async () => {
    const db = await dbPromise;
    await db.exec(`
        CREATE TABLE IF NOT EXISTS user_tokens (
            userId TEXT PRIMARY KEY,
            token TEXT NOT NULL
        )
    `);
};

// Middleware to check and refresh the token
const checkAndRefreshToken = async (req, res, next) => {
    const tokenCookie = req.cookies[COOKIE_NAME];

    if (tokenCookie) {
        try {
            const payload = jwt.verify(tokenCookie, JWT_SECRET);
            const db = await dbPromise;
            const storedToken = await getTokenFromDB(db, payload.userId);

            if (storedToken && storedToken.token === tokenCookie) {
                await refreshTokenIfNeeded(db, payload.userId, tokenCookie, res);
            } else {
                throw new Error('Token mismatch');
            }
        } catch (err) {
            console.error('Token verification failed:', err.message);
            res.clearCookie(COOKIE_NAME); // Clear cookie if verification fails
        }
    }

    next();
};

// Login endpoint to generate the token
app.post('/login', async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required' });
    }

    const token = await generateAndStoreToken(userId);
    
    // Set the token as a secure HttpOnly cookie
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: COOKIE_MAX_AGE
    });

    return res.json({ message: 'Login successful, token issued!' });
});

// Secure API endpoint that checks and validates the token
app.get('/secure-access', async (req, res) => {
    const tokenCookie = req.cookies[COOKIE_NAME];

    if (!tokenCookie) {
        return res.status(401).json({ message: 'Unauthorized, no token provided' });
    }

    try {
        const payload = jwt.verify(tokenCookie, JWT_SECRET);

        const db = await dbPromise;
        const storedToken = await getTokenFromDB(db, payload.userId);

        if (storedToken && storedToken.token === tokenCookie) {
            return res.json({ message: `Access granted, token is valid and the user is ${payload.userId}`  });
        } else {
            throw new Error('Token mismatch');
        }
    } catch (err) {
        return res.status(401).json({ message: 'Unauthorized, invalid token' });
    }
});

// Start the server and initialize the database
initializeDatabase().then(() => {
    app.use(checkAndRefreshToken); // Apply the middleware
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
});

// Function to get the token from the database
const getTokenFromDB = async (db, userId) => {
    return await db.get('SELECT token FROM user_tokens WHERE userId = ?', userId);
};

// Function to refresh the token if needed
const refreshTokenIfNeeded = async (db, userId, tokenCookie, res) => {
    const tokenExpiration = (jwt.decode(tokenCookie)).exp * 1000; // Convert to milliseconds
    const currentTime = Date.now();
    const timeLeft = tokenExpiration - currentTime;

    if (timeLeft < 5 * 60 * 1000) { // 5 minutes threshold
        const newToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '15m' });
        await db.run('UPDATE user_tokens SET token = ? WHERE userId = ?', [newToken, userId]);

        // Set the new token as a secure HttpOnly cookie
        res.cookie(COOKIE_NAME, newToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: COOKIE_MAX_AGE
        });
    }
};

// Function to generate a new token and store it in the database
const generateAndStoreToken = async (userId) => {
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '15m' });
    const db = await dbPromise;
    await db.run('INSERT OR REPLACE INTO user_tokens (userId, token) VALUES (?, ?)', [userId, token]);
    return token;
};
