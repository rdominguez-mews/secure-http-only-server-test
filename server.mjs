import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = 'your_jwt_secret';
const BASIC_TOKEN_LIFETIME = '2m'; // Short-lived (2 minutes)
const REFRESH_TOKEN_LIFETIME = '30m'; // Long-lived (30 minutes)

// Generate a JWT token with userId
function generateToken(userId, expiresIn) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn });
}

// Middleware to validate the basic token and refresh if needed
const validateBasicToken = (req, res, next) => {
  const basicToken = req.cookies.basicToken;
  const refreshToken = req.cookies.refreshToken;

  if (basicToken) {
    try {
      // Verify the basicToken JWT
      jwt.verify(basicToken, JWT_SECRET);
      return next();
    } catch (err) {
      console.log('Basic token expired.');
    }
  }

  if (refreshToken) {
    try {
      // Verify the refreshToken and issue a new basicToken if valid
      const decoded = jwt.verify(refreshToken, JWT_SECRET);
      const newBasicToken = generateToken(decoded.userId, BASIC_TOKEN_LIFETIME);
      res.cookie('basicToken', newBasicToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: 2 * 60 * 1000, // 2 minutes in milliseconds
      });
      console.log('Basic token refreshed.');
      return next();
    } catch (err) {
      console.log('Refresh token expired.');
      return res.status(401).send('Access Denied: Tokens expired');
    }
  } else {
    return res.status(401).send('Access Denied: No valid tokens');
  }
};

// Set initial tokens (both basic and refresh tokens)
app.get('/set-tokens', (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).send('User ID is required');
  }

  const basicToken = generateToken(userId, BASIC_TOKEN_LIFETIME);
  const refreshToken = generateToken(userId, REFRESH_TOKEN_LIFETIME);

  res.cookie('basicToken', basicToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 2 * 60 * 1000, // 2 minutes in milliseconds
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 30 * 60 * 1000, // 30 minutes in milliseconds
  });

  res.send('Tokens set');
});

// Protected endpoint that requires a valid basicToken
app.get('/protected-endpoint', validateBasicToken, (req, res) => {
  res.json({ message: 'Protected data accessed' });
});

// Start the Express server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Express server running at http://localhost:${PORT}`);
});
