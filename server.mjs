import express from "express";
import cookieParser from "cookie-parser";
import {
  CompactEncrypt,
  compactDecrypt,
  importPKCS8,
  importSPKI,
  SignJWT,
  jwtVerify,
} from "jose";
import fs from "fs/promises";

const app = express();
const PORT = 3000;
const COOKIE_NAME = "token";
const COOKIE_MAX_AGE = 15 * 60 * 1000; // 15 minutes

app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

// Import the RSA keys from environment variables
const importKeyPair = async () => {
  const privateKeyPem = await fs.readFile("./private.pem", "utf8");
  const publicKeyPem = await fs.readFile("./public.pem", "utf8");

  const privateKey = await importPKCS8(privateKeyPem, "RS256");
  const publicKey = await importSPKI(publicKeyPem, "RSA-OAEP-256");
  return { privateKey, publicKey };
};

let encryptionKeyPair;
async function initializeEncryptionKeyPair() {
  encryptionKeyPair = await importKeyPair();
}

// Middleware to check and refresh the token
const checkAndRefreshToken = async (req, res, next) => {
  const tokenCookie = req.cookies[COOKIE_NAME];

  if (tokenCookie) {
    try {
      const payload = await decryptToken(tokenCookie);
      await refreshTokenIfNeeded(payload.userId, tokenCookie, res);
    } catch (err) {
      console.error("Token verification failed:", err.message);
      res.clearCookie(COOKIE_NAME); // Clear cookie if verification fails
    }
  }

  next();
};

// Login endpoint to generate the token
app.post("/login", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  const token = await generateEncryptedToken(userId);

  // Set the token as a secure HttpOnly cookie
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: COOKIE_MAX_AGE,
  });

  return res.json({ message: "Login successful, token issued!" });
});

// Secure API endpoint that checks and validates the token
app.get("/secure-access", async (req, res) => {
  const tokenCookie = req.cookies[COOKIE_NAME];

  if (!tokenCookie) {
    return res.status(401).json({ message: "Unauthorized, no token provided" });
  }

  try {
    const payload = await decryptToken(tokenCookie);
    return res.json({
      message: `Access granted, token is valid and the user is ${payload.userId}`,
    });
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized, invalid token" });
  }
});

// Start the server and initialize the database
initializeEncryptionKeyPair().then(() => {
  app.use(checkAndRefreshToken); // Apply the middleware
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});

// Function to refresh the token if needed
const refreshTokenIfNeeded = async (userId, tokenCookie, res) => {
  const tokenExpiration = jwt.decode(tokenCookie).exp * 1000; // Convert to milliseconds
  const currentTime = Date.now();
  const timeLeft = tokenExpiration - currentTime;

  if (timeLeft < 5 * 60 * 1000) {
    // 5 minutes threshold
    const newToken = await generateEncryptedToken(userId);

    // Set the new token as a secure HttpOnly cookie
    res.cookie(COOKIE_NAME, newToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: COOKIE_MAX_AGE,
    });
  }
};

// Function to generate an encrypted JWE token
const generateEncryptedToken = async (userId) => {
  const jwtPayload = { userId };

  // Step 1: Sign the JWT with RS256 using the private key
  const token = await new SignJWT(jwtPayload)
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(encryptionKeyPair.privateKey);

  // Step 2: Encrypt the signed JWT as JWE
  const jwe = await new CompactEncrypt(new TextEncoder().encode(token))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(encryptionKeyPair.publicKey);

  return jwe;
};

// Function to decrypt a JWE token
const decryptToken = async (token) => {
  const { plaintext } = await compactDecrypt(
    token,
    encryptionKeyPair.privateKey
  );
  const decodedToken = new TextDecoder().decode(plaintext);

  // Decode the signed JWT
  const { payload } = await jwtVerify(decodedToken, encryptionKeyPair.privateKey, {
    algorithms: ["RS256"],
  });

  return payload;
};
