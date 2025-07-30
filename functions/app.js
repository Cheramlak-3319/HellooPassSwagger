const express = require("express");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const path = require("path");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const auth = require("../auth.js"); // Your optimized auth module
require("dotenv").config();

const app = express();
const PORT = 4000;

// JWT config
const SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Load Swagger YAML
const swaggerDocument = YAML.load(path.join(__dirname, "swagger.yaml"));

// Middleware setup
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Token extraction utility
const extractToken = (req) => {
  const header = req.headers.authorization || req.headers.Authorization;
  if (header?.startsWith("Bearer ")) return header.split(" ")[1];
  return req.cookies?.token;
};

// Swagger Authentication Middleware
const swaggerAuthMiddleware = (req, res, next) => {
  const publicPaths = ['/login', '/api-docs', '/api/api-docs'];
  if (publicPaths.some(p => req.path.startsWith(p))) return next();

  const token = extractToken(req);
  if (!token) {
    if (req.accepts('html')) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>API Login</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
            form { display: flex; flex-direction: column; gap: 10px; }
            input, button { padding: 8px; font-size: 16px; }
            button { background: #0066cc; color: white; border: none; cursor: pointer; }
          </style>
        </head>
        <body>
          <h1>API Documentation Login</h1>
          <form action="/login" method="POST" onsubmit="event.submitter.disabled=true">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
          </form>
          ${req.query.error ? `<p style="color:red">${req.query.error}</p>` : ''}
        </body>
        </html>
      `);
    }
    return res.status(401).json({ error: "Unauthorized" });
  }

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      if (req.accepts('html')) {
        return res.redirect('/?error=Invalid+or+expired+token');
      }
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = decoded;
    next();
  });
};

// Login Route
app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;
    const token = auth.authenticate(username, password);

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000
    });

    if (req.accepts("html")) {
      return res.redirect("/api/api-docs");
    }

    res.json({ success: true, token });
  } catch (err) {
    const errorMessage = encodeURIComponent(err.message);
    if (req.accepts("html")) {
      return res.redirect(`/?error=${errorMessage}`);
    }

    res.status(401).json({
      success: false,
      error: err.message
    });
  }
});

// Protected Test Route
app.get("/protected", auth.verifyToken, (req, res) => {
  if (req.accepts("html")) {
    return res.send(`
      <h1>Protected Content</h1>
      <p>Welcome ${req.user.username}!</p>
      <a href="/api/api-docs">View API Documentation</a>
    `);
  }

  res.json({
    success: true,
    user: req.user
  });
});

// Apply Swagger Auth Middleware
app.use(swaggerAuthMiddleware);

// Serve Swagger
app.use("/api/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Start Server
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📘 Swagger available at http://localhost:${PORT}/api/api-docs`);
});
