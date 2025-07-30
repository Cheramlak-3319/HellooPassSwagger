const express = require("express");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const path = require("path");
const auth = require('../auth.js');
const cors = require("cors");
// Load the swagger.yaml file
const swaggerDocument = YAML.load(path.join(__dirname, "swagger.yaml"));

const app = express();
const PORT = 4000;

// Middleware setup
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Updated Swagger auth middleware
const swaggerAuthMiddleware = (req, res, next) => {
  // Allow Swagger UI assets and login endpoint
  if (req.path.includes('/api-docs') || req.path === '/login') {
    return next();
  }

  // Check for existing token
  const token = req.cookies?.token || 
               req.headers.authorization?.split(' ')[1];

  if (!token) {
    if (req.accepts('html')) {
      // Serve login form
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
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Verify token
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      if (req.accepts('html')) {
        return res.redirect('/?error=Invalid+or+expired+token');
      }
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
  });
};

// Updated login route
app.post('/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const token = auth.authenticate(username, password);
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });

    // Redirect to protected content after login
    if (req.accepts('html')) {
      return res.redirect('/api/api-docs');
    }
    
    res.json({ success: true, token });
  } catch (err) {
    if (req.accepts('html')) {
      return res.redirect(`/?error=${encodeURIComponent(err.message)}`);
    }
    res.status(401).json({
      success: false,
      error: err.message
    });
  }
});

// Protected route with HTML response option
app.get('/protected', auth.verifyToken, (req, res) => {
  if (req.accepts('html')) {
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

// Apply Swagger auth middleware
app.use(swaggerAuthMiddleware);

app.use("/api/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger UI available at http://localhost:${PORT}/api-docs`);
});