const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

// JWT Configuration
const JWT_CONFIG = {
  secret: process.env.JWT_SECRET || 'your-secret-key',
  expiresIn: '1h',
  algorithm: 'HS256',
  issuer: 'your-api-service',
  audience: 'your-client-app'
};

// Mock database with hashed passwords (hash 'admin' and 'user' for demo)
const users = [
  { id: 1, username: 'admin', password: bcrypt.hashSync('admin', 10), role: 'admin' },
  { id: 2, username: 'user', password: bcrypt.hashSync('user', 10), role: 'user' }
];

// Error messages helper
const getErrorMessage = (code) => ({
  'INVALID_CREDENTIALS': 'Invalid username or password',
  'MISSING_TOKEN': 'Authorization header or cookie with Bearer token required',
  'INVALID_TOKEN': 'Invalid authentication token',
  'TOKEN_EXPIRED': 'Token expired, please reauthenticate',
  'MALFORMED_TOKEN': 'Invalid token format',
  'INVALID_PAYLOAD': 'Token payload is invalid',
  'SERVER_ERROR': 'Authentication service error'
}[code] || 'Authentication failed');

// Extract token from Authorization header or cookie
function extractToken(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader?.startsWith('Bearer ')) return authHeader.split(' ')[1];
  return req.cookies?.token;
}

module.exports = {
  // Authenticates a user and returns a signed JWT
  authenticate: (username, password) => {
    try {
      const user = users.find(u => u.username === username);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        throw new Error('INVALID_CREDENTIALS');
      }

      const token = jwt.sign(
        {
          sub: user.id,
          username: user.username,
          role: user.role,
          iss: JWT_CONFIG.issuer,
          aud: JWT_CONFIG.audience
        },
        JWT_CONFIG.secret,
        {
          expiresIn: JWT_CONFIG.expiresIn,
          algorithm: JWT_CONFIG.algorithm
        }
      );

      return token;
    } catch (err) {
      throw err;
    }
  },

  // Middleware: Verifies JWT from request and attaches user to req
  verifyToken: (req, res, next) => {
    try {
      const token = extractToken(req);

      if (!token) {
        return res.status(401).json({
          success: false,
          error: 'MISSING_TOKEN',
          message: getErrorMessage('MISSING_TOKEN')
        });
      }

      const decoded = jwt.verify(token, JWT_CONFIG.secret, {
        algorithms: [JWT_CONFIG.algorithm],
        issuer: JWT_CONFIG.issuer,
        audience: JWT_CONFIG.audience
      });

      if (!decoded.sub) throw new Error('INVALID_PAYLOAD');

      req.user = {
        id: decoded.sub,
        username: decoded.username,
        role: decoded.role
      };

      next();
    } catch (err) {
      let status = 403;
      let error = 'INVALID_TOKEN';

      if (err instanceof jwt.TokenExpiredError) error = 'TOKEN_EXPIRED';
      else if (err instanceof jwt.JsonWebTokenError) error = 'MALFORMED_TOKEN';
      else if (err.message === 'INVALID_PAYLOAD') {
        error = 'INVALID_PAYLOAD';
        status = 400;
      } else {
        status = 500;
        error = 'SERVER_ERROR';
      }

      return res.status(status).json({
        success: false,
        error,
        message: getErrorMessage(error),
        ...(error === 'TOKEN_EXPIRED' && { renewUrl: '/api/refresh-token' })
      });
    }
  }

  // Optional: Add refreshToken logic here
};
