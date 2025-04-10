const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Always use environment variables in production

// Mock user database
const users = [
  { id: 1, username: 'admin', password: 'admin', role: 'admin' },
  { id: 2, username: 'user', password: 'user', role: 'user' }
];

// Error message helper
function getErrorMessage(code) {
  const messages = {
    'INVALID_CREDENTIALS': 'Invalid username or password',
    'MISSING_TOKEN': 'Authorization header with Bearer token required',
    'INVALID_TOKEN': 'Invalid authentication token',
    'TOKEN_EXPIRED': 'Token expired, please reauthenticate',
    'MALFORMED_TOKEN': 'Invalid token format',
    'INVALID_PAYLOAD': 'Token payload is invalid',
    'SERVER_ERROR': 'Authentication service error'
  };
  return messages[code] || 'Authentication failed';
}

module.exports = {
  authenticate: (username, password) => {
    try {
      const user = users.find(u => 
        u.username === username && 
        u.password === password
      );
      
      if (!user) {
        throw new Error('INVALID_CREDENTIALS');
      }

      return jwt.sign(
        {
          sub: user.id,  // Standard JWT claim for subject
          username: user.username,
          role: user.role,
          iss: 'your-api-service', // Issuer
          aud: 'your-client-app'   // Audience
        },
        SECRET,
        { 
          expiresIn: '1h',
          algorithm: 'HS256'
        }
      );
      
    } catch (err) {
      throw err; // Rethrow for route handler to catch
    }
  },
  
  verifyToken: (req, res, next) => {
    try {
      // Check both Authorization header and cookies
      const authHeader = req.headers.authorization || req.headers.Authorization;
      const tokenFromCookie = req.cookies?.token;
      
      let token;
      
      if (authHeader?.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
      } else if (tokenFromCookie) {
        token = tokenFromCookie;
      } else {
        return res.status(401).json({
          success: false,
          error: 'MISSING_TOKEN',
          message: getErrorMessage('MISSING_TOKEN')
        });
      }
      
      const decoded = jwt.verify(token, SECRET, {
        algorithms: ['HS256'],
        ignoreExpiration: false,
        issuer: 'your-api-service',
        audience: 'your-client-app'
      });

      if (!decoded.sub) {
        throw new Error('INVALID_PAYLOAD');
      }

      req.user = {
        id: decoded.sub,
        username: decoded.username,
        role: decoded.role
      };

      next();
    } catch (err) {
      let status = 403;
      let error = 'INVALID_TOKEN';
      
      if (err instanceof jwt.TokenExpiredError) {
        error = 'TOKEN_EXPIRED';
      } else if (err instanceof jwt.JsonWebTokenError) {
        error = 'MALFORMED_TOKEN';
      } else if (err.message === 'INVALID_PAYLOAD') {
        status = 400;
        error = err.message;
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
};