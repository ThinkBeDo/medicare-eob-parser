const { verifyToken, getUserById } = require('../auth/auth');

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
  
  // Get user details
  const user = getUserById(decoded.userId);
  if (!user) {
    return res.status(403).json({ error: 'User not found' });
  }
  
  req.user = user;
  next();
}

// Middleware to check role-based access
function authorizeRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Middleware for PHI access logging
function logPHIAccess(action) {
  return (req, res, next) => {
    const auditLog = {
      timestamp: new Date().toISOString(),
      userId: req.user?.id || 'anonymous',
      username: req.user?.username || 'anonymous',
      action: action,
      resource: req.path,
      method: req.method,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent']
    };
    
    // In production, this should be logged to a secure audit log
    console.log('[PHI ACCESS AUDIT]', JSON.stringify(auditLog));
    
    next();
  };
}

module.exports = {
  authenticateToken,
  authorizeRole,
  logPHIAccess
};