const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  audit: 3,
  debug: 4
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  audit: 'cyan',
  debug: 'blue'
};

// Add colors to winston
winston.addColors(colors);

// Create format for logs
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  })
);

// Create the logger
const logger = winston.createLogger({
  levels,
  level: process.env.LOG_LEVEL || 'audit',
  format: logFormat,
  transports: [
    // Audit log - HIPAA compliance requires separate audit logs
    new winston.transports.File({
      filename: path.join(logsDir, 'audit.log'),
      level: 'audit',
      maxsize: 10485760, // 10MB
      maxFiles: 100, // Keep 100 files
      tailable: true
    }),
    // Error log
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 10485760,
      maxFiles: 30
    }),
    // Combined log
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 10485760,
      maxFiles: 30
    })
  ]
});

// Add console transport for non-production environments
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// HIPAA Audit Log Functions
const auditLogger = {
  // Log user authentication events
  logAuthentication: (userId, username, success, ip, reason = null) => {
    logger.log('audit', 'Authentication Event', {
      eventType: 'AUTHENTICATION',
      userId,
      username,
      success,
      ip,
      reason,
      timestamp: new Date().toISOString()
    });
  },

  // Log PHI access events
  logPHIAccess: (userId, username, action, resource, ip, metadata = {}) => {
    logger.log('audit', 'PHI Access Event', {
      eventType: 'PHI_ACCESS',
      userId,
      username,
      action,
      resource,
      ip,
      metadata,
      timestamp: new Date().toISOString()
    });
  },

  // Log PHI modifications
  logPHIModification: (userId, username, action, resource, ip, changes = {}) => {
    logger.log('audit', 'PHI Modification Event', {
      eventType: 'PHI_MODIFICATION',
      userId,
      username,
      action,
      resource,
      ip,
      changes,
      timestamp: new Date().toISOString()
    });
  },

  // Log file uploads
  logFileUpload: (userId, username, filename, filesize, ip, success, error = null) => {
    logger.log('audit', 'File Upload Event', {
      eventType: 'FILE_UPLOAD',
      userId,
      username,
      filename,
      filesize,
      ip,
      success,
      error,
      timestamp: new Date().toISOString()
    });
  },

  // Log data exports/downloads
  logDataExport: (userId, username, exportType, recordCount, ip) => {
    logger.log('audit', 'Data Export Event', {
      eventType: 'DATA_EXPORT',
      userId,
      username,
      exportType,
      recordCount,
      ip,
      timestamp: new Date().toISOString()
    });
  },

  // Log authorization failures
  logAuthorizationFailure: (userId, username, resource, requiredRole, userRole, ip) => {
    logger.log('audit', 'Authorization Failure', {
      eventType: 'AUTHORIZATION_FAILURE',
      userId,
      username,
      resource,
      requiredRole,
      userRole,
      ip,
      timestamp: new Date().toISOString()
    });
  },

  // Log security events
  logSecurityEvent: (eventType, description, severity, ip, metadata = {}) => {
    logger.log('audit', 'Security Event', {
      eventType: 'SECURITY',
      subType: eventType,
      description,
      severity,
      ip,
      metadata,
      timestamp: new Date().toISOString()
    });
  },

  // Log system events
  logSystemEvent: (eventType, description, metadata = {}) => {
    logger.log('audit', 'System Event', {
      eventType: 'SYSTEM',
      subType: eventType,
      description,
      metadata,
      timestamp: new Date().toISOString()
    });
  }
};

// Export logger and audit functions
module.exports = {
  logger,
  auditLogger
};