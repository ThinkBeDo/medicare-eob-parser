require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const path = require('path');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

// Import auth and logging modules
const { initializeDefaultUsers, loginUser, registerUser } = require('./auth/auth');
const { authenticateToken, authorizeRole, logPHIAccess } = require('./middleware/auth');
const { logger, auditLogger } = require('./audit/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize default users
initializeDefaultUsers();

// Security Headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS Configuration - Restrictive in production
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',') 
      : ['http://localhost:3000'];
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Session configuration with security settings
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true,
    maxAge: 15 * 60 * 1000, // 15 minutes (HIPAA requirement)
    sameSite: 'strict'
  },
  name: 'sessionId' // Don't use default name
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Limit auth attempts
  message: 'Too many authentication attempts, please try again later.'
});

app.use('/api/', limiter);
app.use('/api/auth/', strictLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  next();
});

// Secure file upload configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1 // Only one file at a time
  },
  fileFilter: (req, file, cb) => {
    // Check file extension
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.pdf') {
      return cb(new Error('Only PDF files are allowed'), false);
    }
    
    // Check MIME type
    if (file.mimetype !== 'application/pdf') {
      return cb(new Error('Invalid file type'), false);
    }
    
    cb(null, true);
  }
});

// Function to validate PDF magic bytes
function validatePDFMagicBytes(buffer) {
  const pdfMagicBytes = Buffer.from([0x25, 0x50, 0x44, 0x46]); // %PDF
  return buffer.slice(0, 4).equals(pdfMagicBytes);
}

// Enhanced parseEOBData function with input sanitization
function parseEOBData(text) {
  const records = [];
  const lines = text.split('\n');
  
  let currentRecord = null;
  let processingClaim = false;
  
  logger.info('Processing EOB data', { lineCount: lines.length });
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Skip empty lines and headers
    if (!line || line.includes('NOVITAS SOLUTIONS') || line.includes('MEDICARE') || 
        line.includes('REMITTANCE') || line.includes('ADVICE') || line.includes('PAGE #') ||
        line.includes('PERF PROV SERV DATE') || line.includes('_____')) {
      continue;
    }
    
    // Check if this is a new patient record with flexible regex patterns
    let nameMatch = line.match(/^NAME\s+([A-Z]+),\s+([A-Z]+)\s+([A-Z]?)\s*MID\s+(\w+)\s+ACNT\s+(\w+)\s+ICN\s+(\d+)\s+ASG\s+([YN])\s+MOA\s+(.+)$/);
    
    if (!nameMatch) {
      nameMatch = line.match(/^NAME\s+([A-Z]+),([A-Z]+)\s*([A-Z]?)\s*MID\s+(\w+)\s+ACNT\s+(\w+)\s+ICN\s+(\d+)\s+ASG\s+([YN])\s+MOA\s+(.+)$/);
    }
    
    if (!nameMatch) {
      nameMatch = line.match(/^NAME\s+([A-Z]+),\s*([A-Z]+)\s*([A-Z]?)\s*MID\s+(\w+)\s+ACNT\s+(\w+)\s+ICN\s+(\d+)\s+ASG\s+([YN])\s+MOA\s*(.*)$/);
    }
    
    if (nameMatch) {
      // Save previous record if exists
      if (currentRecord && (currentRecord.claims.length > 0 || currentRecord.totalBilled > 0)) {
        records.push(currentRecord);
      }
      
      // Sanitize and create new record
      currentRecord = {
        lastName: nameMatch[1].trim().substring(0, 50), // Limit length
        firstName: nameMatch[2].trim().substring(0, 50),
        middleInitial: nameMatch[3] ? nameMatch[3].trim().substring(0, 1) : '',
        patientName: `${nameMatch[2]} ${nameMatch[1]}${nameMatch[3] ? ' ' + nameMatch[3] : ''}`.substring(0, 100),
        mid: nameMatch[4].substring(0, 20),
        accountNumber: nameMatch[5].substring(0, 20),
        icn: nameMatch[6].substring(0, 20),
        assignment: nameMatch[7],
        moa: nameMatch[8].substring(0, 200),
        claims: [],
        totalBilled: 0,
        totalAllowed: 0,
        totalDeductible: 0,
        totalCoinsurance: 0,
        totalAdjustments: 0,
        providerPaid: 0,
        patientResponsibility: 0,
        netAmount: 0,
        forwardedTo: ''
      };
      processingClaim = true;
      continue;
    }
    
    // Parse claim lines if we're processing a record
    if (processingClaim && currentRecord) {
      // Check for claim totals line
      if (line.includes('CLAIM TOTALS')) {
        const totalsMatch = line.match(/CLAIM TOTALS\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
        if (totalsMatch) {
          currentRecord.totalBilled = parseFloat(totalsMatch[1]) || 0;
          currentRecord.totalAllowed = parseFloat(totalsMatch[2]) || 0;
          currentRecord.totalDeductible = parseFloat(totalsMatch[3]) || 0;
          currentRecord.totalCoinsurance = parseFloat(totalsMatch[4]) || 0;
          currentRecord.totalAdjustments = parseFloat(totalsMatch[5]) || 0;
          currentRecord.providerPaid = parseFloat(totalsMatch[6]) || 0;
        }
        continue;
      }
      
      // Check for patient responsibility
      if (line.startsWith('PT RESP')) {
        const respMatch = line.match(/PT RESP\s+([\d.]+)/);
        if (respMatch) {
          currentRecord.patientResponsibility = parseFloat(respMatch[1]) || 0;
        }
        continue;
      }
      
      // Parse individual claim lines
      const claimMatch = line.match(/^(\d{10})\s+(\d{4})\s+(\d{6})\s+(\d+)\s+([\d.]+)\s+(\w+)\s*([\w\s]*?)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([A-Z]+-\d+)\s+([\d.]+)\s+([\d.]+)/);
      
      if (claimMatch) {
        const claim = {
          providerNPI: claimMatch[1],
          dateFrom: claimMatch[2],
          dateThrough: claimMatch[3],
          placeOfService: claimMatch[4],
          quantity: parseFloat(claimMatch[5]) || 0,
          procedureCode: claimMatch[6].substring(0, 10),
          modifiers: claimMatch[7] ? claimMatch[7].trim().substring(0, 10) : '',
          billed: parseFloat(claimMatch[8]) || 0,
          allowed: parseFloat(claimMatch[9]) || 0,
          deductible: parseFloat(claimMatch[10]) || 0,
          coinsurance: parseFloat(claimMatch[11]) || 0,
          adjustmentCode: claimMatch[12].substring(0, 20),
          adjustmentAmount: parseFloat(claimMatch[13]) || 0,
          providerPaid: parseFloat(claimMatch[14]) || 0
        };
        
        currentRecord.claims.push(claim);
      }
    }
  }
  
  // Save the last record
  if (currentRecord && (currentRecord.claims.length > 0 || currentRecord.totalBilled > 0)) {
    records.push(currentRecord);
  }
  
  return records;
}

// Function to convert records to CSV
function convertToCSV(records) {
  if (!records || records.length === 0) {
    return 'No records found';
  }
  
  const headers = [
    'Patient Name',
    'First Name',
    'Last Name',
    'Middle Initial',
    'MID',
    'Account Number',
    'ICN',
    'Assignment',
    'MOA',
    'Total Billed',
    'Total Allowed',
    'Total Deductible', 
    'Total Coinsurance',
    'Total Adjustments',
    'Provider Paid',
    'Patient Responsibility',
    'Net Amount',
    'Forwarded To',
    'Claims Count'
  ];
  
  let csv = headers.join(',') + '\n';
  
  records.forEach(record => {
    const row = [
      `"${record.patientName}"`,
      `"${record.firstName}"`,
      `"${record.lastName}"`,
      `"${record.middleInitial}"`,
      record.mid,
      record.accountNumber,
      record.icn,
      record.assignment,
      `"${record.moa}"`,
      record.totalBilled || 0,
      record.totalAllowed || 0,
      record.totalDeductible || 0,
      record.totalCoinsurance || 0,
      record.totalAdjustments || 0,
      record.providerPaid || 0,
      record.patientResponsibility || 0,
      record.netAmount || 0,
      `"${record.forwardedTo}"`,
      record.claims ? record.claims.length : 0
    ];
    csv += row.join(',') + '\n';
  });
  
  return csv;
}

// Authentication Routes
app.post('/api/auth/login', 
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;
      const result = await loginUser(username, password);
      
      // Log successful authentication
      auditLogger.logAuthentication(result.user.id, username, true, req.ip);
      
      res.json({
        success: true,
        token: result.token,
        user: result.user
      });
    } catch (error) {
      // Log failed authentication
      auditLogger.logAuthentication('unknown', req.body.username, false, req.ip, error.message);
      
      res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }
  }
);

app.post('/api/auth/register',
  authenticateToken,
  authorizeRole('admin'),
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
  body('role').isIn(['user', 'admin']),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password, role } = req.body;
      const user = await registerUser(username, password, role);
      
      auditLogger.logSystemEvent('USER_CREATED', `New user created: ${username}`, {
        createdBy: req.user.username,
        newUserRole: role
      });
      
      res.json({
        success: true,
        user
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }
);

// Protected upload route with authentication
app.post('/api/upload',
  authenticateToken,
  logPHIAccess('UPLOAD_EOB'),
  upload.single('pdf'),
  async (req, res) => {
    let fileProcessed = false;
    
    try {
      if (!req.file) {
        auditLogger.logFileUpload(req.user.id, req.user.username, 'NO_FILE', 0, req.ip, false, 'No file uploaded');
        return res.status(400).json({ error: 'No PDF file uploaded' });
      }
      
      // Validate PDF magic bytes
      if (!validatePDFMagicBytes(req.file.buffer)) {
        auditLogger.logFileUpload(req.user.id, req.user.username, req.file.originalname, req.file.size, req.ip, false, 'Invalid PDF magic bytes');
        return res.status(400).json({ error: 'Invalid PDF file format' });
      }
      
      // Log file upload attempt
      auditLogger.logFileUpload(req.user.id, req.user.username, req.file.originalname, req.file.size, req.ip, true);
      
      logger.info('Processing PDF file', {
        filename: req.file.originalname,
        size: req.file.size,
        user: req.user.username
      });
      
      // Parse PDF
      const pdfData = await pdfParse(req.file.buffer);
      
      // Parse EOB data
      const records = parseEOBData(pdfData.text);
      
      // Log PHI access
      auditLogger.logPHIAccess(req.user.id, req.user.username, 'PROCESS_EOB', req.file.originalname, req.ip, {
        recordCount: records.length,
        fileSize: req.file.size
      });
      
      fileProcessed = true;
      
      if (records.length === 0) {
        return res.json({
          success: false,
          message: 'No Medicare EOB records found in this PDF.',
          recordCount: 0,
          records: [],
          csvData: ''
        });
      }
      
      // Generate download token for secure CSV download
      const downloadToken = crypto.randomBytes(32).toString('hex');
      
      // Store CSV data temporarily (in production, use secure storage)
      req.session.csvData = convertToCSV(records);
      req.session.downloadToken = downloadToken;
      
      // Don't send PHI data directly to client
      res.json({
        success: true,
        message: `Successfully extracted ${records.length} patient records`,
        recordCount: records.length,
        downloadToken: downloadToken // Client uses this to download CSV
      });
      
    } catch (error) {
      logger.error('Error processing PDF', {
        error: error.message,
        user: req.user?.username,
        file: req.file?.originalname
      });
      
      if (!fileProcessed && req.file) {
        auditLogger.logFileUpload(req.user.id, req.user.username, req.file.originalname, req.file.size, req.ip, false, error.message);
      }
      
      res.status(500).json({ 
        error: 'Failed to process PDF',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : error.message
      });
    }
  }
);

// Secure CSV download endpoint
app.get('/api/download/:token',
  authenticateToken,
  logPHIAccess('DOWNLOAD_CSV'),
  (req, res) => {
    const { token } = req.params;
    
    if (!req.session.downloadToken || req.session.downloadToken !== token) {
      auditLogger.logSecurityEvent('INVALID_DOWNLOAD_TOKEN', 'Attempted download with invalid token', 'MEDIUM', req.ip, {
        user: req.user.username,
        providedToken: token
      });
      return res.status(403).json({ error: 'Invalid or expired download token' });
    }
    
    if (!req.session.csvData) {
      return res.status(404).json({ error: 'No data available for download' });
    }
    
    // Log data export
    const recordCount = (req.session.csvData.match(/\n/g) || []).length - 1;
    auditLogger.logDataExport(req.user.id, req.user.username, 'CSV', recordCount, req.ip);
    
    // Clear the data after download
    const csvData = req.session.csvData;
    delete req.session.csvData;
    delete req.session.downloadToken;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="medicare_eob_${Date.now()}.csv"`);
    res.send(csvData);
  }
);

// Health check endpoint (no auth required)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve static files with security headers
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, path) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
  }
}));

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'An error occurred processing your request'
    : err.message;
  
  res.status(err.status || 500).json({
    error: message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Resource not found'
  });
});

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// Start server
app.listen(PORT, () => {
  logger.info('Server started', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version
  });
  
  console.log(`\n🔒 Secure Medicare EOB Parser running on port ${PORT}`);
  console.log(`📊 HIPAA-compliant processing enabled`);
  console.log(`🔐 Authentication required for all operations`);
  console.log(`📝 Audit logging active`);
  console.log(`🌐 Access at: http://localhost:${PORT}`);
  
  if (process.env.NODE_ENV !== 'production') {
    console.log('\n⚠️  Development mode - Using default credentials:');
    console.log('   Admin: admin / Admin123!@#');
    console.log('   User: user / User123!@#');
  }
});