const express = require('express');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'), false);
    }
  }
});

// Function to parse Medicare EOB data
function parseEOBData(text) {
  const records = [];
  const lines = text.split('\n');
  
  let currentRecord = null;
  let processingClaim = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Skip empty lines and headers
    if (!line || line.includes('NOVITAS SOLUTIONS') || line.includes('MEDICARE') || 
        line.includes('REMITTANCE') || line.includes('ADVICE') || line.includes('PAGE #') ||
        line.includes('PERF PROV SERV DATE') || line.includes('_____')) {
      continue;
    }
    
    // Check if this is a new patient record
    const nameMatch = line.match(/^NAME\s+([A-Z,\s]+)\s+MID\s+([A-Z0-9]+)\s+ACNT\s+([A-Z0-9X]+)\s+ICN\s+(\d+)\s+ASG\s+([YN])\s+MOA\s+(.+)$/);
    
    if (nameMatch) {
      // Save previous record if exists
      if (currentRecord && currentRecord.claims && currentRecord.claims.length > 0) {
        records.push(currentRecord);
      }
      
      // Start new record
      currentRecord = {
        patientName: nameMatch[1].trim(),
        mid: nameMatch[2],
        accountNumber: nameMatch[3],
        icn: nameMatch[4],
        assignment: nameMatch[5],
        moa: nameMatch[6],
        claims: [],
        totalBilled: 0,
        totalAllowed: 0,
        totalDeductible: 0,
        totalCoinsurance: 0,
        totalAdjustments: 0,
        providerPaid: 0,
        patientResponsibility: 0,
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
          currentRecord.totalBilled = parseFloat(totalsMatch[1]);
          currentRecord.totalAllowed = parseFloat(totalsMatch[2]);
          currentRecord.totalDeductible = parseFloat(totalsMatch[3]);
          currentRecord.totalCoinsurance = parseFloat(totalsMatch[4]);
          currentRecord.totalAdjustments = parseFloat(totalsMatch[5]);
          currentRecord.providerPaid = parseFloat(totalsMatch[6]);
        }
        continue;
      }
      
      // Check for patient responsibility
      if (line.startsWith('PT RESP')) {
        const respMatch = line.match(/PT RESP\s+([\d.]+)/);
        if (respMatch) {
          currentRecord.patientResponsibility = parseFloat(respMatch[1]);
        }
        continue;
      }
      
      // Check for forwarded to line
      if (line.includes('CLAIM INFORMATION FORWARDED TO:')) {
        const forwardMatch = line.match(/CLAIM INFORMATION FORWARDED TO:\s*(.+?)\s+NET\s+([\d.]+)/);
        if (forwardMatch) {
          currentRecord.forwardedTo = forwardMatch[1].trim();
          currentRecord.netAmount = parseFloat(forwardMatch[2]);
        } else {
          const simpleForwardMatch = line.match(/CLAIM INFORMATION FORWARDED TO:\s*(.+)/);
          if (simpleForwardMatch) {
            currentRecord.forwardedTo = simpleForwardMatch[1].replace(/NET.*/, '').trim();
          }
        }
        continue;
      }
      
      // Check for NET amount line
      if (line.startsWith('NET ') && !currentRecord.netAmount) {
        const netMatch = line.match(/NET\s+([\d.]+)/);
        if (netMatch) {
          currentRecord.netAmount = parseFloat(netMatch[1]);
        }
        continue;
      }
      
      // Parse individual claim lines
      const claimMatch = line.match(/^(\d+)\s+(\d{4})\s+(\d{6})\s+(\d+)\s+([\d.]+)\s+(\w+)\s*(.*)s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(.+)\s+([\d.]+)/);
      
      if (claimMatch) {
        const claim = {
          providerNumber: claimMatch[1],
          dateFrom: claimMatch[2],
          dateThrough: claimMatch[3],
          placeOfService: claimMatch[4],
          quantity: parseFloat(claimMatch[5]),
          procedureCode: claimMatch[6],
          modifiers: claimMatch[7].trim(),
          billed: parseFloat(claimMatch[8]),
          allowed: parseFloat(claimMatch[9]),
          deductible: parseFloat(claimMatch[10]),
          coinsurance: parseFloat(claimMatch[11]),
          adjustments: claimMatch[12],
          providerPaid: parseFloat(claimMatch[13])
        };
        
        currentRecord.claims.push(claim);
      }
    }
  }
  
  // Save the last record
  if (currentRecord && currentRecord.claims && currentRecord.claims.length > 0) {
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

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Upload and parse PDF
app.post('/upload', upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No PDF file uploaded' });
    }
    
    console.log('Processing PDF file:', req.file.originalname);
    
    // Parse PDF
    const pdfData = await pdfParse(req.file.buffer);
    console.log('Extracted text length:', pdfData.text.length);
    
    // Parse EOB data
    const records = parseEOBData(pdfData.text);
    console.log('Extracted records:', records.length);
    
    if (records.length === 0) {
      return res.json({
        success: false,
        message: 'No Medicare EOB records found in this PDF. Please ensure this is a valid Medicare Explanation of Benefits document.',
        recordCount: 0,
        records: [],
        csvData: ''
      });
    }
    
    // Convert to CSV
    const csvData = convertToCSV(records);
    
    res.json({
      success: true,
      message: `Successfully extracted ${records.length} patient records`,
      recordCount: records.length,
      records: records,
      csvData: csvData
    });
    
  } catch (error) {
    console.error('Error processing PDF:', error);
    res.status(500).json({ 
      error: 'Failed to process PDF', 
      details: error.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`\n🚀 Medicare EOB Parser running on port ${PORT}`);
  console.log(`📊 Ready to process Medicare Explanation of Benefits PDFs`);
  console.log(`🌐 Access at: http://localhost:${PORT}`);
});