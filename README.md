# Medicare EOB Parser

A web application for parsing Medicare Explanation of Benefits (EOB) PDF documents and extracting patient records into structured CSV format.

## 🏥 Features

- **PDF Upload**: Drag-and-drop or click to upload Medicare EOB PDF files
- **Intelligent Parsing**: Extracts patient information, billing details, and payment data
- **CSV Export**: Download parsed data in CSV format for analysis
- **Multiple File Support**: Process multiple PDF files at once
- **Real-time Statistics**: View summary statistics of extracted records

## 📊 Extracted Data Points

- Patient Name, MID, Account Number, ICN
- Assignment and MOA information
- Claim details including:
  - Total Billed Amount
  - Total Allowed Amount
  - Total Deductible
  - Total Coinsurance
  - Provider Paid Amount
  - Patient Responsibility
  - Net Amount
  - Insurance forwarding information

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/ThinkBeDo/medicare-eob-parser.git
   cd medicare-eob-parser
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the server**
   ```bash
   npm start
   ```

4. **Access the application**
   Open your browser to `http://localhost:3000`

### Railway Deployment

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/your-template-url)

This application is ready for deployment on Railway with zero configuration needed.

## 📋 Supported Document Types

- Medicare EOB documents from Novitas Solutions
- Other Medicare Administrative Contractors (MACs)
- Standard Medicare remittance advice formats

## 🔧 Technology Stack

- **Backend**: Node.js with Express
- **PDF Processing**: pdf-parse library
- **File Upload**: Multer middleware
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Styling**: Modern gradient design with responsive layout

## 🏗️ Project Structure

```
medicare-eob-parser/
├── public/
│   └── index.html          # Frontend interface
├── server.js               # Main application server
├── package.json           # Dependencies and scripts
└── README.md              # This file
```

## 🔍 How It Works

1. **Upload**: Users upload Medicare EOB PDF files through the web interface
2. **Parse**: The server extracts text content using pdf-parse
3. **Process**: Custom parsing logic identifies patient records and claims
4. **Structure**: Data is organized into structured records
5. **Export**: Results are formatted as CSV for download

## 📈 Example Output

The CSV output includes columns for:
- Patient Name, MID, Account Number, ICN
- Assignment, MOA
- Total Billed, Total Allowed, Total Deductible
- Total Coinsurance, Total Adjustments
- Provider Paid, Patient Responsibility, Net Amount
- Forwarded To, Claims Count

## 🛡️ Security & Privacy

- Files are processed in memory only
- No data is stored on the server
- PDF content is not logged or cached
- Compliant with healthcare data handling best practices

## 🚀 Deployment

### Environment Variables

No environment variables required. The application runs on `PORT` environment variable or defaults to port 3000.

### Railway Deployment

1. Connect your GitHub repository to Railway
2. Deploy automatically - no additional configuration needed
3. Railway will detect Node.js and install dependencies automatically

## 📝 License

MIT License - see LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For issues or questions:
- Open a GitHub issue
- Review the code for technical details
- Check the console for debugging information

---

**Note**: This tool is designed for Medicare EOB documents and may require adjustments for other healthcare billing formats.