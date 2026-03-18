const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.json' && ext !== '.xml') {
      return cb(new Error('Only .json and .xml files are allowed'));
    }
    cb(null, true);
  }
});

// Serve static files from public directory
app.use(express.static('public'));

// File upload endpoint
app.post('/upload', upload.single('sbom'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const fileContent = req.file.buffer.toString('utf-8');
    const ext = path.extname(req.file.originalname).toLowerCase();
    const format = req.body.format || 'cyclonedx'; // Get format from request

    let sbomData;
    if (ext === '.json') {
      sbomData = JSON.parse(fileContent);
    } else if (ext === '.xml') {
      // For XML, we'll send it to the client to parse
      sbomData = { raw: fileContent, type: 'xml' };
    }

    res.json({
      success: true,
      data: sbomData,
      format: format,
      filename: req.file.originalname
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to parse SBOM file',
      details: error.message
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`CycloneDX Visualizer running on http://localhost:${PORT}`);
});
