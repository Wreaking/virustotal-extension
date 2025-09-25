// generate-config.js - Build script to generate config from environment variables
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Get API key from environment variable (optional for development)
const apiKey = process.env.VIRUSTOTAL_API_KEY || 'YOUR_API_KEY_HERE';

console.log('📋 Generating extension configuration...');
if (apiKey === 'YOUR_API_KEY_HERE') {
  console.warn('⚠️  No VIRUSTOTAL_API_KEY environment variable set - using placeholder');
  console.log('💡 Users will be prompted to enter their API key in the extension');
}

// Create configuration object
const config = {
  virustotalApiKey: apiKey,
  apiVersion: 'v3',
  baseUrl: 'https://www.virustotal.com/api/v3',
  rateLimit: {
    requests: 4,
    windowMs: 60000 // 1 minute
  },
  generated: new Date().toISOString()
};

// Write config to JSON file
const configPath = path.join(__dirname, 'extension-config.json');
fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

console.log('✅ Extension configuration generated successfully');
console.log(`📁 Config file: ${configPath}`);
console.log(`🔑 API key loaded from environment variable`);