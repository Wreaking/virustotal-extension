// generate-config.js - Build script to generate config from environment variables
const fs = require('fs');
const path = require('path');

// Get API key from environment variable
const apiKey = process.env.VIRUSTOTAL_API_KEY;

if (!apiKey) {
  console.error('VIRUSTOTAL_API_KEY environment variable not set!');
  process.exit(1);
}

// Validate API key format (VirusTotal keys are 64-character hex strings)
const apiKeyRegex = /^[a-f0-9]{64}$/i;
if (!apiKeyRegex.test(apiKey)) {
  console.error('Invalid VirusTotal API key format. Expected 64-character hexadecimal string.');
  process.exit(1);
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