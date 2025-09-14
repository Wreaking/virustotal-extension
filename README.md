# Advanced VirusTotal Scanner Chrome Extension

A powerful Chrome extension for scanning files and URLs using the VirusTotal API. Features drag & drop file scanning, URL analysis, scan history, and real-time threat detection.

## Features

- 🔍 **File Scanning**: Drag & drop files up to 32MB for malware analysis
- 🔗 **URL Scanning**: Analyze websites and links for threats
- 📊 **Scan History**: Keep track of recent scans and results
- ⚡ **Real-time Monitoring**: Background scanning of downloads and clipboard
- 🛡️ **Threat Detection**: Integration with VirusTotal's comprehensive database
- 🎨 **Modern UI**: Clean, responsive interface with progress indicators

## Installation in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked"
4. Select this project directory
5. The extension will appear in your browser toolbar

## Development Setup

This extension is set up to run in the Replit environment for development:

1. The development server serves extension files for easy access
2. Files are served with CORS enabled for testing
3. Use the workflow to start the development environment

## Getting a VirusTotal API Key

1. Visit [VirusTotal](https://www.virustotal.com/gui/my-apikey)
2. Sign up or log in to your account
3. Copy your API key
4. Enter it when prompted by the extension

## Extension Structure

- `manifest.json` - Extension configuration and permissions
- `popup.html/js` - Main extension interface and functionality
- `background.js` - Background service worker for monitoring
- `content.js` - Content script for page interactions
- `images/` - Extension icons (16, 32, 48, 128px)

## API Usage

The extension uses VirusTotal API v2 endpoints:
- File scanning: `/vtapi/v2/file/scan` and `/vtapi/v2/file/report`
- URL scanning: `/vtapi/v2/url/scan` and `/vtapi/v2/url/report`

Rate limits apply based on your API key type (free accounts: 4 requests per minute).

## Security Features

- Automatic detection of suspicious download links
- Clipboard monitoring for malicious URLs
- Real-time scanning notifications
- Comprehensive scan result reporting

## Development Notes

This Chrome extension can be developed and tested in Replit, but requires manual installation in Chrome browser for full functionality. The development server provides easy access to extension files during development.