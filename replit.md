# Advanced VirusTotal Scanner Chrome Extension

## Overview

This project is a comprehensive Chrome extension that integrates with the VirusTotal API to provide real-time malware scanning capabilities. The extension offers file scanning through drag-and-drop functionality, URL analysis, download monitoring, and scan history management. It features a modern user interface with progress indicators and background monitoring capabilities for enhanced security protection.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Extension Architecture
- **Manifest V3 Compliance**: Built using Chrome's latest extension architecture with service workers
- **Multi-Component Design**: Separated into popup interface, background service worker, and content scripts
- **Modular Structure**: Clean separation between UI, API handling, and browser integration

### Frontend Components
- **Popup Interface** (`popup.html/js`): Main user interface for manual scanning operations
- **Content Scripts** (`content.js`): Page-level interaction handling and download link detection
- **Background Service Worker** (`background.js`): Persistent monitoring and context menu integration

### Data Storage Strategy
- **Dual Storage Approach**: Primary storage using Replit Database with localStorage fallback
- **Scan History Management**: Persistent storage of scan results and user statistics
- **Settings Persistence**: API keys and user preferences stored securely in Chrome storage
- **Rate Limiting Data**: Tracking API usage to comply with VirusTotal limits

### API Integration
- **VirusTotal API v3**: Primary scanning service integration
- **Rate Limiting**: Built-in request throttling (4 requests per minute for free tier)
- **Error Handling**: Comprehensive error management with user feedback
- **Configuration Management**: Environment-based API key loading with validation

### Security Features
- **Download Monitoring**: Real-time detection and scanning of potentially dangerous files
- **Context Menu Integration**: Right-click scanning for links and URLs
- **Threat Detection**: Integration with VirusTotal's comprehensive malware database
- **Background Scanning**: Continuous monitoring without user intervention

### Development Infrastructure
- **Build System**: Node.js-based development setup with HTTP server for testing
- **Icon Generation**: Automated icon creation for multiple Chrome extension sizes
- **Configuration Management**: Environment variable-based API key handling
- **Test Environment**: Local development server with CORS support

## External Dependencies

### Core Services
- **VirusTotal API**: Primary malware scanning and threat detection service
- **Chrome Extension APIs**: Browser integration (downloads, storage, notifications, contextMenus, tabs, webRequest)

### Development Dependencies
- **@replit/database**: Primary database service for scan history and user data
- **http-server**: Local development server for extension testing
- **Node.js**: Build system and configuration management

### Browser Permissions
- **Host Permissions**: Access to VirusTotal domains for API communication
- **Extension Permissions**: Active tab access, scripting, downloads monitoring, storage, notifications, context menus, alarms, tabs, and web requests

### File Processing
- **File Size Limits**: 32MB maximum file size for VirusTotal scanning
- **Supported Formats**: Comprehensive support for executables, documents, archives, and other potentially dangerous file types
- **Detection Patterns**: Extensive file extension monitoring for download protection