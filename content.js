// content.js - Content script for Advanced VirusTotal Scanner
// This script runs on all web pages and provides additional functionality

(function() {
  'use strict';

  // Initialize content script
  class VirusTotalContentScript {
    constructor() {
      this.isInitialized = false;
      this.scanQueue = [];
      this.init();
    }

    init() {
      if (this.isInitialized) return;
      
      this.setupMessageListener();
      this.setupPageInteractions();
      this.isInitialized = true;
      
      console.log('VirusTotal Content Script initialized');
    }

    setupMessageListener() {
      // Listen for messages from popup or background script
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        switch (message.action) {
          case 'scanCurrentPage':
            this.scanCurrentPage();
            sendResponse({ status: 'scanning' });
            break;
          case 'getPageInfo':
            sendResponse(this.getPageInfo());
            break;
          case 'highlightLinks':
            this.highlightSuspiciousLinks();
            sendResponse({ status: 'highlighted' });
            break;
          default:
            sendResponse({ status: 'unknown_action' });
        }
        return true;
      });
    }

    setupPageInteractions() {
      // Add right-click context menu support for links
      document.addEventListener('contextmenu', (e) => {
        const target = e.target;
        if (target.tagName === 'A' && target.href) {
          this.storeContextLink(target.href);
        }
      });

      // Monitor for download links
      document.addEventListener('click', (e) => {
        const target = e.target;
        if (target.tagName === 'A' && target.href) {
          const url = target.href;
          const isDownloadLink = target.hasAttribute('download') || 
                                this.isLikelyDownloadUrl(url);
          
          if (isDownloadLink) {
            this.handleDownloadLink(url);
          }
        }
      });
    }

    scanCurrentPage() {
      const currentUrl = window.location.href;
      
      // Send scan request to background script
      chrome.runtime.sendMessage({
        action: 'scanUrl',
        url: currentUrl,
        source: 'content_script'
      });
    }

    getPageInfo() {
      return {
        url: window.location.href,
        title: document.title,
        domain: window.location.hostname,
        protocol: window.location.protocol,
        hasDownloadLinks: this.countDownloadLinks(),
        externalLinks: this.countExternalLinks()
      };
    }

    countDownloadLinks() {
      const links = document.querySelectorAll('a[href]');
      let downloadCount = 0;
      
      links.forEach(link => {
        if (link.hasAttribute('download') || this.isLikelyDownloadUrl(link.href)) {
          downloadCount++;
        }
      });
      
      return downloadCount;
    }

    countExternalLinks() {
      const links = document.querySelectorAll('a[href]');
      const currentDomain = window.location.hostname;
      let externalCount = 0;
      
      links.forEach(link => {
        try {
          const linkUrl = new URL(link.href);
          if (linkUrl.hostname !== currentDomain) {
            externalCount++;
          }
        } catch (e) {
          // Invalid URL, skip
        }
      });
      
      return externalCount;
    }

    isLikelyDownloadUrl(url) {
      const downloadExtensions = [
        '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
        '.zip', '.rar', '.7z', '.tar', '.gz',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.apk', '.ipa', '.jar'
      ];
      
      return downloadExtensions.some(ext => url.toLowerCase().includes(ext));
    }

    handleDownloadLink(url) {
      // Show notification about download link
      chrome.runtime.sendMessage({
        action: 'downloadLinkDetected',
        url: url,
        pageUrl: window.location.href
      });
    }

    storeContextLink(url) {
      // Store the right-clicked link for context menu actions
      chrome.runtime.sendMessage({
        action: 'storeContextLink',
        url: url
      });
    }

    highlightSuspiciousLinks() {
      const links = document.querySelectorAll('a[href]');
      const suspiciousPatterns = [
        /bit\.ly/i,
        /tinyurl/i,
        /t\.co/i,
        /goo\.gl/i,
        /ow\.ly/i,
        /is\.gd/i
      ];

      links.forEach(link => {
        const url = link.href;
        const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(url));
        
        if (isSuspicious) {
          link.style.border = '2px solid orange';
          link.style.borderRadius = '3px';
          link.title = 'VirusTotal: Shortened URL detected - Click to scan';
          
          // Add click handler for immediate scanning
          link.addEventListener('click', (e) => {
            e.preventDefault();
            chrome.runtime.sendMessage({
              action: 'scanUrl',
              url: url,
              source: 'suspicious_link'
            });
          });
        }
      });
    }

    // Inject scanning widget on specific pages
    injectScanWidget() {
      // Only inject on certain domains or when requested
      const allowedDomains = ['virustotal.com', 'hybrid-analysis.com'];
      const currentDomain = window.location.hostname;
      
      if (!allowedDomains.some(domain => currentDomain.includes(domain))) {
        return;
      }

      const widget = document.createElement('div');
      widget.id = 'vt-scanner-widget';
      widget.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        width: 200px;
        padding: 15px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        z-index: 10000;
        font-family: Arial, sans-serif;
        font-size: 14px;
      `;
      
      widget.innerHTML = `
        <div style="text-align: center;">
          <h4>🛡️ VT Scanner</h4>
          <button id="vt-scan-page" style="
            width: 100%;
            padding: 8px;
            border: none;
            border-radius: 5px;
            background: rgba(255,255,255,0.2);
            color: white;
            cursor: pointer;
            margin-bottom: 8px;
          ">Scan This Page</button>
          <button id="vt-highlight-links" style="
            width: 100%;
            padding: 8px;
            border: none;
            border-radius: 5px;
            background: rgba(255,255,255,0.2);
            color: white;
            cursor: pointer;
          ">Highlight Links</button>
        </div>
      `;
      
      document.body.appendChild(widget);
      
      // Add event listeners
      document.getElementById('vt-scan-page').addEventListener('click', () => {
        this.scanCurrentPage();
      });
      
      document.getElementById('vt-highlight-links').addEventListener('click', () => {
        this.highlightSuspiciousLinks();
      });
    }
  }

  // Initialize content script when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      new VirusTotalContentScript();
    });
  } else {
    new VirusTotalContentScript();
  }
})();