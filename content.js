(function() {
  'use strict';

  class VirusTotalContentScript {
    constructor() {
      this.isInitialized = false;
      this.scanQueue = [];
      this.downloadExtensions = [
        '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.apk', '.ipa',
        '.jar', '.app', '.run', '.bin', '.com', '.scr', '.bat', '.cmd', '.ps1',
        '.zip', '.rar', '.7z', '.tar.gz', '.iso', '.img', '.gz', 
        '.pdf', '.doc', '.docx', '.xls', '.xlsx'
      ];
      this.init();
    }

    init() {
      if (this.isInitialized) return;
      
      this.setupMessageListener();
      this.setupPageInteractions();
      this.detectDownloadLinks();
      this.setupMutationObserver();
      this.isInitialized = true;
      
      console.log('VirusTotal Content Script initialized');
    }

    setupMessageListener() {
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
          case 'highlightDownloads':
            this.detectDownloadLinks();
            sendResponse({ status: 'highlighted' });
            break;
          default:
            sendResponse({ status: 'unknown_action' });
        }
        return true;
      });
    }

    setupPageInteractions() {
      // Right-click context menu support
      document.addEventListener('contextmenu', (e) => {
        const target = e.target;
        if (target.tagName === 'A' && target.href) {
          this.storeContextLink(target.href);
        }
      });

      // Monitor for clipboard events
      document.addEventListener('copy', () => {
        console.log('Copy event detected');
      });
    }

    setupMutationObserver() {
      // Monitor for dynamically added content
      const observer = new MutationObserver((mutations) => {
        let shouldScan = false;
        
        mutations.forEach((mutation) => {
          if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
            mutation.addedNodes.forEach((node) => {
              if (node.nodeType === Node.ELEMENT_NODE) {
                if (node.tagName === 'A' || node.querySelector('a')) {
                  shouldScan = true;
                }
              }
            });
          }
        });
        
        if (shouldScan) {
          setTimeout(() => {
            this.detectDownloadLinks();
            this.highlightSuspiciousLinks();
          }, 1000);
        }
      });
      
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    }

    detectDownloadLinks() {
      const links = document.querySelectorAll('a[href]');
      
      links.forEach(link => {
        const href = link.getAttribute('href');
        if (!href || link.dataset.vtScanned) return;

        const isDownloadLink = link.hasAttribute('download') || 
                               this.isLikelyDownloadUrl(href);

        if (isDownloadLink) {
          link.dataset.vtScanned = 'true';
          
          // Add click handler with bypass system
          link.addEventListener('click', (e) => {
            // Check if this click should bypass the prompt
            if (link.dataset.vtBypass === 'true') {
              // Remove bypass flag and allow native behavior
              delete link.dataset.vtBypass;
              return; // Let the click proceed normally
            }
            
            // Prevent default and show prompt
            e.preventDefault();
            e.stopPropagation();
            this.showDownloadPrompt(href, link);
          });
          
          // Notify background about download link
          chrome.runtime.sendMessage({
            action: 'downloadLinkDetected',
            url: href,
            pageUrl: window.location.href
          });
        }
      });
    }

    showDownloadPrompt(url, linkElement) {
      const overlay = document.createElement('div');
      overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        z-index: 100000;
        display: flex;
        justify-content: center;
        align-items: center;
      `;
      
      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 15px;
        max-width: 500px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        text-align: center;
        font-family: Arial, sans-serif;
      `;
      
      const fileName = url.split('/').pop() || 'file';
      
      dialog.innerHTML = `
        <div style="font-size: 48px; margin-bottom: 20px;">🛡️</div>
        <h3 style="color: #333; margin-bottom: 15px;">Download Protection</h3>
        <p style="color: #666; margin-bottom: 20px;">
          You're about to download: <strong>${fileName}</strong>
        </p>
        <p style="color: #666; margin-bottom: 30px; font-size: 14px;">
          Would you like to scan this file with VirusTotal before downloading?
        </p>
        <div style="display: flex; gap: 15px; justify-content: center;">
          <button id="scanBeforeDownload" style="
            background: #4CAF50;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">🔍 Scan First</button>
          <button id="downloadNow" style="
            background: #2196F3;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">⬇️ Download Now</button>
          <button id="cancelDownload" style="
            background: #f44336;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">❌ Cancel</button>
        </div>
      `;

      // Attach event listeners after setting innerHTML to avoid CSP issues
      const scanBtn = dialog.querySelector('#scanBeforeDownload');
      scanBtn.addEventListener('click', () => {
        document.body.removeChild(overlay);
        this.scanUrlThenDownload(url, linkElement);
      });
      
      const downloadBtn = dialog.querySelector('#downloadNow');
      downloadBtn.addEventListener('click', () => {
        document.body.removeChild(overlay);
        this.proceedWithDownload(linkElement);
      });
      
      const cancelBtn = dialog.querySelector('#cancelDownload');
      cancelBtn.addEventListener('click', () => {
        document.body.removeChild(overlay);
      });
      
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);
      
      // Handle button clicks using addEventListener
      const scanBeforeDownloadBtn = document.getElementById('scanBeforeDownload');
      if (scanBeforeDownloadBtn) {
        scanBeforeDownloadBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.scanUrlThenDownload(url, linkElement);
        });
      }
      
      const downloadNowBtn = document.getElementById('downloadNow');
      if (downloadNowBtn) {
        downloadNowBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.proceedWithDownload(linkElement);
        });
      }
      
      const cancelDownloadBtn = document.getElementById('cancelDownload');
      if (cancelDownloadBtn) {
        cancelDownloadBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
        });
      }
      
      // Close on overlay click
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          document.body.removeChild(overlay);
        }
      });
    }

    scanUrlThenDownload(url, linkElement) {
      chrome.runtime.sendMessage({
        action: 'scanUrl',
        url: url,
        source: 'download_prompt'
      }).then(response => {
        if (response && response.success) {
          this.showScanResultForDownload(response.result, linkElement);
        } else {
          this.showError('Scan failed', linkElement);
        }
      }).catch(error => {
        console.error('Scan failed:', error);
        this.showError('Scan failed: ' + error.message, linkElement);
      });
    }

    showScanResultForDownload(result, linkElement) {
      const isClean = result.status === 'safe' || (result.malicious === 0 && result.suspicious === 0);
      
      const overlay = document.createElement('div');
      overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        z-index: 100000;
        display: flex;
        justify-content: center;
        align-items: center;
      `;
      
      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 15px;
        max-width: 500px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        text-align: center;
        font-family: Arial, sans-serif;
      `;
      
      const fileName = linkElement.href.split('/').pop() || 'file';
      
      if (isClean) {
        dialog.innerHTML = `
          <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
          <h3 style="color: #4CAF50; margin-bottom: 15px;">File Appears Safe</h3>
          <p style="color: #666; margin-bottom: 20px;">
            <strong>${fileName}</strong> was scanned by ${result.total} security engines.
          </p>
          <p style="color: #666; margin-bottom: 30px; font-size: 14px;">
            ${result.harmless} engines reported it as clean.
          </p>
          <button id="proceedDownload" style="
            background: #4CAF50;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            margin-right: 10px;
          ">⬇️ Download Now</button>
          <button id="cancelDownload" style="
            background: #9E9E9E;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">Cancel</button>
        `;
  
        // Attach event listeners after setting innerHTML
        const proceedBtn = dialog.querySelector('#proceedDownload');
        proceedBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.proceedWithDownload(linkElement);
        });
  
        const cancelBtn = dialog.querySelector('#cancelDownload');
        cancelBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
        });
      } else {
        dialog.innerHTML = `
          <div style="font-size: 48px; margin-bottom: 20px;">⚠️</div>
          <h3 style="color: #f44336; margin-bottom: 15px;">Security Threat Detected</h3>
          <p style="color: #666; margin-bottom: 20px;">
            <strong>${fileName}</strong> was flagged by security engines.
          </p>
          <p style="color: #666; margin-bottom: 30px; font-size: 14px;">
            ${result.malicious} engines detected malware, ${result.suspicious} flagged as suspicious.
          </p>
          <p style="color: #f44336; margin-bottom: 30px; font-weight: bold;">
            We strongly recommend NOT downloading this file.
          </p>
          <button id="cancelDownload" style="
            background: #f44336;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">🚫 Don't Download</button>
        `;
  
        // Attach event listener after setting innerHTML
        const cancelBtn = dialog.querySelector('#cancelDownload');
        cancelBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
        });
      }
      
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);
      
      // Handle buttons using addEventListener
      const proceedBtn = document.getElementById('proceedDownload');
      if (proceedBtn) {
        proceedBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.proceedWithDownload(linkElement);
        });
      }
      
      const cancelBtn = document.getElementById('cancelDownload');
      if (cancelBtn) {
        cancelBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
        });
      }
      
      // Close on overlay click
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          document.body.removeChild(overlay);
        }
      });
    }

    proceedWithDownload(linkElement) {
      // Set bypass flag and trigger the original click
      linkElement.dataset.vtBypass = 'true';
      linkElement.click(); // This will now bypass our handler and use native behavior
    }

    showError(error, element) {
      const tooltip = document.createElement('div');
      tooltip.style.cssText = `
        position: absolute;
        background: #ff9800;
        color: white;
        padding: 8px 12px;
        border-radius: 5px;
        font-size: 12px;
        z-index: 10000;
        top: -40px;
        left: 50%;
        transform: translateX(-50%);
        white-space: nowrap;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      `;
      tooltip.textContent = `⚠️ ${error}`;
      
      element.style.position = 'relative';
      element.appendChild(tooltip);
      
      setTimeout(() => {
        if (tooltip.parentNode) {
          tooltip.parentNode.removeChild(tooltip);
        }
      }, 3000);
    }

    scanCurrentPage() {
      const currentUrl = window.location.href;
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
      return this.downloadExtensions.some(ext => 
        url.toLowerCase().includes(ext.toLowerCase())
      );
    }

    storeContextLink(url) {
      chrome.runtime.sendMessage({
        action: 'storeContextLink',
        url: url
      });
    }

    highlightSuspiciousLinks() {
      const links = document.querySelectorAll('a[href]');
      const suspiciousPatterns = [
        { pattern: /bit\.ly/i, name: 'Bit.ly', reason: 'URL shortener that can hide malicious destinations' },
        { pattern: /tinyurl/i, name: 'TinyURL', reason: 'URL shortener that can conceal harmful websites' },
        { pattern: /t\.co/i, name: 'Twitter Link', reason: 'Shortened link that may lead to unsafe content' },
        { pattern: /goo\.gl/i, name: 'Google Shortener', reason: 'Shortened URL that could redirect to malicious sites' },
        { pattern: /ow\.ly/i, name: 'Ow.ly', reason: 'URL shortener that can mask dangerous destinations' },
        { pattern: /is\.gd/i, name: 'Is.gd', reason: 'URL shortener with potential security risks' },
        { pattern: /tinycc/i, name: 'Tiny.cc', reason: 'URL shortener that may hide malicious content' },
        { pattern: /short\.link/i, name: 'Short.link', reason: 'URL shortener with potential security concerns' },
        { pattern: /cutt\.ly/i, name: 'Cutt.ly', reason: 'URL shortener that could conceal threats' }
      ];

      links.forEach(link => {
        if (link.dataset.vtSuspiciousChecked) return;
        link.dataset.vtSuspiciousChecked = 'true';
        
        const url = link.href;
        const suspiciousMatch = suspiciousPatterns.find(item => item.pattern.test(url));
        
        if (suspiciousMatch) {
          // Visual indicator for suspicious links
          link.style.border = '2px solid #ff9800';
          link.style.borderRadius = '3px';
          link.style.position = 'relative';
          link.title = 'VirusTotal: Suspicious link detected - click for safety check';
          
          // Add warning icon
          const warningIcon = document.createElement('span');
          warningIcon.innerHTML = '⚠️';
          warningIcon.style.cssText = `
            position: absolute;
            top: -8px;
            right: -8px;
            font-size: 16px;
            background: #ff9800;
            border-radius: 50%;
            padding: 2px;
            z-index: 1000;
            pointer-events: none;
          `;
          link.style.position = 'relative';
          link.appendChild(warningIcon);
          
          // Block click and show explanation with bypass system
          link.addEventListener('click', (e) => {
            // Check if this click should bypass the prompt
            if (link.dataset.vtSuspiciousBypass === 'true') {
              // Remove bypass flag and allow native behavior
              delete link.dataset.vtSuspiciousBypass;
              return; // Let the click proceed normally
            }
            
            // Check if link is permanently blocked
            if (link.dataset.vtBlocked === 'true') {
              e.preventDefault();
              e.stopPropagation();
              this.showPermanentlyBlockedMessage();
              return;
            }
            
            // Prevent default and show prompt
            e.preventDefault();
            e.stopPropagation();
            this.showSuspiciousLinkWarning(url, suspiciousMatch, link);
          });
        }
      });
    }

    showSuspiciousLinkWarning(url, suspiciousInfo, linkElement) {
      // Create blocking modal
      const overlay = document.createElement('div');
      overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 100000;
        display: flex;
        justify-content: center;
        align-items: center;
      `;
      
      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 15px;
        max-width: 500px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        text-align: center;
        font-family: Arial, sans-serif;
        border: 3px solid #ff9800;
      `;
      
      dialog.innerHTML = `
        <div style="font-size: 48px; margin-bottom: 20px;">🚨</div>
        <h3 style="color: #ff9800; margin-bottom: 15px;">Suspicious Link Blocked</h3>
        <p style="color: #333; margin-bottom: 15px; font-weight: bold;">
          ${suspiciousInfo.name} Detected
        </p>
        <p style="color: #666; margin-bottom: 20px; font-size: 14px;">
          ${suspiciousInfo.reason}
        </p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; word-break: break-all;">
          <strong>Destination:</strong><br>
          <span style="font-family: monospace; font-size: 12px; color: #333;">${url}</span>
        </div>
        <p style="color: #666; margin-bottom: 30px; font-size: 14px;">
          <strong>⚠️ Warning:</strong> Shortened URLs can hide the real destination and may lead to:
          <br>• Malware downloads
          <br>• Phishing sites
          <br>• Scam pages
          <br>• Identity theft attempts
        </p>
        <div style="display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">
          <button id="scanLinkFirst" style="
            background: #4CAF50;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">🔍 Scan First</button>
          <button id="proceedAnyway" style="
            background: #ff9800;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">⚠️ Proceed Anyway</button>
          <button id="blockLink" style="
            background: #f44336;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">🚫 Block & Stay Safe</button>
        </div>
      `;

      // Attach event listeners after setting innerHTML to avoid CSP issues
      const scanBtn = dialog.querySelector('#scanLinkFirst');
      scanBtn.addEventListener('click', () => {
        document.body.removeChild(overlay);
        this.scanSuspiciousLink(url, linkElement);
      });

      proceedBtn = dialog.querySelector('#proceedAnyway');
      proceedBtn.addEventListener('click', () => {
        document.body.removeChild(overlay);
        // Set bypass flag and trigger original link
        linkElement.dataset.vtSuspiciousBypass = 'true';
        linkElement.click();
      });

      blockBtn = dialog.querySelector('#blockLink');
      blockBtn.addEventListener('click', () => {
        document.body.removeChild(overlay);
        // Permanently disable the link
        this.permanentlyBlockLink(linkElement);
        this.showLinkBlockedConfirmation();
      });
      
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);
      
      // Handle button clicks using addEventListener
      const scanLinkBtn = document.getElementById('scanLinkFirst');
      if (scanLinkBtn) {
        scanLinkBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.scanSuspiciousLink(url, linkElement);
        });
      }
      
      const proceedBtn = document.getElementById('proceedAnyway');
      if (proceedBtn) {
        proceedBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          // Set bypass flag and trigger original link
          linkElement.dataset.vtSuspiciousBypass = 'true';
          linkElement.click();
        });
      }
      
      const blockBtn = document.getElementById('blockLink');
      if (blockBtn) {
        blockBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          // Permanently disable the link
          this.permanentlyBlockLink(linkElement);
          this.showLinkBlockedConfirmation();
        });
      }
      
      // Close on overlay click
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          document.body.removeChild(overlay);
        }
      });
      
      // Keyboard support
      const escHandler = (e) => {
        if (e.key === 'Escape') {
          if (document.body.contains(overlay)) {
            document.body.removeChild(overlay);
          }
          document.removeEventListener('keydown', escHandler);
        }
      };
      document.addEventListener('keydown', escHandler);
    }

    scanSuspiciousLink(url, linkElement) {
      // Show scanning indicator
      const scanningOverlay = document.createElement('div');
      scanningOverlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        z-index: 100000;
        display: flex;
        justify-content: center;
        align-items: center;
      `;
      
      // Add CSS keyframes for spinner
      if (!document.getElementById('vt-spinner-styles')) {
        const style = document.createElement('style');
        style.id = 'vt-spinner-styles';
        style.textContent = `
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `;
        document.head.appendChild(style);
      }
      
      scanningOverlay.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 15px; text-align: center; font-family: Arial, sans-serif;">
          <div style="font-size: 48px; margin-bottom: 20px;">🔍</div>
          <h3 style="color: #333; margin-bottom: 15px;">Scanning Link...</h3>
          <p style="color: #666;">Please wait while we check this URL for threats.</p>
          <div style="margin-top: 20px;">
            <div style="border: 3px solid #f3f3f3; border-top: 3px solid #4CAF50; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto;"></div>
          </div>
        </div>
      `;
      
      document.body.appendChild(scanningOverlay);
      
      // Send scan request to background script
      chrome.runtime.sendMessage({
        action: 'scanUrl',
        url: url,
        source: 'suspicious_link'
      }).then(response => {
        if (document.body.contains(scanningOverlay)) {
          document.body.removeChild(scanningOverlay);
        }
        if (response && response.success) {
          this.showSuspiciousLinkScanResult(response.result, url, linkElement);
        } else {
          this.showScanError('Unable to scan link at this time.', linkElement);
        }
      }).catch(error => {
        if (document.body.contains(scanningOverlay)) {
          document.body.removeChild(scanningOverlay);
        }
        console.error('Suspicious link scan failed:', error);
        this.showScanError('Scan failed: ' + error.message, linkElement);
      });
    }

    showSuspiciousLinkScanResult(result, url, linkElement) {
      const isClean = result.status === 'safe' || (result.malicious === 0 && result.suspicious === 0);
      
      const overlay = document.createElement('div');
      overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        z-index: 100000;
        display: flex;
        justify-content: center;
        align-items: center;
      `;
      
      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 15px;
        max-width: 500px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        text-align: center;
        font-family: Arial, sans-serif;
        border: 3px solid ${isClean ? '#4CAF50' : '#f44336'};
      `;
      
      if (isClean) {
        dialog.innerHTML = `
          <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
          <h3 style="color: #4CAF50; margin-bottom: 15px;">Link Appears Safe</h3>
          <p style="color: #666; margin-bottom: 20px;">
            The destination was scanned by ${result.total} security engines.
          </p>
          <p style="color: #666; margin-bottom: 30px; font-size: 14px;">
            ${result.harmless} engines reported it as clean.
          </p>
          <div style="display: flex; gap: 15px; justify-content: center;">
            <button id="proceedToLink" style="
              background: #4CAF50;
              color: white;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              cursor: pointer;
              font-size: 14px;
              font-weight: bold;
            ">🔗 Visit Link</button>
            <button id="stayHere" style="
              background: #9E9E9E;
              color: white;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              cursor: pointer;
              font-size: 14px;
              font-weight: bold;
            ">Stay Here</button>
          </div>
        `;
  
        // Attach event listeners after setting innerHTML
        const proceedBtn = dialog.querySelector('#proceedToLink');
        proceedBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.proceedWithSuspiciousLink(linkElement);
        });
  
        const stayBtn = dialog.querySelector('#stayHere');
        stayBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
        });
      } else {
        dialog.innerHTML = `
          <div style="font-size: 48px; margin-bottom: 20px;">🛑</div>
          <h3 style="color: #f44336; margin-bottom: 15px;">Dangerous Link Detected!</h3>
          <p style="color: #666; margin-bottom: 20px;">
            This URL was flagged as malicious by security engines.
          </p>
          <p style="color: #666; margin-bottom: 20px; font-size: 14px;">
            ${result.malicious} engines detected threats, ${result.suspicious} flagged as suspicious.
          </p>
          <p style="color: #f44336; margin-bottom: 30px; font-weight: bold;">
            🚨 DO NOT visit this link - it may harm your device or steal your information.
          </p>
          <button id="blockDangerous" style="
            background: #f44336;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">🚫 Block Link</button>
        `;
  
        // Attach event listener after setting innerHTML
        const blockBtn = dialog.querySelector('#blockDangerous');
        blockBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.showLinkBlockedConfirmation();
        });
      }
      
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);
      
      // Handle buttons using addEventListener
      const proceedBtn = document.getElementById('proceedToLink');
      if (proceedBtn) {
        proceedBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.proceedWithSuspiciousLink(linkElement);
        });
      }
      
      const stayBtn = document.getElementById('stayHere');
      if (stayBtn) {
        stayBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
        });
      }
      
      const blockBtn = document.getElementById('blockDangerous');
      if (blockBtn) {
        blockBtn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          this.showLinkBlockedConfirmation();
        });
      }
      
      // Close on overlay click
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          document.body.removeChild(overlay);
        }
      });
    }

    showLinkBlockedConfirmation() {
      const confirmation = document.createElement('div');
      confirmation.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        font-family: Arial, sans-serif;
        font-size: 14px;
        font-weight: bold;
        z-index: 100000;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      `;
      confirmation.innerHTML = '✅ Link blocked for your safety';
      
      document.body.appendChild(confirmation);
      
      setTimeout(() => {
        if (document.body.contains(confirmation)) {
          document.body.removeChild(confirmation);
        }
      }, 3000);
    }

    showScanError(error, linkElement) {
      const errorOverlay = document.createElement('div');
      errorOverlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        z-index: 100000;
        display: flex;
        justify-content: center;
        align-items: center;
      `;
      
      errorOverlay.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 15px; text-align: center; font-family: Arial, sans-serif; border: 3px solid #ff9800;">
          <div style="font-size: 48px; margin-bottom: 20px;">⚠️</div>
          <h3 style="color: #ff9800; margin-bottom: 15px;">Scan Error</h3>
          <p style="color: #666; margin-bottom: 30px;">${error}</p>
          <button id="closeErrorOverlay" style="
            background: #ff9800;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
          ">OK</button>
        </div>
      `;

      // Attach event listener after setting innerHTML
      closeBtn = errorOverlay.querySelector('#closeErrorOverlay');
      closeBtn.addEventListener('click', () => {
        document.body.removeChild(errorOverlay);
      });
      
      document.body.appendChild(errorOverlay);
      
      // Handle close button using addEventListener
      closeBtn = document.getElementById('closeErrorOverlay');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => {
          document.body.removeChild(errorOverlay);
        });
      }
      
      // Auto-close after 5 seconds
      setTimeout(() => {
        if (document.body.contains(errorOverlay)) {
          document.body.removeChild(errorOverlay);
        }
      }, 5000);
    }

    permanentlyBlockLink(linkElement) {
      // Mark the link as permanently blocked
      linkElement.dataset.vtBlocked = 'true';
      
      // Visual indication that link is blocked
      linkElement.style.opacity = '0.5';
      linkElement.style.textDecoration = 'line-through';
      linkElement.style.cursor = 'not-allowed';
      linkElement.style.pointerEvents = 'auto'; // Keep events so we can show blocked message
      
      // Update title to indicate blocking
      linkElement.title = 'VirusTotal: This link has been permanently blocked for your safety';
      
      // Update warning icon to show blocked status
      const existingIcon = linkElement.querySelector('span');
      if (existingIcon) {
        existingIcon.innerHTML = '🚫';
        existingIcon.style.background = '#f44336';
      }
    }

    proceedWithSuspiciousLink(linkElement) {
      // Set bypass flag and trigger the original click
      linkElement.dataset.vtSuspiciousBypass = 'true';
      linkElement.click(); // This will now bypass our handler and use native behavior
    }

    showPermanentlyBlockedMessage() {
      const notification = document.createElement('div');
      notification.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: #f44336;
        color: white;
        padding: 20px 30px;
        border-radius: 10px;
        font-family: Arial, sans-serif;
        font-size: 16px;
        font-weight: bold;
        z-index: 100000;
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
        text-align: center;
        max-width: 400px;
      `;
      
      notification.innerHTML = `
        <div style="font-size: 24px; margin-bottom: 10px;">🚫</div>
        <div>Link Permanently Blocked</div>
        <div style="font-size: 14px; font-weight: normal; margin-top: 8px; opacity: 0.9;">
          This link was blocked for your safety and cannot be accessed.
        </div>
      `;
      
      document.body.appendChild(notification);
      
      // Auto-remove after 3 seconds
      setTimeout(() => {
        if (document.body.contains(notification)) {
          document.body.removeChild(notification);
        }
      }, 3000);
      
      // Allow manual dismissal by clicking
      notification.addEventListener('click', () => {
        if (document.body.contains(notification)) {
          document.body.removeChild(notification);
        }
      });
    }

    scanCurrentPage() {
      const currentUrl = window.location.href;
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
      return this.downloadExtensions.some(ext => 
        url.toLowerCase().includes(ext.toLowerCase())
      );
    }

    storeContextLink(url) {
      chrome.runtime.sendMessage({
        action: 'storeContextLink',
        url: url
      });
    }

    highlightSuspiciousLinks() {
      const links = document.querySelectorAll('a[href]');
      const suspiciousPatterns = [
        { pattern: /bit\.ly/i, name: 'Bit.ly', reason: 'URL shortener that can hide malicious destinations' },
        { pattern: /tinyurl/i, name: 'TinyURL', reason: 'URL shortener that can conceal harmful websites' },
        { pattern: /t\.co/i, name: 'Twitter Link', reason: 'Shortened link that may lead to unsafe content' },
        { pattern: /goo\.gl/i, name: 'Google Shortener', reason: 'Shortened URL that could redirect to malicious sites' },
        { pattern: /ow\.ly/i, name: 'Ow.ly', reason: 'URL shortener that can mask dangerous destinations' },
        { pattern: /is\.gd/i, name: 'Is.gd', reason: 'URL shortener with potential security risks' },
        { pattern: /tinycc/i, name: 'Tiny.cc', reason: 'URL shortener that may hide malicious content' },
        { pattern: /short\.link/i, name: 'Short.link', reason: 'URL shortener with potential security concerns' },
        { pattern: /cutt\.ly/i, name: 'Cutt.ly', reason: 'URL shortener that could conceal threats' }
      ];

      links.forEach(link => {
        if (link.dataset.vtSuspiciousChecked) return;
        link.dataset.vtSuspiciousChecked = 'true';
        
        const url = link.href;
        const suspiciousMatch = suspiciousPatterns.find(item => item.pattern.test(url));
        
        if (suspiciousMatch) {
          // Visual indicator for suspicious links
          link.style.border = '2px solid #ff9800';
          link.style.borderRadius = '3px';
          link.style.position = 'relative';
          link.title = 'VirusTotal: Suspicious link detected - click for safety check';
          
          // Add warning icon
          const warningIcon = document.createElement('span');
          warningIcon.innerHTML = '⚠️';
          warningIcon.style.cssText = `
            position: absolute;
            top: -8px;
            right: -8px;
            font-size: 16px;
            background: #ff9800;
            border-radius: 50%;
            padding: 2px;
            z-index: 1000;
            pointer-events: none;
          `;
          link.style.position = 'relative';
          link.appendChild(warningIcon);
          
          // Block click and show explanation with bypass system
          link.addEventListener('click', (e) => {
            // Check if this click should bypass the prompt
            if (link.dataset.vtSuspiciousBypass === 'true') {
              // Remove bypass flag and allow native behavior
              delete link.dataset.vtSuspiciousBypass;
              return; // Let the click proceed normally
            }
            
            // Check if link is permanently blocked
            if (link.dataset.vtBlocked === 'true') {
              e.preventDefault();
              e.stopPropagation();
              this.showPermanentlyBlockedMessage();
              return;
            }
            
            // Prevent default and show prompt
            e.preventDefault();
            e.stopPropagation();
            this.showSuspiciousLinkWarning(url, suspiciousMatch, link);
          });
        }
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