async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['vtApiKey', 'scanCount', 'autoScan', 'scanStats']);
      this.apiKey = result.vtApiKey || '90a0cae6f733f188e170ef946e5adc9daee8887abe26dfff904a50d2b7c8ec4b';
      this.scanCount = result.scanCount || 0;
      this.autoScan = result.autoScan !== false;
      this.stats = result.scanStats || this.stats;
      
      // Initialize rate limiter with API key
      this.rateLimiter.apiKey = this.apiKey;

      
      this.elements.apiUsage.textclass VirusTotalScanner {
  constructor() {
    this.apiKey = null;
    this.currentScan = null;
    this.scanHistory = [];
    this.isScanning = false;
    
    this.initializeElements();
    this.loadSettings();
    this.setupEventListeners();
    this.loadScanHistory();
  }
//getting elements, time to copy paste
  initializeElements() {
    this.elements = {
      tabButtons: document.querySelectorAll('.tab-button'),
      tabContents: document.querySelectorAll('.tab-content'),
      dropZone: document.getElementById('dropZone'),
      fileInput: document.getElementById('fileInput'),
      fileInfo: document.getElementById('fileInfo'),
      fileName: document.getElementById('fileName'),
      fileSize: document.getElementById('fileSize'),
      fileType: document.getElementById('fileType'),
      urlInput: document.getElementById('urlInput'),
      scanButton: document.getElementById('scanButton'),
      loadingSpinner: document.getElementById('loadingSpinner'),
      buttonText: document.getElementById('buttonText'),
      result: document.getElementById('result'),
      progressBar: document.getElementById('progressBar'),
      progressFill: document.getElementById('progressFill'),
      recentScans: document.getElementById('recentScans'),
      apiUsage: document.getElementById('apiUsage'),
      scanCount: document.getElementById('scanCount'),
      settingsButton: document.getElementById('settingsButton')
    };
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['vtApiKey', 'scanCount', 'autoScan']);
      this.apiKey = result.vtApiKey || '90a0cae6f733f188e170ef946e5adc9daee8887abe26dfff904a50d2b7c8ec4b';
      this.scanCount = result.scanCount || 0;
      this.autoScan = result.autoScan !== false;
      
      this.elements.scanCount.textContent = `Scans: ${this.scanCount}`;
      this.elements.apiUsage.textContent = this.apiKey ? 'API: Ready' : 'API: Not Set';
      
      if (!this.apiKey) {
        this.promptForApiKey();
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  setupEventListeners() {
    // Tab switching
    this.elements.tabButtons.forEach(button => {
      button.addEventListener('click', () => this.switchTab(button.dataset.tab));
    });

    // Drag and drop
    this.setupDragAndDrop();

    // File input
    this.elements.fileInput.addEventListener('change', (e) => this.handleFileSelect(e.target.files));
    this.elements.dropZone.addEventListener('click', () => this.elements.fileInput.click());

    // Scan button
    this.elements.scanButton.addEventListener('click', () => this.startScan());

    // URL input
    this.elements.urlInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.startScan();
    });

    // Settings button
    this.elements.settingsButton.addEventListener('click', () => this.showSettings());

    // Real-time URL validation
    this.elements.urlInput.addEventListener('input', (e) => this.validateUrl(e.target.value));
  }

  setupDragAndDrop() {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      this.elements.dropZone.addEventListener(eventName, this.preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      this.elements.dropZone.addEventListener(eventName, () => {
        this.elements.dropZone.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      this.elements.dropZone.addEventListener(eventName, () => {
        this.elements.dropZone.classList.remove('dragover');
      }, false);
    });

    this.elements.dropZone.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      this.handleFileSelect(files);
    }, false);
  }

  preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  switchTab(tabName) {
    this.elements.tabButtons.forEach(btn => btn.classList.remove('active'));
    this.elements.tabContents.forEach(content => content.classList.remove('active'));
    
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');
  }

  handleFileSelect(files) {
    if (files.length === 0) return;

    const file = files[0];
    
    // Check file size (32MB limit for VirusTotal)
    if (file.size > 32 * 1024 * 1024) {
      this.showResult('File too large. Maximum size is 32MB.', 'unsafe');
      return;
    }

    this.showFileInfo(file);
    this.elements.buttonText.textContent = '🔍 Scan File';
  }

  showFileInfo(file) {
    this.elements.fileName.textContent = `📄 ${file.name}`;
    this.elements.fileSize.textContent = `📏 ${this.formatFileSize(file.size)}`;
    this.elements.fileType.textContent = `🏷️ ${file.type || 'Unknown type'}`;
    this.elements.fileInfo.classList.add('show');
  }

  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  validateUrl(url) {
    const urlPattern = /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?$/;
    const isValid = urlPattern.test(url);
    
    if (url && isValid) {
      this.elements.urlInput.style.borderColor = '#4CAF50';
      this.elements.buttonText.textContent = '🔍 Scan URL';
    } else if (url) {
      this.elements.urlInput.style.borderColor = '#f44336';
    } else {
      this.elements.urlInput.style.borderColor = 'rgba(255, 255, 255, 0.3)';
      this.elements.buttonText.textContent = '🔍 Start Scan';
    }
  }

  async startScan() {
    if (this.isScanning) return;
    
    if (!this.apiKey) {
      this.promptForApiKey();
      return;
    }

    const activeTab = document.querySelector('.tab-content.active').id;
    
    if (activeTab === 'file-tab') {
      const file = this.elements.fileInput.files[0];
      if (!file) {
        this.showResult('Please select a file to scan.', 'unsafe');
        return;
      }
      await this.scanFile(file);
    } else if (activeTab === 'url-tab') {
      const url = this.elements.urlInput.value.trim();
      if (!url) {
        this.showResult('Please enter a URL to scan.', 'unsafe');
        return;
      }
      await this.scanUrl(url);
    }
  }

  async scanFile(file) {
    this.startScanning('Scanning file...');
    
    try {
      // First, submit the file
      const formData = new FormData();
      formData.append('file', file);
      
      const submitResponse = await fetch(`https://www.virustotal.com/vtapi/v2/file/scan?apikey=${this.apiKey}`, {
        method: 'POST',
        body: formData
      });
      
      if (!submitResponse.ok) {
        throw new Error(`HTTP error! status: ${submitResponse.status}`);
      }
      
      const submitData = await submitResponse.json();
      
      if (submitData.response_code === 1) {
        // Wait a moment then get the report
        this.updateProgress(50);
        await this.delay(2000);
        
        const reportResponse = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${this.apiKey}&resource=${submitData.resource}`);
        const reportData = await reportResponse.json();
        
        this.updateProgress(100);
        await this.delay(500);
        
        this.handleScanResult(reportData, file.name, 'file');
      } else {
        throw new Error(submitData.verbose_msg || 'Failed to submit file for scanning');
      }
    } catch (error) {
      console.error('Error scanning file:', error);
      this.showResult(`Error scanning file: ${error.message}`, 'unsafe');
    } finally {
      this.stopScanning();
    }
  }

  async scanUrl(url) {
    this.startScanning('Scanning URL...');
    
    try {
      // Submit URL for scanning
      const formData = new URLSearchParams();
      formData.append('url', url);
      
      const submitResponse = await fetch(`https://www.virustotal.com/vtapi/v2/url/scan?apikey=${this.apiKey}`, {
        method: 'POST',
        body: formData
      });
      
      const submitData = await submitResponse.json();
      
      if (submitData.response_code === 1) {
        this.updateProgress(50);
        await this.delay(3000); // URLs typically take longer
        
        // Get the report
        const reportResponse = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${this.apiKey}&resource=${encodeURIComponent(url)}`);
        const reportData = await reportResponse.json();
        
        this.updateProgress(100);
        await this.delay(500);
        
        this.handleScanResult(reportData, url, 'url');
      } else {
        throw new Error(submitData.verbose_msg || 'Failed to submit URL for scanning');
      }
    } catch (error) {
      console.error('Error scanning URL:', error);
      this.showResult(`Error scanning URL: ${error.message}`, 'unsafe');
    } finally {
      this.stopScanning();
    }
  }

  handleScanResult(data, resource, type) {
    let resultHtml = '';
    let resultClass = '';
    
    if (data.response_code === 1) {
      const positives = data.positives || 0;
      const total = data.total || 0;
      
      if (positives === 0) {
        resultClass = 'safe';
        resultHtml = `
          <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 15px;">✅</div>
            <strong>Safe</strong>
            <p>No threats detected by ${total} security vendors</p>
            <small>Scanned: ${new Date(data.scan_date).toLocaleString()}</small>
          </div>
        `;
      } else {
        resultClass = 'unsafe';
        resultHtml = `
          <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 15px;">⚠️</div>
            <strong>Threat Detected</strong>
            <p>${positives}/${total} security vendors flagged this as malicious</p>
            <small>Scanned: ${new Date(data.scan_date).toLocaleString()}</small>
          </div>
        `;
      }
      
      // Add to history
      this.addToHistory(resource, type, positives > 0 ? 'unsafe' : 'safe', positives, total);
      
    } else if (data.response_code === 0) {
      resultClass = 'scanning';
      resultHtml = `
        <div style="text-align: center;">
          <div style="font-size: 48px; margin-bottom: 15px;">🔍</div>
          <strong>Scan in Progress</strong>
          <p>Please wait while we analyze this resource...</p>
          <small>This may take a few minutes</small>
        </div>
      `;
    } else {
      resultClass = 'unsafe';
      resultHtml = `
        <div style="text-align: center;">
          <div style="font-size: 48px; margin-bottom: 15px;">❌</div>
          <strong>Scan Failed</strong>
          <p>Unable to scan this resource</p>
        </div>
      `;
    }
    
    this.showResult(resultHtml, resultClass);
    this.incrementScanCount();
  }

  addToHistory(resource, type, status, positives = 0, total = 0) {
    const historyItem = {
      resource: resource.length > 30 ? resource.substring(0, 30) + '...' : resource,
      type,
      status,
      positives,
      total,
      timestamp: Date.now()
    };
    
    this.scanHistory.unshift(historyItem);
    if (this.scanHistory.length > 10) {
      this.scanHistory = this.scanHistory.slice(0, 10);
    }
    
    this.saveScanHistory();
    this.updateHistoryDisplay();
  }

  updateHistoryDisplay() {
    if (this.scanHistory.length === 0) {
      this.elements.recentScans.innerHTML = '<div class="scan-item"><span class="scan-name">No recent scans</span></div>';
      return;
    }
    
    const historyHtml = this.scanHistory.map(item => `
      <div class="scan-item">
        <span class="scan-name" title="${item.resource}">${item.resource}</span>
        <span class="scan-status ${item.status}">
          ${item.status === 'safe' ? '✅' : item.status === 'unsafe' ? '⚠️' : '🔍'}
          ${item.positives !== undefined ? `${item.positives}/${item.total}` : ''}
        </span>
      </div>
    `).join('');
    
    this.elements.recentScans.innerHTML = historyHtml;
  }

  startScanning(message) {
    this.isScanning = true;
    this.elements.scanButton.disabled = true;
    this.elements.loadingSpinner.classList.add('show');
    this.elements.buttonText.textContent = message;
    this.elements.progressBar.classList.add('show');
    this.elements.result.classList.remove('show');
    this.updateProgress(0);
  }

  stopScanning() {
    this.isScanning = false;
    this.elements.scanButton.disabled = false;
    this.elements.loadingSpinner.classList.remove('show');
    this.elements.buttonText.textContent = '🔍 Start Scan';
    this.elements.progressBar.classList.remove('show');
  }

  updateProgress(percentage) {
    this.elements.progressFill.style.width = percentage + '%';
  }

  showResult(content, className) {
    this.elements.result.innerHTML = content;
    this.elements.result.className = `result ${className} show`;
  }

  async incrementScanCount() {
    this.scanCount++;
    this.elements.scanCount.textContent = `Scans: ${this.scanCount}`;
    await chrome.storage.local.set({ scanCount: this.scanCount });
  }

  async saveScanHistory() {
    await chrome.storage.local.set({ scanHistory: this.scanHistory });
  }

  async loadScanHistory() {
    try {
      const result = await chrome.storage.local.get(['scanHistory']);
      this.scanHistory = result.scanHistory || [];
      this.updateHistoryDisplay();
    } catch (error) {
      console.error('Error loading scan history:', error);
    }
  }

  promptForApiKey() {
    const apiKey = prompt(
      'Please enter your VirusTotal API Key:\n\n' +
      '1. Go to https://www.virustotal.com/gui/my-apikey\n' +
      '2. Sign up/Login to get your free API key\n' +
      '3. Copy and paste it below:'
    );
    
    if (apiKey && apiKey.trim()) {
      this.saveApiKey(apiKey.trim());
    } else {
      this.showResult('VirusTotal API key is required for scanning.', 'unsafe');
    }
  }

  async saveApiKey(apiKey) {
    this.apiKey = apiKey;
    await chrome.storage.local.set({ vtApiKey: apiKey });
    this.elements.apiUsage.textContent = 'API: Ready';
    this.showResult('API key saved successfully! You can now start scanning.', 'safe');
  }

  showSettings() {
    const settingsHtml = `
      <div style="text-align: center; padding: 20px;">
        <h3 style="margin-bottom: 15px; color: white;">Settings</h3>
        <button onclick="scanner.promptForApiKey()" style="margin: 5px; padding: 10px 15px; border: none; border-radius: 5px; background: #4CAF50; color: white; cursor: pointer;">
          Update API Key
        </button>
        <button onclick="scanner.clearHistory()" style="margin: 5px; padding: 10px 15px; border: none; border-radius: 5px; background: #f44336; color: white; cursor: pointer;">
          Clear History
        </button>
        <button onclick="scanner.elements.result.classList.remove('show')" style="margin: 5px; padding: 10px 15px; border: none; border-radius: 5px; background: #666; color: white; cursor: pointer;">
          Close
        </button>
      </div>
    `;
    
    this.showResult(settingsHtml, 'scanning');
  }

  async clearHistory() {
    this.scanHistory = [];
    await this.saveScanHistory();
    this.updateHistoryDisplay();
    this.showResult('History cleared successfully!', 'safe');
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Initialize the scanner when the popup loads
let scanner;
document.addEventListener('DOMContentLoaded', () => {
  scanner = new VirusTotalScanner();
});

