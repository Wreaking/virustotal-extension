class AdvancedVirusTotalScanner {
  constructor() {
    // API key will be loaded from environment/storage
    this.apiKey = null;
    this.scanQueue = [];
    this.isScanning = false;
    this.scanCount = 0;
    this.autoScan = true;
    this.rateLimit = {
      requests: 0,
      resetTime: 0,
      maxRequests: 4, // Free tier limit
      window: 60000 // 1 minute
    };
    this.stats = {
      todayScans: 0,
      threatsFound: 0,
      lastScanDate: new Date().toDateString(),
      totalMalicious: 0,
      totalSafe: 0
    };

    // Initialize database
    this.db = null;
    this.initializeDatabase();
    this.initializeElements();
    this.loadApiKey();
    this.loadSettingsOptimized();
    this.setupEventListeners();
    this.loadScanHistoryFromDB();
    this.setupRateLimiter();
  }

  async initializeDatabase() {
    try {
      // Use Replit's built-in database
      const Database = await import('@replit/database');
      this.db = new Database.default();
      console.log('Database initialized successfully');
    } catch (error) {
      console.error('Database initialization failed:', error);
      // Fallback to localStorage
      this.db = {
        get: async (key) => {
          const value = localStorage.getItem(key);
          return value ? JSON.parse(value) : null;
        },
        set: async (key, value) => {
          localStorage.setItem(key, JSON.stringify(value));
        },
        delete: async (key) => {
          localStorage.removeItem(key);
        },
        list: async () => {
          const keys = [];
          for (let i = 0; i < localStorage.length; i++) {
            keys.push(localStorage.key(i));
          }
          return keys;
        }
      };
    }
  }

  async loadApiKey() {
    try {
      // Try to get API key from storage first
      let apiKey = await this.db.get('virustotal_api_key');
      
      if (!apiKey) {
        // Use hardcoded API key as fallback (you should replace this with your actual key)
        apiKey = "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE";
        // Save it to database for future use
        await this.db.set('virustotal_api_key', apiKey);
      }
      
      this.apiKey = apiKey;
      console.log('API key loaded successfully');
    } catch (error) {
      console.error('Failed to load API key:', error);
      this.apiKey = "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE";
    }
  }

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
      settingsButton: document.getElementById('settingsButton'),
      queueStatus: document.getElementById('queueStatus'),
      rateLimitStatus: document.getElementById('rateLimitStatus'),
      detailedResults: document.getElementById('detailedResults'),
      bulkScanArea: document.getElementById('bulkScanArea'),
      scanStats: document.getElementById('scanStats')
    };
  }

  async loadSettingsOptimized() {
    try {
      // Load only essential settings for faster startup
      const result = await chrome.storage.local.get([
        'scanCount', 'autoScan', 'scanStats', 'rateLimit'
      ]);

      this.scanCount = result.scanCount || 0;
      this.autoScan = result.autoScan !== false;
      this.stats = result.scanStats || this.stats;
      this.rateLimit = { ...this.rateLimit, ...result.rateLimit };

      this.updateUIStatusOptimized();

      // Skip health check for faster popup - API key is hardcoded
      this.showResult('🛡️ Ready to scan! API configured and ready.', 'safe');

    } catch (error) {
      this.handleError('Loading Settings', error);
    }
  }

  async performHealthCheck() {
    try {
      // Check if we can access chrome APIs
      await chrome.storage.local.get(['healthCheck']);

      // Check if background script is responsive
      const bgResponse = await chrome.runtime.sendMessage({ action: 'ping' }).catch(() => null);

      console.log('Extension health check passed');
      return true;
    } catch (error) {
      console.warn('Extension health check failed:', error);
      this.showResult('⚠️ Extension may not be fully loaded. Try refreshing the popup.', 'warning');
      return false;
    }
  }

  setupEventListeners() {
    // Tab switching
    this.elements.tabButtons.forEach(button => {
      button.addEventListener('click', () => this.switchTab(button.dataset.tab));
    });

    // Enhanced drag and drop
    this.setupAdvancedDragAndDrop();

    // File input with multiple file support
    this.elements.fileInput.addEventListener('change', (e) => {
      this.handleMultipleFileSelect(Array.from(e.target.files));
    });

    this.elements.dropZone.addEventListener('click', () => {
      this.elements.fileInput.click();
    });

    // Scan button with queue support
    this.elements.scanButton.addEventListener('click', () => this.processScanQueue());

    // URL input with real-time validation
    this.elements.urlInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addUrlToQueue();
    });

    // Settings button
    this.elements.settingsButton.addEventListener('click', () => this.showAdvancedSettings());

    // Real-time URL validation with debouncing
    let urlValidationTimeout;
    this.elements.urlInput.addEventListener('input', (e) => {
      clearTimeout(urlValidationTimeout);
      urlValidationTimeout = setTimeout(() => {
        this.validateUrlWithFeedback(e.target.value);
      }, 300);
    });

    // Listen for download notifications from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.action) {
        case 'downloadPrompt':
          this.showDownloadPrompt(message.downloadItem);
          sendResponse({ status: 'prompted' });
          break;
        case 'notificationScanRequest':
          this.handleNotificationScanRequest(message.notificationId);
          sendResponse({ status: 'handled' });
          break;
        default:
          sendResponse({ status: 'unknown_action' });
      }
      return true;
    });
  }

  setupAdvancedDragAndDrop() {
    const events = ['dragenter', 'dragover', 'dragleave', 'drop'];

    events.forEach(eventName => {
      this.elements.dropZone.addEventListener(eventName, this.preventDefaults, false);
      document.body.addEventListener(eventName, this.preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      this.elements.dropZone.addEventListener(eventName, () => {
        this.elements.dropZone.classList.add('dragover');
        this.elements.dropZone.innerHTML = `
          <div class="drop-feedback">
            <i style="font-size: 64px;">📂</i>
            <p><strong>Drop files here</strong></p>
            <p>Multiple files supported (up to 10 at once)</p>
            <small>Max file size: 650MB each</small>
          </div>
        `;
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      this.elements.dropZone.addEventListener(eventName, () => {
        this.elements.dropZone.classList.remove('dragover');
        this.resetDropZone();
      }, false);
    });

    this.elements.dropZone.addEventListener('drop', (e) => {
      const files = Array.from(e.dataTransfer.files);
      this.handleMultipleFileSelect(files);
    }, false);
  }

  resetDropZone() {
    this.elements.dropZone.innerHTML = `
      <i style="font-size: 48px; color: rgba(255, 255, 255, 0.7); margin-bottom: 15px; display: block;">📎</i>
      <p><strong>Drag & Drop</strong> your files here</p>
      <p>or click to browse</p>
      <small>Max file size: 650MB • Multiple files supported</small>
    `;
  }

  preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  handleMultipleFileSelect(files) {
    if (files.length === 0) return;

    if (files.length > 10) {
      this.showResult('Maximum 10 files allowed at once. Please select fewer files.', 'error');
      return;
    }

    let validFiles = [];
    let errors = [];

    files.forEach(file => {
      // Check file size (32MB limit for direct upload, 650MB for large file upload)
      const maxSize = 650 * 1024 * 1024; // 650MB
      if (file.size > maxSize) {
        errors.push(`${file.name}: File too large (max 650MB)`);
        return;
      }

      if (file.size === 0) {
        errors.push(`${file.name}: Empty file`);
        return;
      }

      // Warn about large files
      if (file.size > 100 * 1024 * 1024) { // 100MB
        console.warn(`Large file detected: ${file.name} (${this.formatFileSize(file.size)})`);
      }

      validFiles.push(file);
    });

    if (errors.length > 0) {
      const errorMessage = `Some files were rejected:\n${errors.join('\n')}`;
      this.showResult(errorMessage, 'error');
    }

    if (validFiles.length > 0) {
      this.addFilesToQueue(validFiles);
      this.showFileInfo(validFiles);
    }
  }

  addFilesToQueue(files) {
    files.forEach(file => {
      this.scanQueue.push({
        type: 'file',
        data: file,
        name: file.name,
        size: this.formatFileSize(file.size),
        timestamp: Date.now()
      });
    });

    this.updateQueueStatus();
    this.elements.buttonText.textContent = `🔍 Scan ${this.scanQueue.length} Item${this.scanQueue.length > 1 ? 's' : ''}`;
  }

  addUrlToQueue() {
    const url = this.elements.urlInput.value.trim();
    if (!url) return;

    if (!this.validateUrl(url)) {
      this.showResult('Please enter a valid URL (must include http:// or https://)', 'error');
      return;
    }

    this.scanQueue.push({
      type: 'url',
      data: url,
      name: this.extractDomain(url),
      timestamp: Date.now()
    });

    this.elements.urlInput.value = '';
    this.updateQueueStatus();
    this.elements.buttonText.textContent = `🔍 Scan ${this.scanQueue.length} Item${this.scanQueue.length > 1 ? 's' : ''}`;
  }

  async processScanQueue() {
    if (this.isScanning || this.scanQueue.length === 0) return;

    if (!this.apiKey) {
      this.promptForApiKey();
      return;
    }

    this.isScanning = true;
    this.elements.scanButton.disabled = true;
    this.elements.loadingSpinner.classList.add('show');
    this.elements.progressBar.classList.add('show');

    let completed = 0;
    const total = this.scanQueue.length;
    const results = [];

    try {
      while (this.scanQueue.length > 0) {
        // Check rate limits
        if (!await this.checkRateLimit()) {
          const waitTime = Math.ceil((this.rateLimit.resetTime - Date.now()) / 1000);
          this.showResult(`Rate limit reached. Waiting ${waitTime} seconds...`, 'warning');
          await this.delay(waitTime * 1000);
          continue;
        }

        const item = this.scanQueue.shift();
        this.elements.buttonText.textContent = `Scanning ${item.name}...`;

        try {
          let result;
          if (item.type === 'file') {
            result = await this.scanFileAdvanced(item.data);
          } else {
            result = await this.scanUrlAdvanced(item.data);
          }

          result.itemName = item.name;
          result.itemType = item.type;
          results.push(result);

        } catch (error) {
          results.push({
            itemName: item.name,
            itemType: item.type,
            error: error.message,
            isError: true
          });
        }

        completed++;
        this.updateProgress((completed / total) * 100);
        this.updateQueueStatus();

        // Small delay between requests to avoid overwhelming the API
        await this.delay(1000);
      }

      this.displayBatchResults(results);
      await this.saveStats();

    } catch (error) {
      this.handleError('Batch Scanning', error);
    } finally {
      this.stopScanning();
    }
  }

  async scanFileAdvanced(file) {
    try {
      // Enhanced API key validation
      if (!this.validateApiKey(this.apiKey)) {
        throw new Error('Invalid API key format. Expected 64-character hexadecimal string.');
      }

      // Determine upload method based on file size
      const fileSize = file.size;
      const DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024; // 32MB

      let analysisId;

      if (fileSize <= DIRECT_UPLOAD_LIMIT) {
        // Use direct upload for smaller files
        analysisId = await this.uploadFileDirectly(file);
      } else {
        // Use upload URL for larger files
        analysisId = await this.uploadLargeFile(file);
      }

      // Step 2: Wait and get analysis results with enhanced retry logic
      return await this.getAnalysisResults(analysisId, file.name);

    } catch (error) {
      throw new Error(`File scan failed: ${error.message}`);
    }
  }

  async uploadFileDirectly(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.fetchWithRateLimit('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': this.apiKey
      },
      body: formData
    });

    if (!response.ok) {
      throw new Error(`Direct upload failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return data.data.id;
  }

  async uploadLargeFile(file) {
    // Step 1: Get upload URL for large files
    const uploadUrlResponse = await this.fetchWithRateLimit('https://www.virustotal.com/api/v3/files/upload_url', {
      headers: {
        'x-apikey': this.apiKey
      }
    });

    if (!uploadUrlResponse.ok) {
      throw new Error(`Failed to get upload URL: ${uploadUrlResponse.status} ${uploadUrlResponse.statusText}`);
    }

    const uploadUrlData = await uploadUrlResponse.json();
    const uploadUrl = uploadUrlData.data;

    // Step 2: Upload file to the provided URL with progress tracking
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = (e.loaded / e.total) * 100;
          this.updateUploadProgress(percentComplete);
        }
      });

      xhr.addEventListener('load', async () => {
        try {
          if (xhr.status >= 200 && xhr.status < 300) {
            const response = JSON.parse(xhr.responseText);
            resolve(response.data.id);
          } else {
            reject(new Error(`Large file upload failed: ${xhr.status} ${xhr.statusText}`));
          }
        } catch (error) {
          reject(new Error(`Failed to parse upload response: ${error.message}`));
        }
      });

      xhr.addEventListener('error', () => {
        reject(new Error('Network error during large file upload'));
      });

      xhr.addEventListener('timeout', () => {
        reject(new Error('Upload timeout - file too large or connection too slow'));
      });

      xhr.open('POST', uploadUrl);
      xhr.timeout = 300000; // 5 minute timeout for large files
      xhr.send(formData);
    });
  }

  updateUploadProgress(percentage) {
    if (this.elements.progressFill) {
      this.elements.progressFill.style.width = percentage + '%';
    }
    if (this.elements.buttonText) {
      this.elements.buttonText.textContent = `Uploading... ${Math.round(percentage)}%`;
    }
  }

  async scanUrlAdvanced(url) {
    try {
      if (!this.validateApiKey(this.apiKey)) {
        throw new Error('Invalid API key format. Expected 64-character hexadecimal string.');
      }

      // Step 1: Submit URL for scanning
      const response = await this.fetchWithRateLimit('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Invalid API key. Please check your VirusTotal API key.');
        } else if (response.status === 429) {
          throw new Error('Rate limit exceeded. Please wait before scanning again.');
        }
        throw new Error(`URL submission failed: ${response.status} ${response.statusText}`);
      }

      const submitData = await response.json();
      const analysisId = submitData.data.id;

      console.log('URL submitted for analysis:', analysisId);

      // Step 2: Get analysis results
      return await this.getAnalysisResults(analysisId, url);

    } catch (error) {
      console.error('URL scan error:', error);
      throw new Error(`URL scan failed: ${error.message}`);
    }
  }

  async getAnalysisResults(analysisId, resourceName) {
    const maxAttempts = 15; // Increased for more reliability
    let attempts = 0;
    const startTime = Date.now();
    const maxWaitTime = 300000; // 5 minutes maximum wait

    while (attempts < maxAttempts) {
      try {
        // Check if we've exceeded maximum wait time
        if (Date.now() - startTime > maxWaitTime) {
          throw new Error('Analysis timeout - maximum wait time exceeded');
        }

        const response = await this.fetchWithRateLimit(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: {
            'x-apikey': this.apiKey
          }
        });

        if (!response.ok) {
          if (response.status === 404) {
            throw new Error('Analysis not found - may have expired');
          }
          throw new Error(`Analysis fetch failed: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        const status = data.data.attributes.status;

        if (status === 'completed') {
          return this.processAnalysisData(data.data.attributes, resourceName);
        } else if (status === 'error') {
          throw new Error('Analysis failed on VirusTotal servers');
        }

        // Update UI with current status
        if (this.elements.buttonText) {
          this.elements.buttonText.textContent = `Analyzing... (${status})`;
        }

        // Enhanced exponential backoff with jitter
        const baseDelay = 2000;
        const backoffMultiplier = Math.pow(1.6, attempts);
        const jitter = Math.random() * 1000; // Add randomness to avoid thundering herd
        const waitTime = Math.min(baseDelay * backoffMultiplier + jitter, 30000);

        await this.delay(waitTime);
        attempts++;

      } catch (error) {
        attempts++;
        if (attempts >= maxAttempts || error.message.includes('not found') || error.message.includes('timeout')) {
          throw error;
        }

        // Progressive delay for retries on errors
        const errorDelay = Math.min(3000 * attempts, 15000);
        await this.delay(errorDelay);
      }
    }

    throw new Error('Analysis timeout - maximum retry attempts exceeded');
  }

  // Enhanced API key validation
  validateApiKey(apiKey) {
    if (!apiKey) return false;

    // VirusTotal API keys are 64-character hexadecimal strings
    const apiKeyRegex = /^[a-f0-9]{64}$/i;
    return apiKeyRegex.test(apiKey.trim());
  }

  // Rate limiting wrapper for fetch requests
  async fetchWithRateLimit(url, options = {}) {
    // Check rate limits before making request
    if (!await this.checkRateLimit()) {
      const waitTime = Math.ceil((this.rateLimit.resetTime - Date.now()) / 1000);
      throw new Error(`Rate limit exceeded. Try again in ${waitTime} seconds.`);
    }

    try {
      const response = await fetch(url, options);

      // Handle rate limit responses from VirusTotal
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const waitTime = retryAfter ? parseInt(retryAfter) : 60;

        // Update our local rate limit based on server response
        this.rateLimit.resetTime = Date.now() + (waitTime * 1000);
        this.rateLimit.requests = this.rateLimit.maxRequests;

        throw new Error(`Rate limited by server. Retry in ${waitTime} seconds.`);
      }

      // Handle other API errors
      if (response.status === 401) {
        throw new Error('Invalid API key. Please check your VirusTotal API key.');
      } else if (response.status === 403) {
        throw new Error('Access forbidden. Check API key permissions.');
      } else if (response.status >= 500) {
        throw new Error('VirusTotal server error. Please try again later.');
      }

      return response;
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Network error. Check your internet connection.');
      }
      throw error;
    }
  }

  processAnalysisData(attributes, resourceName) {
    const stats = attributes.stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    // Get detailed engine results with enhanced processing
    const engineResults = attributes.results || {};
    const detections = [];
    const engines = [];
    const signatures = new Set();
    const threatFamilies = new Set();

    Object.entries(engineResults).forEach(([engineName, result]) => {
      const engineInfo = {
        name: engineName,
        result: result.result || 'Clean',
        category: result.category || 'undetected',
        version: result.version,
        method: result.method,
        engineUpdate: result.engine_update
      };

      engines.push(engineInfo);

      if (result.category === 'malicious' || result.category === 'suspicious') {
        const detection = {
          engine: engineName,
          threat: result.result,
          category: result.category,
          method: result.method
        };

        detections.push(detection);

        // Extract threat signatures and families
        if (result.result) {
          signatures.add(result.result);

          // Extract common threat family patterns
          const threatName = result.result.toLowerCase();
          if (threatName.includes('trojan')) threatFamilies.add('Trojan');
          else if (threatName.includes('virus')) threatFamilies.add('Virus');
          else if (threatName.includes('adware')) threatFamilies.add('Adware');
          else if (threatName.includes('malware')) threatFamilies.add('Malware');
          else if (threatName.includes('spyware')) threatFamilies.add('Spyware');
          else if (threatName.includes('rootkit')) threatFamilies.add('Rootkit');
          else if (threatName.includes('worm')) threatFamilies.add('Worm');
          else if (threatName.includes('ransomware')) threatFamilies.add('Ransomware');
        }
      }
    });

    const isMalicious = malicious > 0 || suspicious > 0;
    const riskScore = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;

    // Calculate confidence score based on engine consensus
    let confidenceScore = 0;
    if (total > 0) {
      const agreement = Math.max(malicious, suspicious, harmless, undetected);
      confidenceScore = Math.round((agreement / total) * 100);
    }

    // Determine threat severity
    let threatSeverity = 'Unknown';
    if (!isMalicious) {
      threatSeverity = 'Safe';
    } else if (riskScore < 20) {
      threatSeverity = 'Low Risk';
    } else if (riskScore < 50) {
      threatSeverity = 'Medium Risk';
    } else if (riskScore < 80) {
      threatSeverity = 'High Risk';
    } else {
      threatSeverity = 'Critical Risk';
    }

    return {
      resourceName,
      isMalicious,
      riskScore,
      confidenceScore,
      threatSeverity,
      stats: {
        malicious,
        suspicious,
        harmless,
        undetected,
        total
      },
      detections,
      engines,
      signatures: Array.from(signatures),
      threatFamilies: Array.from(threatFamilies),
      scanDate: new Date().toISOString(),
      scanId: attributes.scan_id || 'Unknown'
    };
  }

  displayBatchResults(results) {
    let maliciousCount = 0;
    let safeCount = 0;
    let errorCount = 0;

    const resultElements = results.map(result => {
      if (result.isError) {
        errorCount++;
        return this.createResultElement(result, 'error');
      } else if (result.isMalicious) {
        maliciousCount++;
        return this.createResultElement(result, 'malicious');
      } else {
        safeCount++;
        return this.createResultElement(result, 'safe');
      }
    }).join('');

    const summaryHtml = `
      <div class="batch-summary">
        <h3>Batch Scan Complete</h3>
        <div class="summary-stats">
          <div class="stat ${safeCount > 0 ? 'safe' : ''}">${safeCount} Safe</div>
          <div class="stat ${maliciousCount > 0 ? 'malicious' : ''}">${maliciousCount} Threats</div>
          <div class="stat ${errorCount > 0 ? 'error' : ''}">${errorCount} Errors</div>
        </div>
      </div>
      <div class="results-container">
        ${resultElements}
      </div>
    `;

    this.showResult(summaryHtml, maliciousCount > 0 ? 'unsafe' : 'safe');

    // Update stats
    this.stats.todayScans += results.length;
    this.stats.totalMalicious += maliciousCount;
    this.stats.totalSafe += safeCount;
    this.stats.threatsFound += maliciousCount;

    // Add to history
    for (const result of results) {
      if (!result.isError) {
        await this.addToHistory(result.resourceName, result.itemType, 
          result.isMalicious ? 'malicious' : 'safe', result);
      }
    }
  }

  createResultElement(result, type) {
    if (result.isError) {
      return `
        <div class="result-item error">
          <div class="result-header">
            <span class="result-icon">❌</span>
            <span class="result-name">${result.itemName}</span>
          </div>
          <div class="result-details">Error: ${result.error}</div>
        </div>
      `;
    }

    const icon = type === 'malicious' ? '⚠️' : '✅';
    const riskLevel = this.getRiskLevel(result.riskScore);
    const vtUrl = this.generateVirusTotalUrl(result.resourceName, result.itemType, result.scanId);

    let detailedInfo = '';
    if (result.isMalicious && result.detections.length > 0) {
      const topThreats = result.detections.slice(0, 5);
      detailedInfo = `
        <div class="threat-details">
          <strong>Detected Threats:</strong>
          ${topThreats.map(d => `
            <div class="threat-item">
              <span class="engine-name">${d.engine}</span>: 
              <span class="threat-name">${d.threat}</span>
            </div>
          `).join('')}
          ${result.detections.length > 5 ? `<div class="more-threats">... and ${result.detections.length - 5} more</div>` : ''}
        </div>
      `;
    }

    return `
      <div class="result-item ${type}">
        <div class="result-header">
          <span class="result-icon">${icon}</span>
          <span class="result-name">${result.resourceName}</span>
          <span class="risk-score ${riskLevel.class}">${result.riskScore}% Risk</span>
        </div>
        <div class="result-stats">
          <span class="stat malicious">${result.stats.malicious} Malicious</span>
          <span class="stat suspicious">${result.stats.suspicious} Suspicious</span>
          <span class="stat harmless">${result.stats.harmless} Clean</span>
          <span class="stat undetected">${result.stats.undetected} Undetected</span>
        </div>
        ${detailedInfo}
        <div class="result-actions">
          <button onclick="scanner.viewFullReport('${vtUrl}')" class="view-report-btn">
            🔍 View Full Report on VirusTotal
          </button>
        </div>
      </div>
    `;
  }

  generateVirusTotalUrl(resource, type, scanId) {
    if (type === 'url') {
      // For URLs, create VirusTotal URL analysis link
      const encodedUrl = btoa(resource).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      return `https://www.virustotal.com/gui/url/${encodedUrl}`;
    } else if (scanId && scanId !== 'Unknown') {
      // For files, use the analysis ID
      return `https://www.virustotal.com/gui/file-analysis/${scanId}`;
    } else {
      // Fallback to search
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(resource)}`;
    }
  }

  viewFullReport(vtUrl) {
    chrome.tabs.create({ url: vtUrl });
  }

  getRiskLevel(score) {
    if (score === 0) return { class: 'safe', level: 'Safe' };
    if (score < 10) return { class: 'low', level: 'Low' };
    if (score < 30) return { class: 'medium', level: 'Medium' };
    if (score < 60) return { class: 'high', level: 'High' };
    return { class: 'critical', level: 'Critical' };
  }

  async checkRateLimit() {
    // Get the latest rate limit state from storage (shared across contexts)
    const stored = await chrome.storage.local.get(['globalRateLimit']);
    const globalLimit = stored.globalRateLimit || {
      requests: 0,
      resetTime: 0,
      maxRequests: 4,
      window: 60000
    };

    const now = Date.now();

    // Reset counter if window has passed
    if (now > globalLimit.resetTime) {
      globalLimit.requests = 0;
      globalLimit.resetTime = now + globalLimit.window;
    }

    if (globalLimit.requests >= globalLimit.maxRequests) {
      this.rateLimit = globalLimit;
      this.updateRateLimitStatus();
      return false;
    }

    // Increment and save back to storage
    globalLimit.requests++;
    this.rateLimit = globalLimit;
    await chrome.storage.local.set({ globalRateLimit: globalLimit });
    this.updateRateLimitStatus();
    return true;
  }

  updateRateLimitStatus() {
    if (!this.elements.rateLimitStatus) return;

    const remaining = this.rateLimit.maxRequests - this.rateLimit.requests;
    const resetIn = Math.ceil((this.rateLimit.resetTime - Date.now()) / 1000);

    this.elements.rateLimitStatus.innerHTML = `
      <span class="rate-limit ${remaining === 0 ? 'exhausted' : remaining < 2 ? 'warning' : 'ok'}">
        API: ${remaining}/${this.rateLimit.maxRequests} remaining
        ${remaining === 0 ? `(resets in ${resetIn}s)` : ''}
      </span>
    `;
  }

  setupRateLimiter() {
    setInterval(() => {
      this.updateRateLimitStatus();
    }, 1000);
  }

  showFileInfo(files) {
    if (files.length === 1) {
      const file = files[0];
      this.elements.fileName.textContent = `📄 ${file.name}`;
      this.elements.fileSize.textContent = `📏 ${this.formatFileSize(file.size)}`;
      this.elements.fileType.textContent = `🏷️ ${file.type || 'Unknown type'}`;
    } else {
      this.elements.fileName.textContent = `📄 ${files.length} files selected`;
      const totalSize = files.reduce((sum, file) => sum + file.size, 0);
      this.elements.fileSize.textContent = `📏 Total: ${this.formatFileSize(totalSize)}`;
      this.elements.fileType.textContent = `🏷️ Multiple file types`;
    }
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
    try {
      const urlObj = new URL(url);
      return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
      return false;
    }
  }

  validateUrlWithFeedback(url) {
    const isValid = this.validateUrl(url);

    if (url && isValid) {
      this.elements.urlInput.style.borderColor = '#4CAF50';
      this.elements.urlInput.style.backgroundColor = 'rgba(76, 175, 80, 0.1)';
    } else if (url) {
      this.elements.urlInput.style.borderColor = '#f44336';
      this.elements.urlInput.style.backgroundColor = 'rgba(244, 67, 54, 0.1)';
    } else {
      this.elements.urlInput.style.borderColor = 'rgba(255, 255, 255, 0.3)';
      this.elements.urlInput.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
    }
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url.substring(0, 50) + '...';
    }
  }

  switchTab(tabName) {
    this.elements.tabButtons.forEach(btn => btn.classList.remove('active'));
    this.elements.tabContents.forEach(content => content.classList.remove('active'));

    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');
  }

  updateProgress(percentage) {
    if (this.elements.progressFill) {
      this.elements.progressFill.style.width = percentage + '%';
    }
  }

  updateQueueStatus() {
    if (this.elements.queueStatus) {
      const count = this.scanQueue.length;
      this.elements.queueStatus.innerHTML = count > 0 ? 
        `<span class="queue-count">${count} item${count > 1 ? 's' : ''} in queue</span>` : '';
    }
  }

  updateUIStatus() {
    if (this.elements.apiUsage) {
      this.elements.apiUsage.textContent = this.apiKey ? 'API: Ready ✅' : 'API: Not Set ⚠️';
    }

    this.updateRateLimitStatus();
    this.updateQueueStatus();
  }

  updateUIStatusOptimized() {
    if (this.elements.apiUsage) {
      this.elements.apiUsage.textContent = 'API: Ready ✅';
    }

    // Defer non-critical UI updates
    setTimeout(() => {
      this.updateRateLimitStatus();
      this.updateQueueStatus();
    }, 50);
  }

  showResult(content, className) {
    this.elements.result.innerHTML = content;
    this.elements.result.className = `result ${className} show`;
  }

  stopScanning() {
    this.isScanning = false;
    this.elements.scanButton.disabled = false;
    this.elements.loadingSpinner.classList.remove('show');
    this.elements.buttonText.textContent = this.scanQueue.length > 0 ? 
      `🔍 Scan ${this.scanQueue.length} Item${this.scanQueue.length > 1 ? 's' : ''}` : '🔍 Start Scan';
    this.elements.progressBar.classList.remove('show');
    this.updateProgress(0);
  }

  showDownloadPrompt(downloadItem) {
    const promptHtml = `
      <div class="download-prompt">
        <h3>🔽 Download Detected</h3>
        <p><strong>File:</strong> ${downloadItem.filename}</p>
        <p><strong>Size:</strong> ${this.formatFileSize(downloadItem.fileSize)}</p>
        <p><strong>From:</strong> ${downloadItem.referrer || downloadItem.url}</p>
        <div class="prompt-actions">
          <button onclick="scanner.scanDownload('${downloadItem.id}')" class="scan-btn">
            🛡️ Scan Now
          </button>
          <button onclick="scanner.dismissPrompt()" class="dismiss-btn">
            Skip
          </button>
        </div>
      </div>
    `;

    this.showResult(promptHtml, 'scanning');
  }

  async scanDownload(downloadId) {
    try {
      // Get download info from background script
      const response = await chrome.runtime.sendMessage({
        action: 'getDownloadInfo',
        downloadId: downloadId
      });

      if (response.success) {
        // Add to scan queue
        this.scanQueue.push({
          type: 'download',
          data: response.downloadInfo,
          name: response.downloadInfo.filename,
          timestamp: Date.now()
        });
        this.updateQueueStatus();
        this.processScanQueue();
      }
    } catch (error) {
      this.handleError('Download Scan', error);
    }
  }

  dismissPrompt() {
    this.elements.result.classList.remove('show');
  }

  async addToHistory(resource, type, status, result) {
    const historyItem = {
      id: Date.now().toString(),
      resource: resource.length > 30 ? resource.substring(0, 30) + '...' : resource,
      fullResource: resource,
      type,
      status,
      riskScore: result.riskScore || 0,
      detectionCount: result.stats ? result.stats.malicious + result.stats.suspicious : 0,
      totalEngines: result.stats ? result.stats.total : 0,
      timestamp: Date.now(),
      scanDate: result.scanDate,
      detections: result.detections || [],
      threatFamilies: result.threatFamilies || [],
      signatures: result.signatures || [],
      scanId: result.scanId || 'Unknown',
      confidenceScore: result.confidenceScore || 0,
      threatSeverity: result.threatSeverity || 'Unknown'
    };

    // Save to database
    await this.saveToDatabase(historyItem);

    // Update local history
    this.scanHistory = this.scanHistory || [];
    this.scanHistory.unshift(historyItem);

    if (this.scanHistory.length > 50) {
      this.scanHistory = this.scanHistory.slice(0, 50);
    }

    this.updateHistoryDisplay();
    console.log('Added item to history:', historyItem.resource);
  }

  async saveToDatabase(historyItem) {
    try {
      const key = `scan_${historyItem.id}`;
      await this.db.set(key, historyItem);
      
      // Update scan index
      let scanIndex = await this.db.get('scan_index') || [];
      scanIndex.unshift(historyItem.id);
      
      // Keep only last 100 scans
      if (scanIndex.length > 100) {
        const oldIds = scanIndex.splice(100);
        // Delete old scan records
        for (const oldId of oldIds) {
          await this.db.delete(`scan_${oldId}`);
        }
      }
      
      await this.db.set('scan_index', scanIndex);
    } catch (error) {
      console.error('Failed to save to database:', error);
    }
  }

  async loadScanHistoryFromDB() {
    try {
      const scanIndex = await this.db.get('scan_index') || [];
      this.scanHistory = [];

      for (const scanId of scanIndex.slice(0, 50)) {
        const scanData = await this.db.get(`scan_${scanId}`);
        if (scanData) {
          this.scanHistory.push(scanData);
        }
      }

      this.updateHistoryDisplay();
      console.log('Loaded scan history from database:', this.scanHistory.length, 'items');
    } catch (error) {
      console.error('Failed to load scan history from database:', error);
      this.scanHistory = [];
    }
  }

  updateHistoryDisplay() {
    if (!this.elements.recentScans) return;

    if (this.scanHistory.length === 0) {
      this.elements.recentScans.innerHTML = '<div class="scan-item"><span class="scan-name">No recent scans</span></div>';
      return;
    }

    const historyHtml = this.scanHistory.slice(0, 10).map(item => {
      const statusIcon = item.status === 'safe' ? '✅' : 
                        item.status === 'malicious' ? '⚠️' : '🔍';
      const riskClass = item.riskScore > 0 ? 'high-risk' : 'safe';
      const vtUrl = this.generateVirusTotalUrl(item.fullResource, item.type, item.scanId);

      return `
        <div class="scan-item ${riskClass}" title="${item.fullResource}">
          <div class="scan-info">
            <span class="scan-name">${item.resource}</span>
            <span class="scan-time">${new Date(item.timestamp).toLocaleTimeString()}</span>
            <div class="scan-details-extra">
              ${item.detectionCount > 0 ? 
                `<span class="detection-count">${item.detectionCount}/${item.totalEngines} detections</span>` : 
                `<span class="clean-engines">${item.totalEngines} engines checked</span>`
              }
            </div>
          </div>
          <div class="scan-details">
            <span class="scan-status">${statusIcon}</span>
            ${item.riskScore > 0 ? 
              `<span class="risk-score">${item.riskScore}%</span>` : 
              '<span class="clean-status">Clean</span>'
            }
            <button onclick="scanner.viewFullReport('${vtUrl}')" class="mini-report-btn" title="View full report">
              📊
            </button>
          </div>
        </div>
      `;
    }).join('');

    this.elements.recentScans.innerHTML = historyHtml;
  }

  promptForApiKey() {
    // API key is hardcoded, no need for user input
    this.showResult('🛡️ API key is already configured and ready to use!', 'safe');
  }

  validateApiKey(key) {
    // Basic API key format validation (64 character hex string)
    return /^[a-fA-F0-9]{64}$/.test(key);
  }

  async saveApiKey(apiKey) {
    // API key is hardcoded, no saving needed
    this.showResult('🛡️ API key is already configured!', 'safe');
  }

  showAdvancedSettings() {
    const settingsHtml = `
      <div class="advanced-settings">
        <h3>⚙️ Advanced Settings</h3>

        <div class="setting-group">
          <label>
            <input type="checkbox" id="downloadPromptToggle" ${this.autoScan ? 'checked' : ''}>
            Prompt for download scanning
          </label>
        </div>

        <div class="setting-group">
          <label>API Rate Limit:</label>
          <select id="rateLimitSelect">
            <option value="4" ${this.rateLimit.maxRequests === 4 ? 'selected' : ''}>Free (4/min)</option>
            <option value="1000" ${this.rateLimit.maxRequests === 1000 ? 'selected' : ''}>Premium (1000/min)</option>
          </select>
        </div>

        <div class="stats-display">
          <h4>Usage Statistics</h4>
          <div class="stats-grid">
            <div class="stat-item">
              <span class="stat-number">${this.stats.todayScans}</span>
              <span class="stat-label">Today's Scans</span>
            </div>
            <div class="stat-item">
              <span class="stat-number">${this.stats.threatsFound}</span>
              <span class="stat-label">Threats Found</span>
            </div>
            <div class="stat-item">
              <span class="stat-number">${this.stats.totalSafe}</span>
              <span class="stat-label">Safe Files</span>
            </div>
          </div>
        </div>

        <div class="settings-actions">
          <button onclick="scanner.clearAllHistory()" class="settings-btn danger">
            Clear All History
          </button>
          <button onclick="scanner.exportHistory()" class="settings-btn">
            Export History
          </button>
          <button onclick="scanner.closeSettings()" class="settings-btn">
            Close
          </button>
        </div>
      </div>
    `;

    this.showResult(settingsHtml, 'scanning');
  }

  updateApiKey() {
    this.showResult('🛡️ API key is hardcoded and cannot be changed for security.', 'info');
  }

  async clearAllHistory() {
    if (confirm('Are you sure you want to clear all scan history?')) {
      this.scanHistory = [];
      this.stats = {
        todayScans: 0,
        threatsFound: 0,
        lastScanDate: new Date().toDateString(),
        totalMalicious: 0,
        totalSafe: 0
      };

      await this.saveStats();
      await this.saveScanHistory();
      this.updateHistoryDisplay();
      this.showResult('All history cleared successfully! 🗑️', 'safe');
    }
  }

  exportHistory() {
    const exportData = {
      history: this.scanHistory,
      stats: this.stats,
      exportDate: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `virustotal-scan-history-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();

    URL.revokeObjectURL(url);
    this.showResult('Scan history exported! 📁', 'safe');
  }

  closeSettings() {
    this.elements.result.classList.remove('show');
  }

  async saveStats() {
    await chrome.storage.local.set({ scanStats: this.stats });
  }

  async saveScanHistory() {
    await chrome.storage.local.set({ scanHistory: this.scanHistory });
  }

  handleError(operation, error) {
    console.error(`Error in ${operation}:`, error);
    const userMessage = this.getErrorMessage(error);
    this.showResult(`❌ ${operation} failed: ${userMessage}`, 'error');
  }

  getErrorMessage(error) {
    if (error.message.includes('401')) return 'Invalid API key';
    if (error.message.includes('429')) return 'Rate limit exceeded - please wait';
    if (error.message.includes('403')) return 'API access forbidden';
    if (error.message.includes('network')) return 'Network connection failed';
    return error.message || 'Unknown error occurred';
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Remove the old loadScanHistoryOptimized method since we now use loadScanHistoryFromDB

  // Enhanced download prompt handling
  handleNotificationScanRequest(notificationId) {
    // Switch to file tab and show scan interface
    this.switchTab('file');
    this.showResult('Please select the downloaded file to scan using drag & drop or browse button.', 'info');
  }
}

// Initialize the scanner when the popup loads
let scanner;
document.addEventListener('DOMContentLoaded', () => {
  scanner = new AdvancedVirusTotalScanner();
});