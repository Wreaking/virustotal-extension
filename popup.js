// Advanced VirusTotal Scanner with Enhanced Features
class AdvancedVirusTotalScanner {
  constructor() {
    // Enhanced configuration
    this.apiKey = null;
    this.scanQueue = new Map();
    this.activeScans = new Set();
    this.isQueuePaused = false;
    this.maxConcurrentScans = 2;
    
    // Advanced rate limiting for user protection
    this.rateLimit = {
      requests: 0,
      resetTime: 0,
      maxRequests: 4, // Free tier limit
      window: 60000, // 1 minute
      warningThreshold: 3,
      cooldownPeriod: 300000 // 5 minutes after hitting limit
    };
    
    // Enhanced statistics tracking
    this.stats = {
      todayScans: 0,
      threatsFound: 0,
      lastScanDate: new Date().toDateString(),
      totalMalicious: 0,
      totalSafe: 0,
      totalScanned: 0
    };
    
    // User settings with defaults
    this.settings = {
      autoScanDownloads: true,
      scanPermissionEnabled: true,
      rateLimitNotifications: true,
      maxConcurrentScans: 2,
      detailedReports: true
    };

    // Initialize components
    this.supabase = null;
    this.db = null;
    this.dbManager = null;
    this.initializeDatabase();
    this.initializeElements();
    this.loadUserSettings();
    this.setupEventListeners();
    this.loadScanHistoryFromDB();
    this.setupRateLimiter();
    this.startQueueProcessor();
  }

  async initializeDatabase() {
    try {
      // Initialize Supabase for primary storage
      const { createClient } = await import('@supabase/supabase-js');
      
      // Get Supabase configuration from environment
      const supabaseUrl = process.env.SUPABASE_URL;
      const supabaseKey = process.env.SUPABASE_ANON_KEY;
      
            // Get configuration from extension storage
      const { supabase_url, supabase_key, database_url } = await chrome.storage.local.get(
        ['supabase_url', 'supabase_key', 'database_url']
      );
      
      const databaseUrl = database_url || this.getDatabaseUrl();
      if (databaseUrl && supabase_url && supabase_key) {
        // Use the stored Supabase configuration
        const supabaseUrl = supabase_url;
        const supabaseKey = supabase_key;
        
        this.supabase = createClient(supabaseUrl, supabaseKey);
        this.dbManager = new DatabaseManager(this.supabase);
        console.log('✅ Supabase database initialized successfully');
      }
    } catch (error) {
      console.error('⚠️ Supabase initialization failed, using fallback:', error);
    }
    
    // Fallback to Replit database or localStorage
    try {
      const Database = await import('@replit/database');
      this.db = new Database.default();
      console.log('✅ Replit database initialized as fallback');
    } catch (error) {
      console.error('⚠️ Using localStorage fallback');
      this.db = this.createLocalStorageFallback();
    }
  }
  
  getDatabaseUrl() {
    // In a real Chrome extension, this would come from extension storage or config
    return null; // Will use localStorage fallback for now
  }
  
  createLocalStorageFallback() {
    return {
      get: async (key) => {
        const value = localStorage.getItem(key);
        return value ? JSON.parse(value) : null;
      },
      set: async (key, value) => {
        localStorage.setItem(key, JSON.stringify(value));
      },
      delete: async (key) => {
        localStorage.removeItem(key);
      }
    };
  }

  initializeElements() {
    this.elements = {
      // Tab elements
      tabButtons: document.querySelectorAll('.tab-button'),
      tabContents: document.querySelectorAll('.tab-content'),
      
      // File elements
      dropZone: document.getElementById('dropZone'),
      fileInput: document.getElementById('fileInput'),
      multipleFileInput: document.getElementById('multipleFileInput'),
      folderInput: document.getElementById('folderInput'),
      
      // URL elements
      urlInput: document.getElementById('urlInput'),
      
      // Queue elements
      queueList: document.getElementById('queueList'),
      queueCount: document.getElementById('queueCount'),
      processingCount: document.getElementById('processingCount'),
      completedCount: document.getElementById('completedCount'),
      
      // Settings elements
      autoScanDownloads: document.getElementById('autoScanDownloads'),
      scanPermissionEnabled: document.getElementById('scanPermissionEnabled'),
      rateLimitNotifications: document.getElementById('rateLimitNotifications'),
      maxConcurrentScans: document.getElementById('maxConcurrentScans'),
      apiKeyInput: document.getElementById('apiKeyInput'),
      apiStatus: document.getElementById('apiStatus'),
      
      // Progress and results
      progressBar: document.getElementById('progressBar'),
      progressFill: document.getElementById('progressFill'),
      scanButton: document.getElementById('scanButton'),
      result: document.getElementById('result'),
      
      // Statistics
      todayScans: document.getElementById('todayScans'),
      threatsFound: document.getElementById('threatsFound'),
      cleanScans: document.getElementById('cleanScans'),
      recentScans: document.getElementById('recentScans')
    };
  }

  setupEventListeners() {
    // Tab navigation
    this.elements.tabButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });

    // File drag and drop with folder support
    this.setupDragAndDrop();
    
    // URL scanning
    this.elements.urlInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.addUrlToQueue();
      }
    });
    
    // Settings event listeners
    if (this.elements.autoScanDownloads) {
      this.elements.autoScanDownloads.addEventListener('change', (e) => {
        this.settings.autoScanDownloads = e.target.checked;
        this.saveSettings();
      });
    }
    
    if (this.elements.scanPermissionEnabled) {
      this.elements.scanPermissionEnabled.addEventListener('change', (e) => {
        this.settings.scanPermissionEnabled = e.target.checked;
        this.saveSettings();
      });
    }
    
    if (this.elements.maxConcurrentScans) {
      this.elements.maxConcurrentScans.addEventListener('change', (e) => {
        this.maxConcurrentScans = parseInt(e.target.value);
        this.settings.maxConcurrentScans = this.maxConcurrentScans;
        this.saveSettings();
      });
    }
  }

  setupDragAndDrop() {
    if (!this.elements.dropZone) return;

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
      const files = Array.from(e.dataTransfer.files);
      this.handleMultipleFiles(files);
    }, false);

    this.elements.dropZone.addEventListener('click', () => {
      this.selectMultipleFiles();
    });
  }

  preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  // Enhanced file selection methods
  selectMultipleFiles() {
    if (this.elements.multipleFileInput) {
      this.elements.multipleFileInput.webkitdirectory = false;
      this.elements.multipleFileInput.click();
      this.elements.multipleFileInput.onchange = (e) => {
        this.handleMultipleFiles(Array.from(e.target.files));
      };
    }
  }

  selectFolder() {
    if (this.elements.folderInput) {
      this.elements.folderInput.click();
      this.elements.folderInput.onchange = (e) => {
        this.handleMultipleFiles(Array.from(e.target.files));
      };
    }
  }

  async handleMultipleFiles(files) {
    for (const file of files) {
      await this.addFileToQueue(file);
    }
    this.showNotification(`Added ${files.length} files to queue`, 'info');
  }

  // Advanced Queue Management
  async addFileToQueue(file, priority = 0) {
    if (file.size > 650 * 1024 * 1024) { // 650MB limit
      this.showNotification(`File ${file.name} is too large (max 650MB)`, 'error');
      return null;
    }

    const queueId = this.generateQueueId();
    const queueItem = {
      id: queueId,
      type: 'file',
      name: file.name,
      size: file.size,
      file: file,
      priority: priority,
      status: 'queued',
      addedAt: Date.now(),
      retries: 0,
      maxRetries: 3
    };

    this.scanQueue.set(queueId, queueItem);
    
    // Save to database if available
    if (this.dbManager) {
      try {
        await this.dbManager.addToQueue(queueItem);
      } catch (error) {
        console.error('Failed to save to database:', error);
      }
    }

    this.updateQueueDisplay();
    this.processQueue();
    return queueId;
  }

  async addUrlToQueue() {
    const url = this.elements.urlInput?.value?.trim();
    if (!url) return;

    if (!this.isValidUrl(url)) {
      this.showNotification('Please enter a valid URL', 'error');
      return;
    }

    const queueId = this.generateQueueId();
    const queueItem = {
      id: queueId,
      type: 'url',
      name: url,
      url: url,
      priority: 0,
      status: 'queued',
      addedAt: Date.now(),
      retries: 0,
      maxRetries: 3
    };

    this.scanQueue.set(queueId, queueItem);
    this.elements.urlInput.value = '';

    if (this.dbManager) {
      try {
        await this.dbManager.addToQueue(queueItem);
      } catch (error) {
        console.error('Failed to save to database:', error);
      }
    }

    this.updateQueueDisplay();
    this.processQueue();
    this.showNotification('URL added to queue', 'success');
  }

  async addBulkUrls() {
    const textarea = document.getElementById('bulkUrls');
    if (!textarea) return;

    const urls = textarea.value
      .split('\n')
      .map(url => url.trim())
      .filter(url => url && this.isValidUrl(url));

    for (const url of urls) {
      this.elements.urlInput.value = url;
      await this.addUrlToQueue();
    }

    textarea.value = '';
    this.showNotification(`Added ${urls.length} URLs to queue`, 'success');
  }

  // Advanced Queue Processing with Rate Limiting
  async processQueue() {
    if (this.isQueuePaused || this.activeScans.size >= this.maxConcurrentScans) {
      return;
    }

    if (!this.canMakeRequest()) {
      this.showRateLimitWarning();
      setTimeout(() => this.processQueue(), 5000); // Retry after 5 seconds
      return;
    }

    const queuedItems = Array.from(this.scanQueue.values())
      .filter(item => item.status === 'queued')
      .sort((a, b) => b.priority - a.priority);

    if (queuedItems.length === 0) return;

    const item = queuedItems[0];
    await this.processScanItem(item);
  }

  async processScanItem(item) {
    try {
      item.status = 'processing';
      item.startedAt = Date.now();
      this.activeScans.add(item.id);
      this.updateQueueDisplay();

      let result;
      if (item.type === 'file') {
        result = await this.scanFile(item.file);
      } else if (item.type === 'url') {
        result = await this.scanUrl(item.url);
      }

      item.status = 'completed';
      item.completedAt = Date.now();
      item.result = result;

      // Save result to database
      await this.saveScanResult(item, result);
      
      // Update statistics
      this.updateStats(result);
      
      this.showScanResult(item, result);

    } catch (error) {
      console.error('Scan failed:', error);
      item.retries++;
      
      if (item.retries >= item.maxRetries) {
        item.status = 'failed';
        item.error = error.message;
        this.showNotification(`Scan failed for ${item.name}: ${error.message}`, 'error');
      } else {
        item.status = 'queued'; // Retry
        setTimeout(() => this.processQueue(), 2000); // Wait before retry
      }
    } finally {
      this.activeScans.delete(item.id);
      this.updateQueueDisplay();
      // Continue processing queue after a short delay
      setTimeout(() => this.processQueue(), 1000);
    }
  }

  // Enhanced Rate Limiting with User Protection
  canMakeRequest() {
    const now = Date.now();
    const windowStart = now - this.rateLimit.window;
    
    // Clean old entries
    this.rateLimitTracker = this.rateLimitTracker || new Map();
    for (const [timestamp] of this.rateLimitTracker) {
      if (timestamp < windowStart) {
        this.rateLimitTracker.delete(timestamp);
      }
    }
    
    const currentRequests = this.rateLimitTracker.size;
    
    // Show warning when approaching limit
    if (currentRequests >= this.rateLimit.warningThreshold && this.settings.rateLimitNotifications) {
      this.showRateLimitWarning();
    }
    
    return currentRequests < this.rateLimit.maxRequests;
  }

  trackApiRequest() {
    this.rateLimitTracker = this.rateLimitTracker || new Map();
    this.rateLimitTracker.set(Date.now(), true);
    
    if (this.dbManager) {
      this.dbManager.trackApiRequest('virustotal');
    }
  }

  showRateLimitWarning() {
    const resetTime = new Date(Date.now() + this.rateLimit.window);
    this.showNotification(
      `⚠️ Rate limit warning: ${this.rateLimitTracker.size}/${this.rateLimit.maxRequests} requests used. Next reset: ${resetTime.toLocaleTimeString()}`,
      'warning'
    );
  }

  // Enhanced Scanning Methods with Better Error Handling
  async scanFile(file) {
    try {
      await this.loadApiKey(); // Ensure we have an API key
      if (!this.apiKey) {
        throw new Error('No API key configured. Please set your VirusTotal API key in settings.');
      }

      this.trackApiRequest();

      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: {
          'X-Apikey': this.apiKey
        },
        body: formData
      });

      if (!response.ok) {
        if (response.status === 429) {
          throw new Error('Rate limit exceeded. Please wait before scanning more files.');
        }
        throw new Error(`API request failed: ${response.status} ${response.statusText}`);
      }

      const uploadResult = await response.json();
      const analysisId = uploadResult.data.id;

      return await this.pollForResults(analysisId, 'file', file.name);

    } catch (error) {
      console.error('File scan error:', error);
      throw error;
    }
  }

  async scanUrl(url) {
    try {
      await this.loadApiKey();
      if (!this.apiKey) {
        throw new Error('No API key configured. Please set your VirusTotal API key in settings.');
      }

      this.trackApiRequest();

      const formData = new FormData();
      formData.append('url', url);

      const response = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'X-Apikey': this.apiKey
        },
        body: formData
      });

      if (!response.ok) {
        if (response.status === 429) {
          throw new Error('Rate limit exceeded. Please wait before scanning more URLs.');
        }
        throw new Error(`API request failed: ${response.status} ${response.statusText}`);
      }

      const uploadResult = await response.json();
      const analysisId = uploadResult.data.id;

      return await this.pollForResults(analysisId, 'url', url);

    } catch (error) {
      console.error('URL scan error:', error);
      throw error;
    }
  }

  async pollForResults(analysisId, type, name, maxAttempts = 30) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        if (!this.canMakeRequest()) {
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
          continue;
        }

        this.trackApiRequest();

        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: {
            'X-Apikey': this.apiKey
          }
        });

        if (!response.ok) {
          throw new Error(`Poll request failed: ${response.status}`);
        }

        const result = await response.json();
        
        if (result.data.attributes.status === 'completed') {
          return this.formatScanResult(result.data.attributes, type, name);
        }

        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, 3000));

      } catch (error) {
        console.error(`Poll attempt ${attempt + 1} failed:`, error);
        if (attempt >= maxAttempts - 1) {
          throw error;
        }
      }
    }

    throw new Error('Scan timeout - results not available after 30 attempts');
  }

  formatScanResult(attributes, type, name) {
    const stats = attributes.stats || {};
    const totalEngines = Object.values(stats).reduce((sum, count) => sum + count, 0);
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const harmlessCount = stats.harmless || 0;
    const undetectedCount = stats.undetected || 0;

    return {
      type,
      name,
      status: 'completed',
      stats: {
        malicious: maliciousCount,
        suspicious: suspiciousCount,
        harmless: harmlessCount,
        undetected: undetectedCount,
        timeout: stats.timeout || 0
      },
      totalEngines,
      detectionRatio: `${maliciousCount}/${totalEngines}`,
      threatLevel: this.calculateThreatLevel(maliciousCount, suspiciousCount, totalEngines),
      permalink: attributes.permalink,
      scanId: attributes.scan_id,
      scanDate: new Date().toISOString(),
      engines: attributes.scans || {}
    };
  }

  calculateThreatLevel(malicious, suspicious, total) {
    if (malicious > 0) return 'high';
    if (suspicious > 2) return 'medium';
    if (suspicious > 0) return 'low';
    return 'clean';
  }

  // Enhanced Result Display
  showScanResult(item, result) {
    const resultElement = this.createResultElement(item, result);
    
    // Add to recent scans display
    if (this.elements.recentScans) {
      this.elements.recentScans.insertBefore(resultElement, this.elements.recentScans.firstChild);
      
      // Keep only last 10 results in display
      while (this.elements.recentScans.children.length > 10) {
        this.elements.recentScans.removeChild(this.elements.recentScans.lastChild);
      }
    }

    // Show notification
    const threatLevel = result.threatLevel;
    let message, type;
    
    switch (threatLevel) {
      case 'high':
        message = `⚠️ THREAT DETECTED: ${item.name} - ${result.detectionRatio} engines detected malware`;
        type = 'error';
        break;
      case 'medium':
        message = `⚠️ Suspicious: ${item.name} - ${result.detectionRatio} engines flagged`;
        type = 'warning';
        break;
      case 'low':
        message = `ℹ️ Minor concerns: ${item.name} - ${result.detectionRatio}`;
        type = 'warning';
        break;
      default:
        message = `✅ Clean: ${item.name} - ${result.detectionRatio} engines verified safe`;
        type = 'success';
    }
    
    this.showNotification(message, type, 5000);
  }

  createResultElement(item, result) {
    const div = document.createElement('div');
    div.className = `scan-item result-item ${result.threatLevel}`;
    
    const icon = result.threatLevel === 'high' ? '🦠' : 
                 result.threatLevel === 'medium' ? '⚠️' :
                 result.threatLevel === 'low' ? 'ℹ️' : '✅';
    
    div.innerHTML = `
      <div class="result-header">
        <span class="result-icon">${icon}</span>
        <span class="result-name" title="${item.name}">${item.name}</span>
        <span class="detection-ratio">${result.detectionRatio}</span>
      </div>
      <div class="result-stats">
        ${result.stats.malicious > 0 ? `<span class="stat malicious">🦠 ${result.stats.malicious} malicious</span>` : ''}
        ${result.stats.suspicious > 0 ? `<span class="stat suspicious">⚠️ ${result.stats.suspicious} suspicious</span>` : ''}
        <span class="stat harmless">✅ ${result.stats.harmless} clean</span>
      </div>
      <div class="result-actions">
        <button onclick="scanner.showDetailedReport('${item.id}')" class="view-report-btn">📊 View Report</button>
      </div>
      <div class="scan-time">${new Date(result.scanDate).toLocaleString()}</div>
    `;
    
    return div;
  }

  // API Key Management
  async loadApiKey() {
    try {
      // Try Chrome storage first
      if (typeof chrome !== 'undefined' && chrome.storage) {
        const result = await chrome.storage.local.get(['virustotal_api_key']);
        if (result.virustotal_api_key && this.validateApiKey(result.virustotal_api_key)) {
          this.apiKey = result.virustotal_api_key;
          this.updateApiStatus('✅ API key configured');
          return;
        }
      }

      // Fallback to database
      const storedKey = await this.db.get('virustotal_api_key');
      if (storedKey && this.validateApiKey(storedKey)) {
        this.apiKey = storedKey;
        this.updateApiStatus('✅ API key configured');
        return;
      }

      this.apiKey = null;
      this.updateApiStatus('❌ No API key configured');
      
    } catch (error) {
      console.error('Failed to load API key:', error);
      this.updateApiStatus('❌ API key error');
    }
  }

  validateApiKey(key) {
    return key && typeof key === 'string' && key.length === 64 && /^[a-f0-9]+$/i.test(key);
  }

  async saveApiKey() {
    const apiKey = this.elements.apiKeyInput?.value?.trim();
    if (!apiKey) {
      this.showNotification('Please enter an API key', 'error');
      return;
    }

    if (!this.validateApiKey(apiKey)) {
      this.showNotification('Invalid API key format. Expected 64-character hexadecimal string.', 'error');
      return;
    }

    try {
      // Save to Chrome storage if available
      if (typeof chrome !== 'undefined' && chrome.storage) {
        await chrome.storage.local.set({ virustotal_api_key: apiKey });
      }
      
      // Also save to database as backup
      await this.db.set('virustotal_api_key', apiKey);
      
      this.apiKey = apiKey;
      this.elements.apiKeyInput.value = '';
      this.updateApiStatus('✅ API key saved successfully');
      this.showNotification('API key saved successfully', 'success');
      
    } catch (error) {
      console.error('Failed to save API key:', error);
      this.showNotification('Failed to save API key', 'error');
    }
  }

  updateApiStatus(status) {
    if (this.elements.apiStatus) {
      this.elements.apiStatus.textContent = status;
    }
  }

  // Settings Management
  async loadUserSettings() {
    try {
      if (this.dbManager) {
        const settings = await this.dbManager.getAllSettings();
        Object.assign(this.settings, settings);
      } else {
        const settings = await this.db.get('user_settings');
        if (settings) {
          Object.assign(this.settings, settings);
        }
      }
      
      this.applySettings();
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async saveSettings() {
    try {
      if (this.dbManager) {
        for (const [key, value] of Object.entries(this.settings)) {
          await this.dbManager.saveSetting(key, value);
        }
      } else {
        await this.db.set('user_settings', this.settings);
      }
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  }

  applySettings() {
    if (this.elements.autoScanDownloads) {
      this.elements.autoScanDownloads.checked = this.settings.autoScanDownloads;
    }
    if (this.elements.scanPermissionEnabled) {
      this.elements.scanPermissionEnabled.checked = this.settings.scanPermissionEnabled;
    }
    if (this.elements.rateLimitNotifications) {
      this.elements.rateLimitNotifications.checked = this.settings.rateLimitNotifications;
    }
    if (this.elements.maxConcurrentScans) {
      this.elements.maxConcurrentScans.value = this.settings.maxConcurrentScans;
    }
    
    this.maxConcurrentScans = this.settings.maxConcurrentScans || 2;
  }

  // Database Operations
  async saveScanResult(item, result) {
    try {
      const scanData = {
        type: item.type,
        name: item.name,
        hash: result.sha256 || null,
        size: item.size || null,
        mimeType: item.file?.type || null,
        totalEngines: result.totalEngines,
        stats: result.stats,
        scanId: result.scanId,
        permalink: result.permalink,
        scanDate: result.scanDate
      };

      if (this.dbManager) {
        await this.dbManager.saveScanResult(scanData);
      } else {
        // Fallback to simple storage
        const history = await this.db.get('scan_history') || [];
        history.unshift(scanData);
        // Keep only last 100 scans
        if (history.length > 100) {
          history.splice(100);
        }
        await this.db.set('scan_history', history);
      }
    } catch (error) {
      console.error('Failed to save scan result:', error);
    }
  }

  async loadScanHistoryFromDB() {
    try {
      let history = [];
      
      if (this.dbManager) {
        history = await this.dbManager.getScanHistory(50);
      } else {
        history = await this.db.get('scan_history') || [];
      }

      this.displayScanHistory(history);
      this.updateStatsFromHistory(history);
      
    } catch (error) {
      console.error('Failed to load scan history:', error);
    }
  }

  updateStatsFromHistory(history) {
    const today = new Date().toDateString();
    
    this.stats.totalScanned = history.length;
    this.stats.todayScans = history.filter(scan => 
      new Date(scan.scanDate || scan.created_at).toDateString() === today
    ).length;
    this.stats.threatsFound = history.filter(scan => 
      (scan.stats?.malicious || scan.malicious_count || 0) > 0
    ).length;
    this.stats.totalSafe = history.filter(scan => 
      (scan.stats?.malicious || scan.malicious_count || 0) === 0
    ).length;

    this.updateStatsDisplay();
  }

  updateStatsDisplay() {
    if (this.elements.todayScans) {
      this.elements.todayScans.textContent = this.stats.todayScans;
    }
    if (this.elements.threatsFound) {
      this.elements.threatsFound.textContent = this.stats.threatsFound;
    }
    if (this.elements.cleanScans) {
      this.elements.cleanScans.textContent = this.stats.totalSafe;
    }
  }

  // UI Management
  switchTab(tabName) {
    // Update tab buttons
    this.elements.tabButtons.forEach(button => {
      button.classList.toggle('active', button.dataset.tab === tabName);
    });

    // Update tab contents
    this.elements.tabContents.forEach(content => {
      content.classList.toggle('active', content.id === `${tabName}-tab`);
    });
  }

  updateQueueDisplay() {
    const queued = Array.from(this.scanQueue.values()).filter(item => item.status === 'queued').length;
    const processing = Array.from(this.scanQueue.values()).filter(item => item.status === 'processing').length;
    const completed = Array.from(this.scanQueue.values()).filter(item => item.status === 'completed').length;

    if (this.elements.queueCount) this.elements.queueCount.textContent = queued;
    if (this.elements.processingCount) this.elements.processingCount.textContent = processing;
    if (this.elements.completedCount) this.elements.completedCount.textContent = completed;

    // Update queue list display
    if (this.elements.queueList) {
      this.elements.queueList.innerHTML = '';
      Array.from(this.scanQueue.values()).forEach(item => {
        const queueItem = this.createQueueItemElement(item);
        this.elements.queueList.appendChild(queueItem);
      });
    }
  }

  createQueueItemElement(item) {
    const div = document.createElement('div');
    div.className = `queue-item ${item.status}`;
    
    const statusIcon = {
      'queued': '⏳',
      'processing': '🔄',
      'completed': '✅',
      'failed': '❌'
    }[item.status] || '?';

    const progressInfo = item.status === 'processing' ? 
      `<div class="progress-info">Scanning...</div>` : '';

    div.innerHTML = `
      <div class="queue-item-header">
        <span class="queue-status">${statusIcon}</span>
        <span class="queue-name" title="${item.name}">${item.name}</span>
        <span class="queue-type">${item.type.toUpperCase()}</span>
      </div>
      ${progressInfo}
      <div class="queue-actions">
        ${item.status === 'queued' ? `<button onclick="scanner.prioritizeItem('${item.id}')" class="priority-btn">⬆️</button>` : ''}
        <button onclick="scanner.removeFromQueue('${item.id}')" class="remove-btn">🗑️</button>
      </div>
    `;

    return div;
  }

  // Queue Control Methods
  pauseQueue() {
    this.isQueuePaused = true;
    this.showNotification('Queue paused', 'info');
  }

  resumeQueue() {
    this.isQueuePaused = false;
    this.showNotification('Queue resumed', 'info');
    this.processQueue();
  }

  clearQueue() {
    if (confirm('Are you sure you want to clear the entire queue?')) {
      this.scanQueue.clear();
      this.updateQueueDisplay();
      this.showNotification('Queue cleared', 'info');
    }
  }

  removeFromQueue(itemId) {
    this.scanQueue.delete(itemId);
    this.updateQueueDisplay();
    this.showNotification('Item removed from queue', 'info');
  }

  prioritizeItem(itemId) {
    const item = this.scanQueue.get(itemId);
    if (item) {
      item.priority = Math.max(...Array.from(this.scanQueue.values()).map(i => i.priority)) + 1;
      this.updateQueueDisplay();
      this.showNotification('Item prioritized', 'info');
    }
  }

  // Utility Methods
  generateQueueId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }

  showNotification(message, type = 'info', duration = 3000) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Style the notification
    Object.assign(notification.style, {
      position: 'fixed',
      top: '20px',
      right: '20px',
      padding: '12px 20px',
      borderRadius: '8px',
      color: 'white',
      fontWeight: '600',
      zIndex: '10000',
      minWidth: '200px',
      maxWidth: '400px',
      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
      backgroundColor: type === 'success' ? '#4CAF50' :
                      type === 'error' ? '#f44336' :
                      type === 'warning' ? '#FF9800' :
                      '#2196F3'
    });
    
    document.body.appendChild(notification);
    
    // Animate in
    notification.style.transform = 'translateX(100%)';
    notification.style.transition = 'transform 0.3s ease';
    setTimeout(() => {
      notification.style.transform = 'translateX(0)';
    }, 10);
    
    // Remove after duration
    setTimeout(() => {
      notification.style.transform = 'translateX(100%)';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.parentNode.removeChild(notification);
        }
      }, 300);
    }, duration);
  }

  // Data Management
  async exportHistory() {
    try {
      let history = [];
      
      if (this.dbManager) {
        history = await this.dbManager.getScanHistory(1000);
      } else {
        history = await this.db.get('scan_history') || [];
      }

      const exportData = {
        exportDate: new Date().toISOString(),
        scanHistory: history,
        stats: this.stats
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = `virustotal_scan_history_${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      
      URL.revokeObjectURL(url);
      this.showNotification('Scan history exported successfully', 'success');
      
    } catch (error) {
      console.error('Failed to export history:', error);
      this.showNotification('Failed to export history', 'error');
    }
  }

  async clearHistory() {
    if (confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
      try {
        if (this.dbManager) {
          // Clear from Supabase
          const history = await this.dbManager.getScanHistory(1000);
          for (const scan of history) {
            await this.dbManager.deleteScanHistory(scan.id);
          }
        } else {
          await this.db.set('scan_history', []);
        }

        this.stats = {
          todayScans: 0,
          threatsFound: 0,
          totalMalicious: 0,
          totalSafe: 0,
          totalScanned: 0
        };

        this.updateStatsDisplay();
        this.elements.recentScans.innerHTML = '<div class="scan-item"><span class="scan-name">No recent scans</span></div>';
        
        this.showNotification('Scan history cleared successfully', 'success');
        
      } catch (error) {
        console.error('Failed to clear history:', error);
        this.showNotification('Failed to clear history', 'error');
      }
    }
  }

  // Queue Processor
  startQueueProcessor() {
    // Process queue every 2 seconds
    setInterval(() => {
      if (!this.isQueuePaused) {
        this.processQueue();
      }
    }, 2000);
  }

  // Rate Limiter Setup
  setupRateLimiter() {
    // Reset rate limit tracker every minute
    setInterval(() => {
      const now = Date.now();
      const windowStart = now - this.rateLimit.window;
      
      if (this.rateLimitTracker) {
        for (const [timestamp] of this.rateLimitTracker) {
          if (timestamp < windowStart) {
            this.rateLimitTracker.delete(timestamp);
          }
        }
      }
    }, 10000); // Clean up every 10 seconds
  }
}

// Initialize the scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.scanner = new AdvancedVirusTotalScanner();
});

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AdvancedVirusTotalScanner;
}