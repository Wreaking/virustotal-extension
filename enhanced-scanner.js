// Enhanced VirusTotal Scanner with Advanced Features
class EnhancedScanner {
  constructor() {
    this.scanQueue = new Map(); // Using Map for better performance
    this.activeScans = new Set();
    this.rateLimitTracker = new Map();
    this.downloadQueue = [];
    
    // Enhanced rate limiting
    this.rateLimits = {
      free: { requests: 4, window: 60000, daily: 500 },
      premium: { requests: 1000, window: 60000, daily: 31000 }
    };
    
    this.settings = {
      autoScanDownloads: true,
      scanPermissionEnabled: true,
      maxConcurrentScans: 2,
      rateLimit: 'free',
      detailedReports: true,
      notificationsEnabled: true
    };
  }

  // Advanced Queue Management
  async addToQueue(item) {
    const queueId = this.generateQueueId();
    const queueItem = {
      id: queueId,
      ...item,
      status: 'queued',
      priority: item.priority || 0,
      addedAt: Date.now(),
      retries: 0,
      maxRetries: 3
    };
    
    this.scanQueue.set(queueId, queueItem);
    
    // Save to database
    if (this.supabase) {
      await this.supabase.from('scan_queue').insert({
        user_id: 'anonymous',
        scan_type: item.type,
        target_name: item.name,
        target_data: item,
        priority: item.priority || 0
      });
    }
    
    this.updateQueueDisplay();
    this.processQueue();
    return queueId;
  }

  async processQueue() {
    if (this.activeScans.size >= this.settings.maxConcurrentScans) {
      return; // Don't exceed concurrent limit
    }

    // Check rate limits
    if (!this.canMakeRequest()) {
      this.showRateLimitWarning();
      return;
    }

    // Get highest priority queued item
    const queuedItems = Array.from(this.scanQueue.values())
      .filter(item => item.status === 'queued')
      .sort((a, b) => b.priority - a.priority);

    if (queuedItems.length === 0) return;

    const item = queuedItems[0];
    await this.processScanItem(item);
  }

  async processScanItem(item) {
    try {
      item.status = 'scanning';
      item.startedAt = Date.now();
      this.activeScans.add(item.id);
      this.updateQueueDisplay();

      const result = await this.performScan(item);
      
      item.status = 'completed';
      item.completedAt = Date.now();
      item.result = result;
      
      // Save result to database
      await this.saveScanResult(item, result);
      
    } catch (error) {
      item.retries++;
      if (item.retries >= item.maxRetries) {
        item.status = 'failed';
        item.error = error.message;
      } else {
        item.status = 'queued'; // Retry
      }
    } finally {
      this.activeScans.delete(item.id);
      this.updateQueueDisplay();
      // Continue processing queue
      setTimeout(() => this.processQueue(), 1000);
    }
  }

  // Advanced Rate Limiting with User Protection
  canMakeRequest() {
    const now = Date.now();
    const limit = this.rateLimits[this.settings.rateLimit];
    const windowStart = now - limit.window;
    
    // Clean old entries
    for (const [timestamp] of this.rateLimitTracker) {
      if (timestamp < windowStart) {
        this.rateLimitTracker.delete(timestamp);
      }
    }
    
    const currentRequests = this.rateLimitTracker.size;
    
    // Check if we're approaching the limit
    if (currentRequests >= limit.requests - 1) {
      this.showRateLimitWarning();
      return false;
    }
    
    return currentRequests < limit.requests;
  }

  async makeApiRequest(url, options = {}) {
    if (!this.canMakeRequest()) {
      throw new Error('Rate limit exceeded. Please wait before making more requests.');
    }
    
    // Track this request
    this.rateLimitTracker.set(Date.now(), true);
    
    // Make the actual API request
    const response = await fetch(url, {
      ...options,
      headers: {
        'X-Apikey': this.apiKey,
        ...options.headers
      }
    });
    
    if (!response.ok) {
      if (response.status === 429) {
        this.handleRateLimitHit();
      }
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }
    
    return response.json();
  }

  handleRateLimitHit() {
    this.showNotification('Rate limit reached. Cooling down...', 'warning');
    // Implement exponential backoff
    setTimeout(() => {
      this.rateLimitTracker.clear();
    }, this.rateLimit.cooldownPeriod);
  }

  // Enhanced File Scanning with Detection Ratios
  async scanFile(file) {
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      // Upload file
      const uploadResult = await this.makeApiRequest(
        'https://www.virustotal.com/api/v3/files',
        {
          method: 'POST',
          body: formData
        }
      );
      
      const analysisId = uploadResult.data.id;
      
      // Poll for results
      return await this.pollForResults(analysisId, 'file');
      
    } catch (error) {
      console.error('File scan error:', error);
      throw error;
    }
  }

  async scanUrl(url) {
    try {
      const formData = new FormData();
      formData.append('url', url);
      
      const uploadResult = await this.makeApiRequest(
        'https://www.virustotal.com/api/v3/urls',
        {
          method: 'POST',
          body: formData
        }
      );
      
      const analysisId = uploadResult.data.id;
      return await this.pollForResults(analysisId, 'url');
      
    } catch (error) {
      console.error('URL scan error:', error);
      throw error;
    }
  }

  async pollForResults(analysisId, type, maxAttempts = 30) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const result = await this.makeApiRequest(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`
        );
        
        if (result.data.attributes.status === 'completed') {
          return this.formatScanResult(result.data.attributes, type);
        }
        
        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, 2000));
        
      } catch (error) {
        console.error(`Poll attempt ${attempt + 1} failed:`, error);
      }
    }
    
    throw new Error('Scan timeout - results not available');
  }

  formatScanResult(attributes, type) {
    const stats = attributes.stats || {};
    
    return {
      type,
      status: 'completed',
      stats: {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        timeout: stats.timeout || 0
      },
      totalEngines: Object.values(stats).reduce((sum, count) => sum + count, 0),
      detectionRatio: `${stats.malicious || 0}/${Object.values(stats).reduce((sum, count) => sum + count, 0)}`,
      permalink: attributes.permalink,
      scanId: attributes.scan_id,
      scanDate: new Date().toISOString(),
      engines: attributes.scans || {}
    };
  }

  // Download Monitoring with Permission System
  setupDownloadMonitoring() {
    if (!chrome.downloads) return;
    
    chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
      if (!this.settings.scanPermissionEnabled) {
        suggest();
        return;
      }
      
      this.handleDownloadDetected(downloadItem, suggest);
    });
    
    chrome.downloads.onChanged.addListener((delta) => {
      if (delta.state && delta.state.current === 'complete') {
        this.handleDownloadComplete(delta.id);
      }
    });
  }

  async handleDownloadDetected(downloadItem, suggest) {
    const shouldScan = await this.promptUserForScanPermission(downloadItem);
    
    if (shouldScan && this.settings.autoScanDownloads) {
      // Add to download queue for scanning
      this.downloadQueue.push({
        id: downloadItem.id,
        filename: downloadItem.filename,
        url: downloadItem.url,
        totalBytes: downloadItem.totalBytes
      });
    }
    
    suggest();
  }

  async promptUserForScanPermission(downloadItem) {
    return new Promise((resolve) => {
      // Create permission dialog
      const dialog = this.createPermissionDialog(downloadItem);
      
      dialog.querySelector('.scan-btn').onclick = () => {
        resolve(true);
        dialog.remove();
      };
      
      dialog.querySelector('.skip-btn').onclick = () => {
        resolve(false);
        dialog.remove();
      };
      
      dialog.querySelector('.disable-btn').onclick = () => {
        this.settings.scanPermissionEnabled = false;
        this.saveSettings();
        resolve(false);
        dialog.remove();
      };
      
      document.body.appendChild(dialog);
      
      // Auto-resolve after 10 seconds (default to scan if no response)
      setTimeout(() => {
        if (document.body.contains(dialog)) {
          resolve(this.settings.autoScanDownloads);
          dialog.remove();
        }
      }, 10000);
    });
  }

  // Enhanced UI Methods
  createPermissionDialog(downloadItem) {
    const dialog = document.createElement('div');
    dialog.className = 'scan-permission-dialog';
    dialog.innerHTML = `
      <div class="dialog-content">
        <h3>🛡️ Scan Downloaded File?</h3>
        <p><strong>${downloadItem.filename}</strong></p>
        <p>Size: ${this.formatFileSize(downloadItem.totalBytes)}</p>
        <p>Would you like to scan this file for malware?</p>
        <div class="dialog-actions">
          <button class="scan-btn">🔍 Scan Now</button>
          <button class="skip-btn">Skip</button>
          <button class="disable-btn">Disable Auto-Prompt</button>
        </div>
      </div>
    `;
    return dialog;
  }

  showRateLimitWarning() {
    const warning = this.rateLimits[this.settings.rateLimit];
    const resetTime = new Date(Date.now() + warning.window);
    
    this.showNotification(
      `⚠️ Approaching rate limit (${warning.requests} requests per minute). Next reset: ${resetTime.toLocaleTimeString()}`,
      'warning'
    );
  }

  generateQueueId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  formatFileSize(bytes) {
    if (!bytes) return 'Unknown size';
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }
}

// Export for use in popup.js
window.EnhancedScanner = EnhancedScanner;