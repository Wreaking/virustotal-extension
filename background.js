// background.js - Service Worker for MV3

// Global variables
let contextLink = null;

// Service worker event listeners
chrome.runtime.onInstalled.addListener(() => {
  console.log('VirusTotal Scanner extension installed');
  
  // Create context menu for scanning links
  chrome.contextMenus.create({
    id: 'scanLink',
    title: 'Scan with VirusTotal',
    contexts: ['link']
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scanLink' && info.linkUrl) {
    scanURL(info.linkUrl, 'context_menu');
  }
});

// Handle messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Background received message:', message);
  
  try {
    switch (message.action) {
      case 'scanUrl':
        if (!message.url) {
          sendResponse({ success: false, error: 'URL is required' });
          return;
        }
        handleScanUrl(message.url, message.source || 'unknown')
          .then(result => sendResponse({ success: true, result }))
          .catch(error => {
            console.error('Error in handleScanUrl:', error);
            sendResponse({ success: false, error: error.message });
          });
        return true; // Keep message channel open for async response
        
      case 'downloadLinkDetected':
        if (message.url && message.pageUrl) {
          handleDownloadLinkDetected(message.url, message.pageUrl);
        }
        sendResponse({ success: true });
        break;
        
      case 'storeContextLink':
        if (message.url) {
          contextLink = message.url;
        }
        sendResponse({ success: true });
        break;
        
      case 'getDownloadInfo':
        if (message.downloadId) {
          getStoredDownloadInfo(message.downloadId)
            .then(downloadInfo => sendResponse({ success: true, downloadInfo }))
            .catch(error => sendResponse({ success: false, error: error.message }));
          return true;
        }
        sendResponse({ success: false, error: 'Download ID required' });
        break;
        
      case 'scanFile':
        if (message.file) {
          handleFileScan(message.file)
            .then(result => sendResponse({ success: true, result }))
            .catch(error => sendResponse({ success: false, error: error.message }));
          return true;
        }
        sendResponse({ success: false, error: 'File data required' });
        break;
        
      default:
        sendResponse({ success: false, error: 'Unknown action' });
    }
  } catch (error) {
    console.error('Error handling message:', error);
    sendResponse({ success: false, error: 'Internal error' });
  }
});

// Handle download monitoring with user prompts
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  console.log('Download detected:', downloadItem);
  
  // Check if download prompt is enabled
  const settings = await chrome.storage.local.get(['downloadPrompt', 'autoScan']);
  const shouldPrompt = settings.downloadPrompt !== false;
  
  if (shouldPrompt) {
    await handleDownloadCreated(downloadItem);
  }
});

// Listen for download completion to offer scanning
chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === 'complete') {
    const [downloadItem] = await chrome.downloads.search({ id: delta.id });
    if (downloadItem) {
      await promptForDownloadScan(downloadItem);
    }
  }
});

// Main URL scanning function
async function handleScanUrl(url, source) {
  console.log(`Scanning URL from ${source}:`, url);
  
  if (!isValidURL(url)) {
    throw new Error('Invalid URL format');
  }
  
  try {
    const result = await scanURL(url);
    
    // Show notification with result
    showScanNotification(url, result, source);
    
    return result;
  } catch (error) {
    console.error('Error scanning URL:', error);
    throw error;
  }
}

async function scanURL(url, source = 'unknown') {
  console.log('Scanning URL:', url);

  try {
    // Validate URL
    if (!url || typeof url !== 'string') {
      throw new Error('Invalid URL provided');
    }

    // Get API key and check rate limits
    const storageResult = await chrome.storage.local.get(['vtApiKey', 'globalRateLimit']);
    const apiKey = storageResult.vtApiKey;
    
    if (!apiKey || apiKey.trim() === '') {
      throw new Error('VirusTotal API key not configured. Please set it in the extension popup.');
    }

    // Enhanced API key validation
    if (!validateApiKey(apiKey)) {
      throw new Error('Invalid API key format. Expected 64-character hexadecimal string.');
    }

    // Check global rate limits
    if (!await checkGlobalRateLimit()) {
      throw new Error('Rate limit exceeded. Please wait before making more requests.');
    }

    // Submit URL for scanning with enhanced error handling
    const scanResponse = await fetchWithBackgroundRateLimit('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });

    if (!scanResponse.ok) {
      if (scanResponse.status === 429) {
        throw new Error('Rate limited by VirusTotal. Please wait before scanning again.');
      }
      throw new Error(`VirusTotal API error: ${scanResponse.status} ${scanResponse.statusText}`);
    }

    const scanData = await scanResponse.json();
    const analysisId = scanData.data.id;
    
    // Get analysis results with enhanced retry logic
    const result = await getAnalysisResultsBackground(analysisId);
    
    // Process and return enhanced results
    const scanResult = {
      url: url,
      analysisId: analysisId,
      malicious: result.stats.malicious,
      suspicious: result.stats.suspicious,
      harmless: result.stats.harmless,
      undetected: result.stats.undetected,
      total: result.stats.total,
      riskScore: result.riskScore,
      threatSeverity: result.threatSeverity,
      detections: result.detections,
      scan_date: result.scanDate,
      status: result.isMalicious ? 'unsafe' : 'safe',
      source: source
    };

    console.log('Enhanced scan results:', scanResult);
    return scanResult;
    
  } catch (error) {
    console.error('Error scanning URL:', error);
    throw error;
  }
}

// Enhanced API key validation for background
function validateApiKey(apiKey) {
  if (!apiKey) return false;
  const apiKeyRegex = /^[a-f0-9]{64}$/i;
  return apiKeyRegex.test(apiKey.trim());
}

// Global rate limiting check
async function checkGlobalRateLimit() {
  const stored = await chrome.storage.local.get(['globalRateLimit']);
  const globalLimit = stored.globalRateLimit || {
    requests: 0,
    resetTime: 0,
    maxRequests: 4,
    window: 60000
  };
  
  const now = Date.now();
  
  if (now > globalLimit.resetTime) {
    globalLimit.requests = 0;
    globalLimit.resetTime = now + globalLimit.window;
  }

  if (globalLimit.requests >= globalLimit.maxRequests) {
    return false;
  }

  globalLimit.requests++;
  await chrome.storage.local.set({ globalRateLimit: globalLimit });
  return true;
}

// Rate limiting wrapper for background fetch
async function fetchWithBackgroundRateLimit(url, options = {}) {
  try {
    const response = await fetch(url, options);
    
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      const waitTime = retryAfter ? parseInt(retryAfter) : 60;
      throw new Error(`Rate limited by server. Retry in ${waitTime} seconds.`);
    }
    
    if (response.status === 401) {
      throw new Error('Invalid API key. Please check your VirusTotal API key.');
    }
    
    return response;
  } catch (error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error('Network error. Check your internet connection.');
    }
    throw error;
  }
}

// Enhanced analysis results for background
async function getAnalysisResultsBackground(analysisId) {
  const maxAttempts = 10;
  let attempts = 0;
  
  while (attempts < maxAttempts) {
    try {
      const response = await fetchWithBackgroundRateLimit(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: {
          'x-apikey': (await chrome.storage.local.get(['vtApiKey'])).vtApiKey
        }
      });

      if (!response.ok) {
        throw new Error(`Analysis fetch failed: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.data.attributes.status === 'completed') {
        return processAnalysisDataBackground(data.data.attributes);
      }

      const waitTime = Math.min(2000 * Math.pow(1.5, attempts), 30000);
      await delay(waitTime);
      attempts++;

    } catch (error) {
      attempts++;
      if (attempts >= maxAttempts) {
        throw error;
      }
      await delay(3000);
    }
  }

  throw new Error('Analysis timeout');
}

// Process analysis data in background (simplified version)
function processAnalysisDataBackground(attributes) {
  const stats = attributes.stats;
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  const engineResults = attributes.results || {};
  const detections = [];

  Object.entries(engineResults).forEach(([engineName, result]) => {
    if (result.category === 'malicious' || result.category === 'suspicious') {
      detections.push({
        engine: engineName,
        threat: result.result,
        category: result.category
      });
    }
  });

  const isMalicious = malicious > 0 || suspicious > 0;
  const riskScore = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  
  let threatSeverity = 'Safe';
  if (isMalicious) {
    if (riskScore < 20) threatSeverity = 'Low Risk';
    else if (riskScore < 50) threatSeverity = 'Medium Risk';
    else if (riskScore < 80) threatSeverity = 'High Risk';
    else threatSeverity = 'Critical Risk';
  }

  return {
    isMalicious,
    riskScore,
    threatSeverity,
    stats: { malicious, suspicious, harmless, undetected, total },
    detections,
    scanDate: new Date().toISOString()
  };
}

function handleDownloadLinkDetected(downloadUrl, pageUrl) {
  console.log('Download link detected:', downloadUrl, 'on page:', pageUrl);
  
  // Show notification about detected download
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'images/icon48.png',
    title: 'Download Link Detected',
    message: `Found download link: ${downloadUrl.substring(0, 50)}...`
  });
}

async function handleDownloadCreated(downloadItem) {
  try {
    // Only prompt for potentially risky file types
    const riskyExtensions = ['.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.apk', '.ipa', 
                            '.jar', '.app', '.run', '.bin', '.com', '.scr', '.bat', '.cmd', '.ps1'];
    
    const filename = downloadItem.filename || '';
    const isRisky = riskyExtensions.some(ext => filename.toLowerCase().endsWith(ext));
    const isLarge = downloadItem.fileSize > 10 * 1024 * 1024; // Files > 10MB
    
    if (isRisky || isLarge) {
      console.log('Risky download detected:', filename);
      
      // Try to send message to popup if open
      try {
        await chrome.runtime.sendMessage({
          action: 'downloadPrompt',
          downloadItem: {
            id: downloadItem.id,
            filename: downloadItem.filename,
            fileSize: downloadItem.fileSize || 0,
            url: downloadItem.finalUrl || downloadItem.url,
            referrer: downloadItem.referrer,
            startTime: downloadItem.startTime
          }
        });
      } catch (error) {
        // Popup not open, show notification instead
        await showDownloadDetectionNotification(downloadItem);
      }
    }
  } catch (error) {
    console.error('Error handling download creation:', error);
  }
}

// Show notification when risky download is detected
async function showDownloadDetectionNotification(downloadItem) {
  await chrome.notifications.create({
    type: 'basic',
    iconUrl: 'images/icon48.png',
    title: '⚠️ Risky Download Detected',
    message: `File: ${downloadItem.filename}\nSize: ${formatFileSize(downloadItem.fileSize || 0)}\nClick to open scanner`,
    buttons: [
      { title: '🛡️ Open Scanner' },
      { title: '❌ Dismiss' }
    ],
    requireInteraction: true
  });
}

// Prompt user when download completes
async function promptForDownloadScan(downloadItem) {
  const settings = await chrome.storage.local.get(['downloadPrompt']);
  if (settings.downloadPrompt === false) return;

  const notification = await chrome.notifications.create({
    type: 'basic',
    iconUrl: 'images/icon48.png',
    title: '🔽 Download Complete - Scan for Malware?',
    message: `${downloadItem.filename}\nSize: ${formatFileSize(downloadItem.fileSize || 0)}\nRecommended: Scan before opening`,
    buttons: [
      { title: '🛡️ Scan Now' },
      { title: '❌ Skip Scan' }
    ],
    requireInteraction: true
  });

  // Store download info for later scanning
  await chrome.storage.local.set({
    [`pendingDownload_${downloadItem.id}`]: {
      id: downloadItem.id,
      filename: downloadItem.filename,
      fileSize: downloadItem.fileSize,
      fullPath: downloadItem.filename,
      url: downloadItem.finalUrl || downloadItem.url,
      completedTime: Date.now()
    }
  });
}

// Format file size helper function
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Get stored download info for scanning
async function getStoredDownloadInfo(downloadId) {
  try {
    const result = await chrome.storage.local.get([`pendingDownload_${downloadId}`]);
    const downloadInfo = result[`pendingDownload_${downloadId}`];
    
    if (!downloadInfo) {
      throw new Error('Download information not found');
    }
    
    return downloadInfo;
  } catch (error) {
    throw new Error(`Failed to get download info: ${error.message}`);
  }
}

// Handle file scanning from background
async function handleFileScan(fileData) {
  try {
    // This would be used for downloaded files
    console.log('Background file scan requested for:', fileData.filename);
    
    // For now, redirect to popup for file scanning
    chrome.action.openPopup();
    
    return {
      message: 'Redirected to popup for file scanning',
      filename: fileData.filename
    };
  } catch (error) {
    throw new Error(`File scan failed: ${error.message}`);
  }
}

// Enhanced notification button handling
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  console.log('Notification button clicked:', notificationId, buttonIndex);
  
  try {
    if (buttonIndex === 0) { // First button (Scan Now / Open Scanner)
      // Store notification context for popup
      await chrome.storage.local.set({
        [`notification_${notificationId}`]: {
          timestamp: Date.now(),
          action: 'scan_request',
          source: 'notification'
        }
      });
      
      // Open the extension popup
      chrome.action.openPopup();
      
      // Send message to popup about the scan request with retry
      let retries = 3;
      const sendMessage = async () => {
        try {
          await chrome.runtime.sendMessage({
            action: 'notificationScanRequest',
            notificationId: notificationId
          });
        } catch (error) {
          if (retries > 0) {
            retries--;
            setTimeout(sendMessage, 1000);
          } else {
            console.log('Popup not available for scan request message after retries');
          }
        }
      };
      
      setTimeout(sendMessage, 500);
    }
  } catch (error) {
    console.error('Error handling notification button click:', error);
  }
  
  // Clear the notification
  chrome.notifications.clear(notificationId);
});

// Handle notification clicks (when user clicks the notification body)
chrome.notifications.onClicked.addListener(async (notificationId) => {
  console.log('Notification clicked:', notificationId);
  
  // Open popup on notification click
  chrome.action.openPopup();
  chrome.notifications.clear(notificationId);
});

function showScanNotification(url, result, source) {
  const isUnsafe = result.status === 'unsafe';
  const title = isUnsafe ? '⚠️ Threat Detected' : '✅ Safe';
  const message = isUnsafe 
    ? `${result.malicious}/${result.total} engines detected threats`
    : `No threats found (${result.total} engines checked)`;

  chrome.notifications.create({
    type: 'basic',
    iconUrl: isUnsafe ? 'images/icon48.png' : 'images/icon48.png',
    title: title,
    message: `${url.substring(0, 40)}...\n${message}`
  });
}

function isValidURL(url) {
  try {
    new URL(url);
    return url.startsWith('http://') || url.startsWith('https://');
  } catch {
    return false;
  }
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Error handling for unhandled promise rejections
self.addEventListener('unhandledrejection', event => {
  console.error('Unhandled promise rejection:', event.reason);
  
  // Show user-friendly notification for critical errors
  if (event.reason && typeof event.reason === 'object' && event.reason.message) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'images/icon48.png',
      title: 'VirusTotal Scanner Error',
      message: 'An unexpected error occurred. Check console for details.'
    });
  }
});

// Handle extension installation and updates
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('VirusTotal Scanner installed successfully');
    // Set default settings
    chrome.storage.local.set({
      autoScanDownloads: false,
      scanStats: {
        todayScans: 0,
        threatsFound: 0,
        lastScanDate: new Date().toDateString()
      }
    });
  } else if (details.reason === 'update') {
    console.log('VirusTotal Scanner updated to version', chrome.runtime.getManifest().version);
  }
});