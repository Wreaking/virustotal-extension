// Enhanced Background Service Worker for Advanced VirusTotal Scanner
// Handles download monitoring, context menus, permissions, and background scanning

// Enhanced Global Variables
let contextLink = null;
let downloadQueue = new Map();
let userSettings = {
  autoScanDownloads: true,
  scanPermissionEnabled: true,
  downloadMonitoring: true,
  rateLimitNotifications: true
};
let rateLimitTracker = new Map();

// Enhanced Service Worker Event Listeners
chrome.runtime.onInstalled.addListener(() => {
  console.log('✅ Advanced VirusTotal Scanner extension installed');
  
  // Create enhanced context menus
  chrome.contextMenus.create({
    id: 'scanLink',
    title: '🔍 Scan URL with VirusTotal',
    contexts: ['link']
  });
  
  chrome.contextMenus.create({
    id: 'scanFile',
    title: '🛡️ Scan File with VirusTotal',
    contexts: ['page'],
    documentUrlPatterns: ['file://*/*']
  });

  // Set enhanced default settings
  chrome.storage.local.set({
    autoScanDownloads: true,
    scanPermissionEnabled: true,
    downloadMonitoring: true,
    rateLimitNotifications: true,
    maxConcurrentScans: 2,
    detailedReports: true,
    scanStats: {
      todayScans: 0,
      threatsFound: 0,
      lastScanDate: new Date().toDateString(),
      totalMalicious: 0,
      totalSafe: 0,
      totalScanned: 0
    }
  });
  
  // Initialize download monitoring
  setupDownloadMonitoring();
  
  console.log('✅ Extension initialized with advanced features');
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scanLink' && info.linkUrl) {
    scanURL(info.linkUrl, 'context_menu');
  } else if (info.menuItemId === 'scanFile') {
    // Handle file scanning from context menu
    chrome.tabs.sendMessage(tab.id, { action: 'scanCurrentPage' });
  }
});

// Enhanced message handling
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
        return true;
        
      case 'scanDownloadedFile':
        if (message.downloadId && message.filename) {
          handleDownloadedFileScan(message)
            .then(result => sendResponse({ success: true, result }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        } else {
          sendResponse({ success: false, error: 'Download info is required' });
        }
        return true;
        
      case 'downloadLinkDetected':
        if (message.url && message.pageUrl) {
          handleDownloadLinkDetected(message.url, message.pageUrl);
        }
        sendResponse({ success: true });
        break;
        
      case 'updateSettings':
        if (message.settings) {
          updateUserSettings(message.settings)
            .then(() => sendResponse({ success: true }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        }
        return true;
        
      case 'getQueueStatus':
        sendResponse({ 
          success: true, 
          queueSize: downloadQueue.size,
          processing: Array.from(downloadQueue.values()).filter(item => item.status === 'processing').length
        });
        break;
        
      case 'storeContextLink':
        if (message.url) {
          contextLink = message.url;
        }
        sendResponse({ success: true });
        break;
        
      default:
        console.log('Unknown action:', message.action);
        sendResponse({ success: false, error: 'Unknown action' });
    }
  } catch (error) {
    console.error('Error in message handler:', error);
    sendResponse({ success: false, error: error.message });
  }
});

// Enhanced Download Monitoring with Permission System
function setupDownloadMonitoring() {
  console.log('✅ Setting up advanced download monitoring');
  
  // Monitor download creation
  chrome.downloads.onCreated.addListener(handleDownloadCreated);
  
  // Monitor download completion
  chrome.downloads.onChanged.addListener(handleDownloadChanged);
  
  // Monitor download errors
  chrome.downloads.onErased.addListener(handleDownloadErased);
}

async function handleDownloadCreated(downloadItem) {
  try {
    console.log('📎 Download detected:', downloadItem.filename);
    
    // Get current user settings
    const settings = await chrome.storage.local.get([
      'autoScanDownloads',
      'scanPermissionEnabled',
      'downloadMonitoring'
    ]);
    
    if (!settings.downloadMonitoring) {
      console.log('⚠️ Download monitoring disabled');
      return;
    }
    
    // Add to download queue
    const queueItem = {
      id: downloadItem.id,
      filename: downloadItem.filename,
      url: downloadItem.url,
      totalBytes: downloadItem.totalBytes,
      status: 'pending',
      addedAt: Date.now(),
      shouldScan: false
    };
    
    downloadQueue.set(downloadItem.id, queueItem);
    
    // Check if we should prompt for permission
    if (settings.scanPermissionEnabled && settings.autoScanDownloads) {
      await promptUserForScanPermission(downloadItem);
    } else if (settings.autoScanDownloads) {
      queueItem.shouldScan = true;
      console.log('✅ Auto-scan enabled for:', downloadItem.filename);
    }
    
  } catch (error) {
    console.error('❌ Error handling download creation:', error);
  }
}

async function handleDownloadChanged(delta) {
  try {
    if (delta.state && delta.state.current === 'complete') {
      const queueItem = downloadQueue.get(delta.id);
      if (queueItem && queueItem.shouldScan) {
        console.log('✅ Download completed, starting scan:', queueItem.filename);
        await initiateDownloadScan(delta.id);
      }
    }
    
    if (delta.state && delta.state.current === 'interrupted') {
      console.log('⚠️ Download interrupted:', delta.id);
      downloadQueue.delete(delta.id);
    }
  } catch (error) {
    console.error('❌ Error handling download change:', error);
  }
}

function handleDownloadErased(downloadId) {
  console.log('🗑️ Download erased:', downloadId);
  downloadQueue.delete(downloadId);
}

async function promptUserForScanPermission(downloadItem) {
  try {
    // Create notification for permission
    const notificationId = `scan_permission_${downloadItem.id}`;
    
    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: 'images/icon48.png',
      title: '🛡️ Scan Downloaded File?',
      message: `Would you like to scan "${downloadItem.filename}" for malware?`,
      buttons: [
        { title: '🔍 Scan Now' },
        { title: 'Skip' }
      ],
      requireInteraction: true
    });
    
    // Handle notification clicks
    const clickHandler = (notifId, buttonIndex) => {
      if (notifId === notificationId) {
        const queueItem = downloadQueue.get(downloadItem.id);
        if (queueItem) {
          queueItem.shouldScan = (buttonIndex === 0);
          if (buttonIndex === 0) {
            console.log('✅ User chose to scan:', downloadItem.filename);
          } else {
            console.log('❌ User chose to skip:', downloadItem.filename);
          }
        }
        chrome.notifications.clear(notificationId);
        chrome.notifications.onButtonClicked.removeListener(clickHandler);
      }
    };
    
    chrome.notifications.onButtonClicked.addListener(clickHandler);
    
    // Auto-clear notification after 10 seconds
    setTimeout(() => {
      chrome.notifications.clear(notificationId);
      chrome.notifications.onButtonClicked.removeListener(clickHandler);
      const queueItem = downloadQueue.get(downloadItem.id);
      if (queueItem && queueItem.shouldScan === false) {
        // Default to scan if no response
        queueItem.shouldScan = true;
        console.log('⏰ Auto-scan enabled (no response):', downloadItem.filename);
      }
    }, 10000);
    
  } catch (error) {
    console.error('❌ Error prompting for scan permission:', error);
    // Fallback to auto-scan
    const queueItem = downloadQueue.get(downloadItem.id);
    if (queueItem) {
      queueItem.shouldScan = true;
    }
  }
}

async function initiateDownloadScan(downloadId) {
  try {
    const queueItem = downloadQueue.get(downloadId);
    if (!queueItem) {
      console.error('❌ Queue item not found for download:', downloadId);
      return;
    }
    
    queueItem.status = 'scanning';
    
    // Get download info
    const downloads = await chrome.downloads.search({ id: downloadId });
    if (downloads.length === 0) {
      console.error('❌ Download not found:', downloadId);
      return;
    }
    
    const downloadInfo = downloads[0];
    
    // Check file size (VirusTotal limit is 650MB)
    if (downloadInfo.totalBytes > 650 * 1024 * 1024) {
      console.warn('⚠️ File too large for VirusTotal:', downloadInfo.filename);
      await showScanNotification(downloadInfo.filename, 'warning', 'File too large for scanning (>650MB)');
      return;
    }
    
    // Show scanning notification
    await showScanNotification(downloadInfo.filename, 'info', 'Starting malware scan...');
    
    // Send message to popup to handle actual scanning
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0) {
        await chrome.tabs.sendMessage(tabs[0].id, {
          action: 'scanDownloadedFile',
          downloadId: downloadId,
          filename: downloadInfo.filename,
          filePath: downloadInfo.filename,
          fileSize: downloadInfo.totalBytes
        });
      }
      
      console.log('✅ Scan message sent to content script');
      queueItem.status = 'completed';
      
    } catch (error) {
      console.error('❌ Error communicating with content script:', error);
      queueItem.status = 'failed';
    }
    
  } catch (error) {
    console.error('❌ Error initiating download scan:', error);
    const queueItem = downloadQueue.get(downloadId);
    if (queueItem) {
      queueItem.status = 'failed';
    }
  }
}

async function showScanNotification(filename, type, message) {
  try {
    const iconMap = {
      'info': 'images/icon48.png',
      'warning': 'images/icon48.png',
      'error': 'images/icon48.png',
      'success': 'images/icon48.png'
    };
    
    const titleMap = {
      'info': '🔍 VirusTotal Scanner',
      'warning': '⚠️ VirusTotal Warning',
      'error': '❌ VirusTotal Error',
      'success': '✅ VirusTotal Result'
    };
    
    await chrome.notifications.create({
      type: 'basic',
      iconUrl: iconMap[type] || 'images/icon48.png',
      title: titleMap[type] || '🛡️ VirusTotal Scanner',
      message: `${filename}: ${message}`
    });
  } catch (error) {
    console.error('❌ Error showing notification:', error);
  }
}

// Enhanced settings management
async function updateUserSettings(newSettings) {
  try {
    // Update local settings
    Object.assign(userSettings, newSettings);
    
    // Save to Chrome storage
    await chrome.storage.local.set(newSettings);
    
    console.log('✅ User settings updated:', newSettings);
  } catch (error) {
    console.error('❌ Error updating settings:', error);
    throw error;
  }
}

// Enhanced URL scanning with rate limiting
async function handleScanUrl(url, source) {
  try {
    console.log(`🔍 Scanning URL from ${source}:`, url);
    
    // Check rate limits
    if (!canMakeRequest()) {
      throw new Error('Rate limit exceeded. Please wait before scanning more URLs.');
    }
    
    // Track this request
    trackApiRequest();
    
    // Get API key from storage, with fallback to environment variables
    let { virustotal_api_key } = await chrome.storage.local.get(['virustotal_api_key']);
    
    // If no API key in storage, try to get from extension config
    if (!virustotal_api_key) {
      const response = await fetch(chrome.runtime.getURL('extension-config.json'));
      const config = await response.json();
      virustotal_api_key = config.virustotalApiKey;
    }
    
    if (!virustotal_api_key || virustotal_api_key === 'YOUR_API_KEY_HERE') {
      throw new Error('No API key configured. Please set your VirusTotal API key in the extension settings.');
    }
    
    // Submit URL for scanning
    const formData = new FormData();
    formData.append('url', url);
    
    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'X-Apikey': virustotal_api_key
      },
      body: formData
    });
    
    if (!response.ok) {
      if (response.status === 429) {
        throw new Error('Rate limit exceeded. Please wait before scanning more URLs.');
      }
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }
    
    const result = await response.json();
    console.log('✅ URL scan submitted successfully:', result.data.id);
    
    // Show success notification
    await showScanNotification(url, 'success', 'Scan submitted successfully');
    
    return result;
    
  } catch (error) {
    console.error('❌ URL scan failed:', error);
    await showScanNotification(url, 'error', error.message);
    throw error;
  }
}

async function handleDownloadedFileScan(message) {
  try {
    console.log('🔍 Handling downloaded file scan:', message.filename);
    
    // This would typically read the file and submit it to VirusTotal
    // For now, we'll just show a notification that the scan was initiated
    await showScanNotification(message.filename, 'info', 'File scan initiated');
    
    return { success: true, message: 'File scan initiated' };
  } catch (error) {
    console.error('❌ File scan failed:', error);
    throw error;
  }
}

// Rate limiting functions
function canMakeRequest() {
  const now = Date.now();
  const windowStart = now - 60000; // 1 minute window
  
  // Clean old entries
  for (const [timestamp] of rateLimitTracker) {
    if (timestamp < windowStart) {
      rateLimitTracker.delete(timestamp);
    }
  }
  
  return rateLimitTracker.size < 4; // Free tier limit
}

function trackApiRequest() {
  rateLimitTracker.set(Date.now(), true);
}

// Download link detection from original file
async function handleDownloadLinkDetected(url, pageUrl) {
  try {
    console.log('📥 Download link detected:', url);
    
    // Store for context menu scanning
    contextLink = url;
    
    // Get user settings
    const settings = await chrome.storage.local.get(['autoScanDownloads', 'scanPermissionEnabled']);
    
    if (settings.autoScanDownloads && settings.scanPermissionEnabled) {
      // Show notification about detected download link
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'images/icon48.png',
        title: '📥 Download Link Detected',
        message: `Click to scan: ${url.split('/').pop() || 'Unknown file'}`,
        buttons: [
          { title: '🔍 Scan Now' },
          { title: 'Ignore' }
        ],
        requireInteraction: false
      });
    }
  } catch (error) {
    console.error('❌ Error handling download link detection:', error);
  }
}

// Load settings on startup
chrome.storage.local.get([
  'autoScanDownloads',
  'scanPermissionEnabled', 
  'downloadMonitoring',
  'rateLimitNotifications',
  'maxConcurrentScans',
  'detailedReports'
]).then(settings => {
  Object.assign(userSettings, settings);
  console.log('✅ User settings loaded:', userSettings);
}).catch(error => {
  console.error('❌ Error loading settings:', error);
});

// Periodic cleanup of rate limit tracker
setInterval(() => {
  const now = Date.now();
  const windowStart = now - 60000;
  
  for (const [timestamp] of rateLimitTracker) {
    if (timestamp < windowStart) {
      rateLimitTracker.delete(timestamp);
    }
  }
}, 10000); // Clean up every 10 seconds

console.log('🚀 Enhanced VirusTotal Scanner background script loaded');