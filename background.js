// background.js

// Listen for clipboard changes
chrome.clipboard.onClipboardDataChanged.addListener(handleClipboardChange);

async function handleClipboardChange() {
  const pastedText = await getPastedText();
  if (isValidURL(pastedText)) {
    await scanURL(pastedText);
  }
}

async function getPastedText() {
  return new Promise((resolve) => {
    chrome.clipboard.getData(['text'], (clipboardData) => {
      resolve(clipboardData[0]);
    });
  });
}

async function scanURL(url) {
  console.log('Scanning URL:', url);

  // Call VirusTotal API to scan the URL
  const apiKey = 'YOUR_VIRUSTOTAL_API_KEY';
  const scanUrl = `https://www.virustotal.com/vtapi/v2/url/scan?apikey=${apiKey}&url=${encodeURIComponent(url)}`;

  try {
    const response = await fetch(scanUrl, { method: 'POST' });
    const data = await response.json();
    console.log('Scan results:', data);
  } catch (error) {
    console.error('Error scanning URL:', error);
  }
}

function isValidURL(url) {
  // Simple URL validation logic using regular expression
  const urlPattern = /^https?:\/\/(?:www\.)?[a-z0-9-]+\.[a-z]{2,}(?:\/[^]*)?$/i;
  return urlPattern.test(url);
}
