// Script to create extension icons using Sharp
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');

// Create SVG icon content
const svgIcon = `
<svg width="128" height="128" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#4CAF50;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#2E7D32;stop-opacity:1" />
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge> 
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  
  <!-- Background circle -->
  <circle cx="64" cy="64" r="60" fill="url(#shieldGradient)" filter="url(#glow)"/>
  
  <!-- Shield shape -->
  <path d="M64 20 L64 20 C76 20 86 26 86 35 L86 70 C86 85 75 95 64 108 C53 95 42 85 42 70 L42 35 C42 26 52 20 64 20 Z" 
        fill="white" opacity="0.9"/>
  
  <!-- Virus/malware detection symbol -->
  <circle cx="64" cy="50" r="12" fill="#f44336"/>
  <line x1="58" y1="44" x2="70" y2="56" stroke="white" stroke-width="3" stroke-linecap="round"/>
  <line x1="70" y1="44" x2="58" y2="56" stroke="white" stroke-width="3" stroke-linecap="round"/>
  
  <!-- Checkmark for protection -->
  <path d="M54 75 L60 81 L74 67" stroke="#4CAF50" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  
  <!-- Scanner lines -->
  <line x1="32" y1="30" x2="38" y2="30" stroke="white" stroke-width="2" opacity="0.8"/>
  <line x1="90" y1="30" x2="96" y2="30" stroke="white" stroke-width="2" opacity="0.8"/>
  <line x1="32" y1="98" x2="38" y2="98" stroke="white" stroke-width="2" opacity="0.8"/>
  <line x1="90" y1="98" x2="96" y2="98" stroke="white" stroke-width="2" opacity="0.8"/>
</svg>
`;

// Save the SVG file first
fs.writeFileSync(path.join(__dirname, 'icon.svg'), svgIcon);

// Icon sizes for Chrome extension
const sizes = [16, 32, 48, 128];
const imagesDir = path.join(__dirname, 'images');

// Ensure images directory exists
if (!fs.existsSync(imagesDir)) {
  fs.mkdirSync(imagesDir, { recursive: true });
}

async function generateIcons() {
  try {
    console.log('Generating PNG icons from SVG...');
    
    for (const size of sizes) {
      await sharp(Buffer.from(svgIcon, 'utf8'))
        .resize(size, size)
        .png()
        .toFile(path.join(imagesDir, `icon${size}.png`));
      
      console.log(`Generated icon${size}.png (${size}x${size})`);
    }
    
    console.log('All icons generated successfully!');
    console.log('You can now reload your Chrome extension to use the new icons.');
  } catch (error) {
    console.error('Error generating icons:', error);
  }
}

// Run the generation
generateIcons();
