# 🛡️ Email Security Analysis - Browser Extension for Email Security

<div align="center">
  <img src="icons/icon128.png" alt="Email Security Analysis Logo" width="128" height="128">
  
  [![Version](https://img.shields.io/badge/version-3.0-blue.svg)](https://github.com/yourusername/mail-security-extension)
  [![Chrome](https://img.shields.io/badge/Chrome-Supported-brightgreen.svg)](https://www.google.com/chrome/)
  [![Edge](https://img.shields.io/badge/Edge-Supported-brightgreen.svg)](https://www.microsoft.com/edge)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
  
  **Real-time security analysis extension for Outlook and Gmail emails**
  
  [English](#english) | [Türkçe](README.md) | [Español](#español) | [Deutsch](#deutsch)
</div>

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Installation](#-installation)
3. [Getting API Keys](#-getting-api-keys)
4. [Usage](#-usage)
5. [Changing Language](#-changing-language)
6. [Directory Structure](#-directory-structure)
7. [Optional Features](#-optional-features)
8. [Security](#-security)
9. [Troubleshooting](#-troubleshooting)
10. [Development](#-development)
11. [License](#-license)

---

## ✨ Features

### 🔍 Core Features
- **Email Security Analysis**: Automatic analysis of emails in Outlook and Gmail
- **URL Checking**: Security scanning of all links in emails
- **Attachment Analysis**: Detection of malicious attachments
- **Risk Scoring**: Detailed risk score from 0-100

### 🌟 Advanced Features
- **Sender Reputation Check**
  - SPF/DKIM/DMARC validation
  - Domain age verification
  - IP reputation analysis
- **Multiple Threat Intelligence**
  - VirusTotal integration
  - AbuseIPDB integration (optional)
- **Multi-language Support**
  - 🇬🇧 English
  - 🇹🇷 Turkish
  - 🇪🇸 Spanish
  - 🇩🇪 German

---

## 🚀 Installation

### 📦 Downloading Files

1. Clone the project to your computer:
   ```bash
   git clone https://github.com/yourusername/mail-security-extension.git
   ```
   or download as ZIP and extract.

### 🌐 Installing on Chrome

1. Open Chrome browser
2. Type `chrome://extensions/` in the address bar and press Enter
3. Enable **"Developer mode"** toggle in the top right corner
4. Click **"Load unpacked"** button
5. Select the downloaded folder (the folder containing manifest.json)
6. Extension installed! 🎉

### 🌐 Installing on Microsoft Edge

1. Open Edge browser
2. Type `edge://extensions/` in the address bar and press Enter
3. Enable **"Developer mode"** toggle in the bottom left
4. Click **"Load unpacked"** button
5. Select the downloaded folder
6. Extension installed! 🎉

### 🌐 Installing on Opera

1. Open Opera browser
2. Type `opera://extensions/` in the address bar
3. Click **"Developer mode"** button in the top right
4. Click **"Load unpacked extension"** button
5. Select the downloaded folder
6. Extension installed! 🎉

---

## 🔑 Getting API Keys

### 1️⃣ VirusTotal API Key (REQUIRED)

1. Go to [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Log in to your account
4. Go to [API Key page](https://www.virustotal.com/gui/my-apikey)
5. Copy your API key

**Free Limit**: 4 requests per minute, 500 requests per month

### 2️⃣ AbuseIPDB API Key (OPTIONAL)

1. Go to [AbuseIPDB](https://www.abuseipdb.com/register)
2. Create a free account
3. Verify your email
4. Go to [API page](https://www.abuseipdb.com/account/api)
5. Click "Create Key" button
6. Copy your API key

**Free Limit**: 1000 requests per day

### 📝 Adding API Keys to Extension

1. Click the extension icon in the browser toolbar
2. Switch to **"Settings"** tab
3. Paste your VirusTotal API key in the first field
4. (Optional) Paste your AbuseIPDB API key in the second field
5. Click **"Save"** button

---

## 📖 Usage

### Basic Usage

1. Log in to your **Outlook** or **Gmail** account
2. Open any email
3. Click the extension icon in the browser toolbar
4. Click **"Analyze Email"** button
5. Review the analysis results

### Risk Levels

- 🟢 **Low Risk (0-25)**: Email appears safe
- 🟡 **Medium Risk (25-50)**: Be cautious, suspicious elements found
- 🔴 **High Risk (50-100)**: Dangerous! Do not click links or open attachments

### Demo Test

You can use the **"Demo Phishing Test"** button to test the extension. This shows a fake phishing email analysis.

---

## 🌍 Changing Language

The extension **automatically selects language based on your browser's language setting**.

### Changing Language in Chrome

1. Go to Chrome Settings (⋮ → Settings)
2. From left menu **"Advanced"** → **"Languages"**
3. Expand **"Language"** section
4. Add your desired language or change the order
5. The top language will be used in the extension
6. Restart Chrome

### Changing Language in Edge

1. Go to Edge Settings (⋯ → Settings)
2. From left menu **"Languages"**
3. Add your desired language and click **"..."** → **"Display Microsoft Edge in this language"**
4. Restart Edge

### Supported Languages

- **English** (en) - Default
- **Türkçe** (tr)
- **Español** (es)
- **Deutsch** (de)

---

## 📁 Directory Structure

```
Chrome Extension/
│
├── 📄 README.md              ← Turkish documentation
├── 📄 README-EN.md           ← This file (add to main directory)
├── 📄 manifest.json          ← Extension configuration file
├── 📄 background.js          ← Background service
├── 📄 content.js             ← Content script (email analysis)
├── 📄 popup.html             ← Extension interface
├── 📄 popup.js               ← Extension controller
├── 📄 language-manager.js    ← Language management (optional)
│
├── 📁 icons/                 ← Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
│
└── 📁 _locales/              ← Language files
    ├── 📁 en/
    │   └── messages.json     ← English
    ├── 📁 tr/
    │   └── messages.json     ← Turkish
    ├── 📁 es/
    │   └── messages.json     ← Spanish
    └── 📁 de/
        └── messages.json     ← German
```

---

## ⚙️ Optional Features

### 1. AbuseIPDB Integration

You can enable AbuseIPDB API for IP reputation control:
- Sender IP address abuse history
- Geographic location information
- ISP information

### 2. Manual Language Selection

By default, it works according to browser language. To add manual language selection:
1. Add `language-manager.js` file to the project
2. Language selector becomes active in popup
3. Users can select their preferred language

### 3. Whitelist/Blacklist (Future Version)

Feature to create trusted or blocked email address lists is planned.

---

## 🔒 Security

### Data Privacy

- ✅ Email contents are **never sent anywhere**
- ✅ Only URLs and file hashes are checked
- ✅ All analyses are done **locally**
- ✅ API keys are stored **encrypted**

### Permissions

The extension only uses these permissions:
- `activeTab`: Only works on the active tab
- `storage`: Stores API keys
- `dns`: For SPF/DMARC checks

### Security Tips

1. **Never share** your API keys
2. **Don't click** links in suspicious emails
3. **Don't download** high-risk attachments
4. **Use common sense** despite analysis results

---

## 🔧 Troubleshooting

### "Content script not responding" error

1. Refresh the page (F5)
2. Click "Load" button
3. Remove and reinstall the extension

### API key errors

1. Make sure your API key is correct
2. Check your free limit
3. Re-enter the API key

### Language not changing

1. After changing browser language, **completely close and restart** the browser
2. Refresh the extension page

---

## 👨‍💻 Development

### Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push your branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Testing

```bash
# Load extension in developer mode
# Check console for errors
# Test features with demo test
```

### Adding New Language

1. Add new language folder to `_locales/` (e.g., `fr`)
2. Copy `messages.json` from English
3. Translate all messages
4. Add to language selector in `popup.html` (optional)

---

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com) - Security analysis API
- [AbuseIPDB](https://www.abuseipdb.com) - IP reputation API
- All contributors

---

## 📞 Contact

- **Email**: your-email@example.com
- **GitHub**: [github.com/yourusername](https://github.com/yourusername)
- **Issues**: [GitHub Issues](https://github.com/yourusername/mail-security-extension/issues)

---

<div align="center">
  <strong>🛡️ Email Security Analysis for safer email experience!</strong>
  
  ⭐ Don't forget to star the project if you like it!
</div>
