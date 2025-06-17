// background.js - Arka plan servisi
console.log('Mail Güvenlik Analizi - Background script loaded');

// Content script durumunu takip et
let contentScriptStatus = {
  isInjected: false,
  lastError: null
};

// Eklenti ilk yüklendiğinde ya da güncellendiğinde çalışır
chrome.runtime.onInstalled.addListener(() => {
  console.log('Mail Güvenlik Analizi eklentisi yüklendi');
});

// Content script iletişim köprüsü
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Background script message received:', message);
  
  if (message.action === 'checkContentScript') {
    // Content script varlığını kontrol et
    checkContentScript()
      .then(result => {
        sendResponse(result);
      })
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });
    
    return true; // Asenkron yanıt için gerekli
  }
  
  if (message.action === 'injectContentScript') {
    // Content script'i manuel olarak inject et
    injectContentScript()
      .then(result => {
        sendResponse(result);
      })
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });
    
    return true; // Asenkron yanıt için gerekli
  }
  
  return false;
});

// Aktif sekmeye content script'in inject edilip edilmediğini kontrol et
async function checkContentScript() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tabs || !tabs[0]) {
      return { success: false, error: 'Active tab not found' };
    }
    
    const tab = tabs[0];
    
    // Desteklenen bir URL mi kontrol et
    const isMailUrl = isMailWebsite(tab.url);
    if (!isMailUrl) {
      return { 
        success: false, 
        error: 'Not a mail website',
        url: tab.url
      };
    }
    
    // Test mesajı gönder
    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'ping' });
      console.log('Content script ping response:', response);
      
      contentScriptStatus.isInjected = true;
      return { 
        success: true, 
        contentScriptActive: true,
        url: tab.url 
      };
    } catch (err) {
      console.log('Content script ping error:', err);
      contentScriptStatus.isInjected = false;
      contentScriptStatus.lastError = err.message;
      
      return { 
        success: false, 
        contentScriptActive: false,
        error: err.message,
        url: tab.url
      };
    }
  } catch (err) {
    console.error('Error checking content script:', err);
    return { success: false, error: err.message };
  }
}

// Content script'i manuel olarak inject et
async function injectContentScript() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tabs || !tabs[0]) {
      return { success: false, error: 'Active tab not found' };
    }
    
    const tab = tabs[0];
    
    // Desteklenen bir URL mi kontrol et
    const isMailUrl = isMailWebsite(tab.url);
    if (!isMailUrl) {
      return { 
        success: false, 
        error: 'Not a mail website',
        url: tab.url
      };
    }
    
    // Content script'i inject et
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['content.js']
    });
    
    contentScriptStatus.isInjected = true;
    
    return { 
      success: true, 
      message: 'Content script injected successfully',
      url: tab.url
    };
  } catch (err) {
    console.error('Error injecting content script:', err);
    contentScriptStatus.lastError = err.message;
    
    return { 
      success: false, 
      error: err.message
    };
  }
}

// URL'in desteklenen bir mail sitesi olup olmadığını kontrol et
function isMailWebsite(url) {
  if (!url) return false;
  
  const mailDomains = [
    'outlook.office.com',
    'outlook.live.com',
    'outlook.office365.com',
    'mail.google.com'
  ];
  
  return mailDomains.some(domain => url.includes(domain));
}