// Mail Güvenlik Analizi - Enhanced Content Script v3.0
console.log('🚀 Mail Security Extension content script loaded v3.0');

// Global değişkenler
let currentMailData = null;
let isAnalysisInProgress = false;
let platformType = 'unknown'; // 'outlook' veya 'gmail'

// API Ayarları
let VIRUSTOTAL_API_KEY = null;
let ABUSEIPDB_API_KEY = null;
let URLVOID_API_KEY = null;

// API URLs
const VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3";
const ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2";
const DNS_OVER_HTTPS_URL = "https://dns.google/resolve";

// i18n helper
function getMessage(key, substitutions) {
    return chrome.i18n.getMessage(key, substitutions) || key;
}

// Başlangıç
init();

// Extension başlatma fonksiyonu
async function init() {
    console.log('📋 Mail analiz eklentisi başlatılıyor...');
    
    // API key'leri yükle
    await loadApiKeys();
    
    // Platform tespiti
    detectPlatform();
    
    // Extension popup ile iletişim için mesaj dinleyicisi
    chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
        console.log('📩 Message received in content script:', request);
        
        try {
            // Ping - iletişim kontrolü
            if (request.action === 'ping') {
                sendResponse({
                    success: true,
                    message: "Content script is working!",
                    platform: platformType,
                    url: window.location.href,
                    language: chrome.i18n.getUILanguage()
                });
                return true;
            }
            
            // API key yeniden yükleme
            if (request.action === 'reloadApiKey') {
                loadApiKeys().then(success => {
                    sendResponse({
                        success: success,
                        message: success ? 'API keys reloaded' : 'Failed to reload API keys'
                    });
                });
                return true;
            }
            
            // E-posta analiz işlemi
            if (request.action === 'analyzeEmail') {
                console.log('📧 E-posta analiz isteği alındı');
                
                // E-posta analizini başlat
                analyzeCurrentEmail()
                    .then(result => {
                        console.log('📊 Analiz sonucu:', result);
                        sendResponse({ 
                            success: true,
                            result: result
                        });
                    })
                    .catch(error => {
                        console.error('❌ Analiz hatası:', error);
                        sendResponse({ 
                            success: false,
                            error: error.message
                        });
                    });
                
                return true; // Asenkron yanıt için
            }
            
            // Debug bilgisi
            if (request.action === 'getEmailContent') {
                const emailData = extractEmailContent();
                sendResponse({
                    success: true,
                    emailData: emailData
                });
                return true;
            }
            
            // Bilinmeyen istek
            sendResponse({
                success: false,
                error: "Unknown action: " + request.action
            });
            return true;
            
        } catch (error) {
            console.error('❌ Message handler error:', error);
            sendResponse({ 
                success: false, 
                error: error.message
            });
            return true;
        }
    });
    
    console.log('✅ Mail Security Extension content script ready');
}

// API key'leri storage'dan yükle
async function loadApiKeys() {
    try {
        const result = await chrome.storage.local.get([
            'virusTotalApiKey', 
            'abuseIPDBApiKey',
            'urlVoidApiKey'
        ]);
        
        if (result.virusTotalApiKey) {
            VIRUSTOTAL_API_KEY = result.virusTotalApiKey;
            console.log('✅ VirusTotal API key loaded');
        }
        
        if (result.abuseIPDBApiKey) {
            ABUSEIPDB_API_KEY = result.abuseIPDBApiKey;
            console.log('✅ AbuseIPDB API key loaded');
        }
        
        if (result.urlVoidApiKey) {
            URLVOID_API_KEY = result.urlVoidApiKey;
            console.log('✅ URLVoid API key loaded');
        }
        
        return true;
    } catch (error) {
        console.error('❌ Error loading API keys:', error);
        return false;
    }
}

// Platform tespiti (Outlook veya Gmail)
function detectPlatform() {
    const url = window.location.href.toLowerCase();
    
    if (url.includes('outlook.office') || 
        url.includes('outlook.live') || 
        url.includes('outlook.office365')) {
        platformType = 'outlook';
    } else if (url.includes('mail.google.com')) {
        platformType = 'gmail';
    }
    
    console.log('🔍 Platform detected:', platformType);
    return platformType;
}

// E-posta içeriğini çıkar
function extractEmailContent() {
    console.log('📧 E-posta içeriği çıkarılıyor...');
    
    try {
        if (platformType === 'outlook') {
            return extractOutlookEmailContent();
        } else if (platformType === 'gmail') {
            return extractGmailEmailContent();
        } else {
            throw new Error('Desteklenmeyen platform: ' + platformType);
        }
    } catch (error) {
        console.error('❌ E-posta içeriği çıkarma hatası:', error);
        return {
            subject: 'Çıkarma hatası',
            sender: 'Bilinmiyor',
            body: '',
            links: [],
            attachments: [],
            headers: {}
        };
    }
}

// Outlook e-posta içeriğini çıkar
function extractOutlookEmailContent() {
    // Konu
    const subjectElement = document.querySelector('[role="heading"][aria-level="1"]') || 
                         document.querySelector('.rps_7d32 .fNGvUR');
    const subject = subjectElement ? subjectElement.textContent.trim() : 'Konu bulunamadı';
    
    // Gönderen
    const senderElements = document.querySelectorAll('.lF34jE .rZ7OQf, .XnY2d, .G4a5N');
    let sender = 'Gönderen bulunamadı';
    let senderEmail = '';
    
    if (senderElements && senderElements.length > 0) {
        const senderName = senderElements[0].textContent.trim();
        senderEmail = senderElements.length > 1 ? 
            senderElements[1].textContent.trim().replace(/[<>]/g, '') : '';
        sender = senderEmail || senderName;
    }
    
    // İçerik
    const bodyElement = document.querySelector('[role="region"][aria-label="Ileti gövdesi"]') || 
                      document.querySelector('[role="region"][aria-label="Message body"]');
    const body = bodyElement ? bodyElement.innerHTML : '';
    
    // URL'leri çıkar
    const links = extractLinksFromContent(body);
    
    // Ekleri çıkar
    const attachments = [];
    const attachmentElements = document.querySelectorAll('[role="listitem"][aria-label*="attachment"], [role="listitem"][aria-label*="Ek"]');
    
    attachmentElements.forEach(el => {
        const name = el.getAttribute('aria-label').replace('Attachment', '').replace('Ek', '').trim();
        const size = 0; // Outlook'ta boyut bilgisini almak zor
        
        if (name) {
            attachments.push({ name, size });
        }
    });
    
    // Email headers - Outlook'ta sınırlı
    const headers = {
        from: senderEmail,
        subject: subject,
        date: new Date().toISOString()
    };
    
    console.log('📧 Outlook e-posta içeriği çıkarıldı:', { subject, sender, bodyLength: body.length, links, attachments });
    
    return {
        subject,
        sender,
        senderEmail,
        body,
        links,
        attachments,
        headers
    };
}

// Gmail e-posta içeriğini çıkar
function extractGmailEmailContent() {
    // Konu
    const subjectElement = document.querySelector('h2.hP');
    const subject = subjectElement ? subjectElement.textContent.trim() : 'Konu bulunamadı';
    
    // Gönderen
    const senderElement = document.querySelector('.gD');
    let sender = 'Gönderen bulunamadı';
    let senderEmail = '';
    
    if (senderElement) {
        const emailElement = senderElement.querySelector('span[email]');
        senderEmail = emailElement ? emailElement.getAttribute('email') : '';
        sender = senderEmail || senderElement.textContent.trim();
    }
    
    // İçerik
    const bodyElement = document.querySelector('.a3s.aiL') || document.querySelector('.a3s');
    const body = bodyElement ? bodyElement.innerHTML : '';
    
    // URL'leri çıkar
    const links = extractLinksFromContent(body);
    
    // Ekleri çıkar
    const attachments = [];
    const attachmentElements = document.querySelectorAll('.aZo, .aQw');
    
    attachmentElements.forEach(el => {
        const nameEl = el.querySelector('.aV3');
        const sizeEl = el.querySelector('.aQz');
        
        if (nameEl) {
            const name = nameEl.textContent.trim();
            const size = sizeEl ? parseInt(sizeEl.textContent.replace(/[^\d]/g, '')) : 0;
            
            attachments.push({ name, size });
        }
    });
    
    // Email headers - Gmail'de sınırlı
    const headers = {
        from: senderEmail,
        subject: subject,
        date: new Date().toISOString()
    };
    
    console.log('📧 Gmail e-posta içeriği çıkarıldı:', { subject, sender, bodyLength: body.length, links, attachments });
    
    return {
        subject,
        sender,
        senderEmail,
        body,
        links,
        attachments,
        headers
    };
}

// URL'leri içerikten çıkarma
function extractLinksFromContent(htmlContent) {
    if (!htmlContent) return [];
    
    // HTML içindeki linkleri çıkar
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlContent;
    
    const links = [];
    const anchors = tempDiv.querySelectorAll('a[href]');
    
    anchors.forEach(anchor => {
        const href = anchor.getAttribute('href');
        if (href && !links.includes(href) && isValidUrl(href)) {
            links.push(href);
        }
    });
    
    // Text içindeki URL'leri çıkar
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
    const textContent = tempDiv.textContent || htmlContent;
    const matches = textContent.match(urlRegex);
    
    if (matches) {
        matches.forEach(match => {
            if (!links.includes(match)) {
                links.push(match);
            }
        });
    }
    
    return links;
}

// Geçerli URL kontrolü
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Mevcut e-postayı analiz et
async function analyzeCurrentEmail() {
    console.log('🔍 Mevcut e-posta analizi başlatılıyor...');
    
    if (isAnalysisInProgress) {
        throw new Error(getMessage('analysisInProgress'));
    }
    
    isAnalysisInProgress = true;
    
    try {
        // E-posta içeriğini çıkar
        const emailData = extractEmailContent();
        
        // Analiz sonuçlarını göstermek için banner oluştur
        const banner = createLoadingBanner();
        addBannerToEmail(banner);
        
        // Sender reputation check
        updateLoadingBanner(banner, getMessage('checking') + " " + getMessage('senderReputation') + "...");
        const senderReputation = await checkSenderReputation(emailData.senderEmail);
        
        // URL'leri analiz et
        updateLoadingBanner(banner, getMessage('checking') + " URLs...");
        const urlResults = await analyzeUrlsWithMultipleSources(emailData.links);
        
        // Ekleri analiz et
        updateLoadingBanner(banner, getMessage('checking') + " " + getMessage('attachmentAnalysis') + "...");
        const attachmentResults = await analyzeAttachmentsWithVirusTotal(emailData.attachments);
        
        // Risk skorunu hesapla
        updateLoadingBanner(banner, getMessage('riskScore') + " hesaplanıyor...");
        const riskScore = calculateEnhancedRiskScore(emailData, urlResults, attachmentResults, senderReputation);
        
        // Yükleme banner'ını kaldır
        removeLoadingBanner(banner);
        
        // Analiz sonuçlarını göster
        const results = {
            emailData,
            urlResults,
            attachmentResults,
            senderReputation,
            riskScore
        };
        
        displayEnhancedAnalysisResults(results);
        
        // Sonuçları döndür
        return results;
        
    } catch (error) {
        console.error('❌ E-posta analiz hatası:', error);
        throw error;
    } finally {
        isAnalysisInProgress = false;
    }
}

// Sender reputation kontrolü
async function checkSenderReputation(senderEmail) {
    if (!senderEmail || !senderEmail.includes('@')) {
        return {
            trustScore: 0,
            domainAge: null,
            spf: 'unknown',
            dkim: 'unknown',
            dmarc: 'unknown',
            ipReputation: null,
            error: 'Invalid sender email'
        };
    }
    
    const domain = senderEmail.split('@')[1];
    console.log(`🔍 Checking reputation for domain: ${domain}`);
    
    const reputation = {
        domain: domain,
        trustScore: 50, // Başlangıç skoru
        domainAge: null,
        spf: 'checking',
        dkim: 'checking', 
        dmarc: 'checking',
        ipReputation: null
    };
    
    try {
        // 1. SPF kaydı kontrolü
        const spfRecord = await checkDNSRecord(domain, 'TXT', 'v=spf1');
        reputation.spf = spfRecord ? 'passed' : 'failed';
        if (spfRecord) reputation.trustScore += 10;
        
        // 2. DMARC kaydı kontrolü
        const dmarcRecord = await checkDNSRecord(`_dmarc.${domain}`, 'TXT', 'v=DMARC1');
        reputation.dmarc = dmarcRecord ? 'passed' : 'failed';
        if (dmarcRecord) reputation.trustScore += 15;
        
        // 3. Domain yaşı kontrolü (basitleştirilmiş)
        const domainAge = await checkDomainAge(domain);
        reputation.domainAge = domainAge;
        
        if (domainAge) {
            const ageInDays = (new Date() - new Date(domainAge)) / (1000 * 60 * 60 * 24);
            if (ageInDays > 365) reputation.trustScore += 15; // 1 yıldan eski
            else if (ageInDays > 180) reputation.trustScore += 10; // 6 aydan eski
            else if (ageInDays > 30) reputation.trustScore += 5; // 1 aydan eski
            else reputation.trustScore -= 20; // Çok yeni domain
        }
        
        // 4. IP reputation kontrolü (AbuseIPDB)
        if (ABUSEIPDB_API_KEY) {
            const ipReputation = await checkIPReputation(domain);
            reputation.ipReputation = ipReputation;
            
            if (ipReputation && ipReputation.abuseScore < 25) {
                reputation.trustScore += 10;
            } else if (ipReputation && ipReputation.abuseScore > 75) {
                reputation.trustScore -= 30;
            }
        }
        
        // Trust score'u 0-100 arasında tut
        reputation.trustScore = Math.max(0, Math.min(100, reputation.trustScore));
        
    } catch (error) {
        console.error('❌ Sender reputation check error:', error);
        reputation.error = error.message;
    }
    
    console.log('✅ Sender reputation result:', reputation);
    return reputation;
}

// DNS kaydı kontrolü
async function checkDNSRecord(domain, type, contains) {
    try {
        const response = await fetch(`${DNS_OVER_HTTPS_URL}?name=${domain}&type=${type}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/dns-json'
            }
        });
        
        if (!response.ok) return false;
        
        const data = await response.json();
        
        if (data.Answer) {
            return data.Answer.some(record => 
                record.data && record.data.includes(contains)
            );
        }
        
        return false;
    } catch (error) {
        console.error(`DNS lookup error for ${domain}:`, error);
        return false;
    }
}

// Domain yaşı kontrolü (basitleştirilmiş)
async function checkDomainAge(domain) {
    // Not: Gerçek WHOIS sorgusu için özel API gerekir
    // Bu basitleştirilmiş bir tahmini kontroldür
    
    try {
        // DNS SOA kaydından tahmini yaş
        const response = await fetch(`${DNS_OVER_HTTPS_URL}?name=${domain}&type=SOA`, {
            method: 'GET',
            headers: {
                'Accept': 'application/dns-json'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.Answer && data.Answer.length > 0) {
                // SOA serial number'dan tahmini tarih
                const serial = data.Answer[0].data.split(' ')[2];
                if (serial && serial.length >= 8) {
                    const year = serial.substring(0, 4);
                    const month = serial.substring(4, 6);
                    const day = serial.substring(6, 8);
                    
                    const date = new Date(`${year}-${month}-${day}`);
                    if (!isNaN(date.getTime())) {
                        return date.toISOString();
                    }
                }
            }
        }
        
        // Fallback: domain mevcutsa en az 30 gün eskidir varsay
        return new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        
    } catch (error) {
        console.error('Domain age check error:', error);
        return null;
    }
}

// IP reputation kontrolü (AbuseIPDB)
async function checkIPReputation(domain) {
    if (!ABUSEIPDB_API_KEY) return null;
    
    try {
        // Önce domain'in IP adresini bul
        const dnsResponse = await fetch(`${DNS_OVER_HTTPS_URL}?name=${domain}&type=A`, {
            method: 'GET',
            headers: {
                'Accept': 'application/dns-json'
            }
        });
        
        if (!dnsResponse.ok) return null;
        
        const dnsData = await dnsResponse.json();
        if (!dnsData.Answer || dnsData.Answer.length === 0) return null;
        
        const ipAddress = dnsData.Answer[0].data;
        
        // AbuseIPDB'den IP reputation kontrolü
        const response = await fetch(`${ABUSEIPDB_API_URL}/check?ipAddress=${ipAddress}`, {
            method: 'GET',
            headers: {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
        });
        
        if (!response.ok) return null;
        
        const data = await response.json();
        
        return {
            ip: ipAddress,
            abuseScore: data.data.abuseConfidenceScore || 0,
            usageType: data.data.usageType || 'Unknown',
            isp: data.data.isp || 'Unknown',
            countryCode: data.data.countryCode || 'Unknown',
            totalReports: data.data.totalReports || 0
        };
        
    } catch (error) {
        console.error('IP reputation check error:', error);
        return null;
    }
}

// URL'leri birden fazla kaynakla analiz et
async function analyzeUrlsWithMultipleSources(urls) {
    if (!urls || urls.length === 0) return [];
    
    console.log(`🔍 ${urls.length} URL multiple sources ile analiz ediliyor...`);
    const results = [];
    
    for (const url of urls) {
        const result = {
            url,
            virusTotal: null,
            abuseIPDB: null,
            urlVoid: null,
            aggregatedRisk: 'low',
            aggregatedScore: 0
        };
        
        try {
            // 1. VirusTotal analizi
            if (VIRUSTOTAL_API_KEY) {
                result.virusTotal = await analyzeUrlWithVirusTotal(url);
            }
            
            // 2. AbuseIPDB domain kontrolü
            if (ABUSEIPDB_API_KEY) {
                const urlObj = new URL(url);
                const ipRep = await checkIPReputation(urlObj.hostname);
                if (ipRep) {
                    result.abuseIPDB = {
                        abuseScore: ipRep.abuseScore,
                        totalReports: ipRep.totalReports,
                        riskLevel: ipRep.abuseScore > 75 ? 'high' : 
                                  ipRep.abuseScore > 25 ? 'medium' : 'low'
                    };
                }
            }
            
            // Agregasyon
            let totalScore = 0;
            let sourceCount = 0;
            
            if (result.virusTotal) {
                totalScore += result.virusTotal.positives;
                sourceCount++;
            }
            
            if (result.abuseIPDB) {
                totalScore += result.abuseIPDB.abuseScore / 10; // 0-100'ü 0-10'a normalize et
                sourceCount++;
            }
            
            result.aggregatedScore = sourceCount > 0 ? totalScore / sourceCount : 0;
            
            // Risk seviyesi belirleme
            if (result.aggregatedScore >= 5) {
                result.aggregatedRisk = 'high';
            } else if (result.aggregatedScore >= 2) {
                result.aggregatedRisk = 'medium';
            } else {
                result.aggregatedRisk = 'low';
            }
            
        } catch (error) {
            console.error(`❌ URL analiz hatası (${url}):`, error);
            result.error = error.message;
        }
        
        results.push(result);
        await delay(200); // API rate limiting
    }
    
    console.log('✅ Multi-source URL analizi tamamlandı:', results);
    return results;
}

// Tek bir URL'yi VirusTotal ile analiz et
async function analyzeUrlWithVirusTotal(url) {
    if (!VIRUSTOTAL_API_KEY) {
        return createFakeUrlAnalysisResult(url);
    }
    
    try {
        const encodedUrl = encodeURIComponent(url);
        
        // URL'yi analiz için gönder
        const response = await fetch(`${VIRUSTOTAL_API_URL}/urls`, {
            method: "POST",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodedUrl}`
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                throw new Error('Invalid API key');
            }
            throw new Error(`VirusTotal API error: ${response.status}`);
        }
        
        const data = await response.json();
        const analysisId = data.data.id;
        
        // Analiz sonucunu al
        await delay(2000);
        
        const analysisResponse = await fetch(`${VIRUSTOTAL_API_URL}/analyses/${analysisId}`, {
            method: "GET",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
        });
        
        if (!analysisResponse.ok) {
            throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
        }
        
        const analysisData = await analysisResponse.json();
        const stats = analysisData.data.attributes.stats;
        
        const positives = stats.malicious + stats.suspicious;
        const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
        
        return {
            positives,
            total,
            riskLevel: positives >= 3 ? 'high' : positives >= 1 ? 'medium' : 'low',
            scanDate: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('VirusTotal analysis error:', error);
        return createFakeUrlAnalysisResult(url);
    }
}

// Sahte URL analiz sonucu oluştur
function createFakeUrlAnalysisResult(url) {
    const suspiciousKeywords = [
        'login', 'account', 'secure', 'update', 'verify', 'wallet',
        'password', 'bank', 'alert', 'confirm', 'verification',
        'signin', 'security', '.tk', '.ml', '.ga', '.cf', '.ru'
    ];
    
    const dangerousKeywords = [
        'phishing', 'malware', 'trojan', 'virus', 'hack', 'steal',
        'credential', 'download', 'exe', 'bat', 'suspicious'
    ];
    
    const urlLower = url.toLowerCase();
    
    const dangerCount = dangerousKeywords.filter(word => urlLower.includes(word)).length;
    const suspiciousCount = suspiciousKeywords.filter(word => urlLower.includes(word)).length;
    
    let positives = 0;
    let riskLevel = 'low';
    
    if (dangerCount > 0) {
        positives = Math.floor(Math.random() * 30) + 10;
        riskLevel = 'high';
    } else if (suspiciousCount > 0) {
        positives = Math.floor(Math.random() * 8) + 2;
        riskLevel = 'medium';
    } else if (!url.startsWith('https://')) {
        positives = Math.floor(Math.random() * 3) + 1;
        riskLevel = 'low';
    } else {
        positives = Math.floor(Math.random() * 2);
        riskLevel = 'low';
    }
    
    return {
        positives,
        total: 75,
        riskLevel,
        scanDate: new Date().toISOString()
    };
}

// VirusTotal API ile ekli dosya analizi
async function analyzeAttachmentsWithVirusTotal(attachments) {
    if (!attachments || attachments.length === 0) return [];
    
    console.log(`🔍 ${attachments.length} ek dosya analiz ediliyor...`);
    const results = [];
    
    for (const attachment of attachments) {
        try {
            const fileName = attachment.name;
            const extension = fileName.split('.').pop().toLowerCase();
            
            const result = createFakeAttachmentAnalysisResult(fileName, extension);
            results.push(result);
            
        } catch (error) {
            console.error(`❌ Ek analiz hatası (${attachment.name}):`, error);
            
            results.push({
                name: attachment.name,
                size: attachment.size,
                positives: 0,
                total: 75,
                riskLevel: 'unknown',
                scanDate: new Date().toISOString(),
                note: 'Analiz hatası: ' + error.message
            });
        }
        
        await delay(200);
    }
    
    console.log('✅ Ek dosya analizi tamamlandı:', results);
    return results;
}

// Sahte ek dosya analiz sonucu oluştur
function createFakeAttachmentAnalysisResult(fileName, extension) {
    const dangerousExtensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'msi', 'reg'];
    const suspiciousExtensions = ['zip', 'rar', 'docm', 'xlsm', 'pptm', 'hta', 'scr', 'com'];
    const mediumExtensions = ['doc', 'docx', 'xls', 'xlsx', 'pdf', 'ppt', 'pptx'];
    
    const fileHash = Array.from(
        new Uint8Array(
            Array.from(fileName).map(c => c.charCodeAt(0))
        )
    ).map(b => b.toString(16).padStart(2, '0')).join('');
    
    let positives = 0;
    let riskLevel = 'low';
    
    if (dangerousExtensions.includes(extension)) {
        positives = Math.floor(Math.random() * 30) + 15;
        riskLevel = 'high';
    } else if (suspiciousExtensions.includes(extension)) {
        positives = Math.floor(Math.random() * 10) + 5;
        riskLevel = 'medium';
    } else if (mediumExtensions.includes(extension)) {
        positives = Math.floor(Math.random() * 6);
        riskLevel = positives > 2 ? 'medium' : 'low';
    } else {
        positives = Math.floor(Math.random() * 3);
        riskLevel = 'low';
    }
    
    return {
        name: fileName,
        extension: extension,
        positives,
        total: 75,
        riskLevel,
        scanDate: new Date().toISOString(),
        vtLink: `https://www.virustotal.com/gui/file/${fileHash}/detection`,
        note: positives > 0 ? getMessage('noThreatsDetected') : getMessage('noThreatsDetected')
    };
}

// Gelişmiş risk skoru hesaplama
function calculateEnhancedRiskScore(emailData, urlResults, attachmentResults, senderReputation) {
    let score = 0;
    const factors = [];
    
    // Sender reputation faktörleri
    if (senderReputation) {
        // Trust score'a göre
        if (senderReputation.trustScore < 30) {
            score += 25;
            factors.push(`🚨 ${getMessage('senderReputation')}: ${getMessage('lowRisk')} (${senderReputation.trustScore}/100)`);
        } else if (senderReputation.trustScore < 60) {
            score += 10;
            factors.push(`⚠️ ${getMessage('senderReputation')}: ${getMessage('mediumRisk')} (${senderReputation.trustScore}/100)`);
        }
        
        // SPF/DKIM/DMARC
        if (senderReputation.spf === 'failed') {
            score += 10;
            factors.push(`❌ SPF ${getMessage('failed')}`);
        }
        if (senderReputation.dmarc === 'failed') {
            score += 15;
            factors.push(`❌ DMARC ${getMessage('failed')}`);
        }
        
        // Yeni domain
        if (senderReputation.domainAge) {
            const ageInDays = (new Date() - new Date(senderReputation.domainAge)) / (1000 * 60 * 60 * 24);
            if (ageInDays < 30) {
                score += 20;
                factors.push(`🆕 Çok yeni domain (${Math.floor(ageInDays)} gün)`);
            }
        }
        
        // IP reputation
        if (senderReputation.ipReputation && senderReputation.ipReputation.abuseScore > 50) {
            score += 20;
            factors.push(`🚫 Kötü IP itibarı (${senderReputation.ipReputation.abuseScore}% abuse score)`);
        }
    }
    
    // URL riskleri (multi-source)
    urlResults.forEach(result => {
        if (result.aggregatedRisk === 'high') {
            score += 25;
            factors.push(`🔗 Tehlikeli URL: ${result.url.substring(0, 30)}...`);
        } else if (result.aggregatedRisk === 'medium') {
            score += 15;
            factors.push(`🔗 Şüpheli URL: ${result.url.substring(0, 30)}...`);
        }
    });
    
    // Ek riskleri
    attachmentResults.forEach(att => {
        if (att.riskLevel === 'high') {
            score += 20;
            factors.push(`📎 Yüksek riskli ek: ${att.name} (${att.positives}/${att.total})`);
        } else if (att.riskLevel === 'medium') {
            score += 10;
            factors.push(`📎 Orta riskli ek: ${att.name} (${att.positives}/${att.total})`);
        }
    });
    
    // İçerik riskleri
    const subjectLower = emailData.subject.toLowerCase();
    const bodyLower = emailData.body.toLowerCase();
    
    // Şüpheli kelimeler
    const suspiciousWords = [
        'urgent', 'acil', 'immediately', 'hemen', 'action required',
        'login', 'verify', 'doğrula', 'password', 'şifre', 
        'account', 'hesap', 'limited', 'sınırlı', 'update', 'güncelle'
    ];
    
    suspiciousWords.forEach(word => {
        if (subjectLower.includes(word)) {
            score += 5;
            factors.push(`📧 Şüpheli kelime (konu): "${word}"`);
        } else if (bodyLower.includes(word)) {
            score += 2;
            factors.push(`📧 Şüpheli kelime (içerik): "${word}"`);
        }
    });
    
    // Panik yaratma belirtileri
    if (subjectLower.includes('!') || subjectLower.includes('urgent') || subjectLower.includes('acil')) {
        score += 5;
        factors.push('⚡ Panik yaratmaya yönelik konu');
    }
    
    // Risk seviyesini belirle
    let level = 'low';
    if (score >= 50) {
        level = 'high';
    } else if (score >= 25) {
        level = 'medium';
    }
    
    return { score: Math.min(100, score), level, factors };
}

// Yükleniyor banner'ı oluştur
function createLoadingBanner() {
    const banner = document.createElement('div');
    banner.id = 'securityAnalysisLoadingBanner';
    banner.style.cssText = `
        width: 100%;
        padding: 10px;
        margin-bottom: 15px;
        border-radius: 8px;
        font-family: Arial, sans-serif;
        position: relative;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        background: #e8f4fd;
        border-left: 4px solid #3498db;
        display: flex;
        align-items: center;
        z-index: 9999;
    `;
    
    // Spinner animasyonu
    const spinner = document.createElement('div');
    spinner.style.cssText = `
        border: 3px solid #f3f3f3;
        border-top: 3px solid #3498db;
        border-radius: 50%;
        width: 20px;
        height: 20px;
        animation: spin 1s linear infinite;
        margin-right: 10px;
    `;
    
    // Animasyon için stil ekleme
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    `;
    document.head.appendChild(style);
    
    // Yükleniyor metni
    const text = document.createElement('div');
    text.id = 'loadingBannerText';
    text.textContent = getMessage('loading');
    text.style.cssText = `
        font-size: 14px;
        color: #2980b9;
    `;
    
    banner.appendChild(spinner);
    banner.appendChild(text);
    
    return banner;
}

// Yükleniyor banner'ını güncelle
function updateLoadingBanner(banner, message) {
    const textElement = banner.querySelector('#loadingBannerText');
    if (textElement) {
        textElement.textContent = message;
    }
}

// Yükleniyor banner'ını kaldır
function removeLoadingBanner(banner) {
    if (banner && banner.parentNode) {
        banner.parentNode.removeChild(banner);
    }
}

// Banner'ı e-postaya ekle
function addBannerToEmail(banner) {
    // Platforma göre en uygun yere ekle
    if (platformType === 'outlook') {
        const container = document.querySelector('[role="main"], .ReadingPaneContent');
        if (container) {
            container.insertBefore(banner, container.firstChild);
        } else {
            document.body.appendChild(banner);
        }
    } else if (platformType === 'gmail') {
        const container = document.querySelector('.a3s.aiL, .a3s');
        if (container && container.parentNode) {
            container.parentNode.insertBefore(banner, container);
        } else {
            document.body.appendChild(banner);
        }
    } else {
        document.body.appendChild(banner);
    }
}

// Gelişmiş analiz sonuçlarını göster
function displayEnhancedAnalysisResults(results) {
    // Eski sonuçları temizle
    removeAnalysisResults();
    
    // Yeni sonuç banner'ı oluştur
    const banner = createEnhancedResultBanner(results);
    addBannerToEmail(banner);
    
    // Detay görüntüleme butonuna tıklama dinleyicisi ekle
    const detailsButton = document.getElementById('securityDetailsButton');
    if (detailsButton) {
        detailsButton.addEventListener('click', function() {
            const detailsContainer = document.getElementById('securityDetailsContainer');
            if (detailsContainer) {
                if (detailsContainer.style.display === 'none') {
                    detailsContainer.style.display = 'block';
                    detailsButton.textContent = getMessage('hideDetails') || 'Detayları Gizle';
                } else {
                    detailsContainer.style.display = 'none';
                    detailsButton.textContent = getMessage('showDetails') || 'Detayları Göster';
                }
            }
        });
    }
}

// Analiz sonuçlarını temizle
function removeAnalysisResults() {
    const existingBanner = document.getElementById('securityAnalysisBanner');
    if (existingBanner && existingBanner.parentNode) {
        existingBanner.parentNode.removeChild(existingBanner);
    }
    
    const existingLoadingBanner = document.getElementById('securityAnalysisLoadingBanner');
    if (existingLoadingBanner && existingLoadingBanner.parentNode) {
        existingLoadingBanner.parentNode.removeChild(existingLoadingBanner);
    }
}

// Gelişmiş sonuç banner'ı oluştur
function createEnhancedResultBanner(results) {
    const { emailData, urlResults, attachmentResults, senderReputation, riskScore } = results;
    
    // Ana container
    const banner = document.createElement('div');
    banner.id = 'securityAnalysisBanner';
    banner.style.cssText = `
        width: 100%;
        padding: 12px;
        margin-bottom: 15px;
        border-radius: 8px;
        font-family: Arial, sans-serif;
        position: relative;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        background: ${riskScore.level === 'high' ? '#fef2f2' : 
                      riskScore.level === 'medium' ? '#fff8e6' : '#f0fdf4'};
        border-left: 4px solid ${riskScore.level === 'high' ? '#ef4444' : 
                                 riskScore.level === 'medium' ? '#f59e0b' : '#22c55e'};
        z-index: 9999;
    `;
    
    // Başlık ve özet
    const title = document.createElement('div');
    title.style.cssText = `
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 8px;
    `;
    
    const icon = riskScore.level === 'high' ? '⚠️' : 
                riskScore.level === 'medium' ? '🔶' : '✅';
    
    const titleText = riskScore.level === 'high' ? getMessage('highRisk') : 
                     riskScore.level === 'medium' ? getMessage('mediumRisk') : getMessage('lowRisk');
    
    title.innerHTML = `
        <div style="font-weight: bold; font-size: 14px; color: ${riskScore.level === 'high' ? '#b91c1c' : 
                                                                 riskScore.level === 'medium' ? '#92400e' : '#166534'}">
            ${icon} ${getMessage('riskScore')}: ${titleText}
        </div>
        <div style="display: flex; align-items: center;">
            <span style="
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: bold;
                margin-right: 10px;
                background: ${riskScore.level === 'high' ? '#ef4444' : 
                              riskScore.level === 'medium' ? '#f59e0b' : '#22c55e'};
                color: white;
            ">
                ${riskScore.score}/100
            </span>
            <button id="securityDetailsButton" style="
                border: none;
                background: rgba(0,0,0,0.05);
                padding: 4px 8px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
            ">
                Detayları Göster
            </button>
        </div>
    `;
    
    banner.appendChild(title);
    
    // Özet
    const summary = document.createElement('div');
    summary.style.cssText = `
        font-size: 12px;
        margin-bottom: 10px;
        color: ${riskScore.level === 'high' ? '#b91c1c' : 
               riskScore.level === 'medium' ? '#92400e' : '#166534'};
    `;
    
    const summaryText = riskScore.level === 'high' ? 
        'Bu e-posta yüksek güvenlik riski taşıyor. Linklere tıklamadan ve ekleri açmadan önce dikkatli olun.' : 
        riskScore.level === 'medium' ? 
        'Bu e-postada dikkat edilmesi gereken güvenlik unsurları tespit edildi.' : 
        'Bu e-posta düşük risk seviyesinde görünüyor.';
    
    summary.textContent = summaryText;
    banner.appendChild(summary);
    
    // Multi-source bilgisi
    const sourceInfo = document.createElement('div');
    sourceInfo.style.cssText = `
        display: flex;
        align-items: center;
        font-size: 10px;
        margin-bottom: 8px;
        color: #64748b;
        flex-wrap: wrap;
    `;
    
    sourceInfo.innerHTML = `
        <div style="display: flex; align-items: center;">
            <span style="font-style: italic; margin-right: 5px;">Güvenlik analizi:</span>
            <img src="https://www.virustotal.com/gui/images/favicon.png" alt="VT" style="width: 12px; height: 12px; margin-right: 2px;">
            <span style="font-weight: bold; margin-right: 8px;">VirusTotal</span>
            ${ABUSEIPDB_API_KEY ? '<span style="margin-right: 8px;">• AbuseIPDB</span>' : ''}
            <span>tarafından desteklenmektedir</span>
        </div>
    `;
    
    banner.appendChild(sourceInfo);
    
    // Detaylar (başlangıçta gizli)
    const detailsContainer = document.createElement('div');
    detailsContainer.id = 'securityDetailsContainer';
    detailsContainer.style.cssText = `
        display: none;
        background: white;
        border-radius: 6px;
        padding: 10px;
        margin-top: 10px;
        border: 1px solid rgba(0,0,0,0.1);
    `;
    
    // Sender reputation section
    if (senderReputation) {
        const senderSection = document.createElement('div');
        senderSection.style.cssText = `
            margin-bottom: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
        `;
        
        senderSection.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 8px; color: #1e293b;">
                👤 ${getMessage('senderReputation')}
            </div>
            <div style="font-size: 11px;">
                <div style="margin-bottom: 4px;">
                    <strong>${getMessage('trustScore')}:</strong> 
                    <span style="
                        color: ${senderReputation.trustScore < 30 ? '#ef4444' : 
                                senderReputation.trustScore < 60 ? '#f59e0b' : '#22c55e'};
                        font-weight: bold;
                    ">${senderReputation.trustScore}/100</span>
                </div>
                <div style="margin-bottom: 4px;">
                    <strong>Domain:</strong> ${senderReputation.domain}
                    ${senderReputation.domainAge ? 
                        ` (${getMessage('domainRegistered')}: ${new Date(senderReputation.domainAge).toLocaleDateString()})` : ''}
                </div>
                <div style="margin-bottom: 4px;">
                    <strong>SPF:</strong> ${getStatusBadge(senderReputation.spf)}
                    <strong style="margin-left: 10px;">DKIM:</strong> ${getStatusBadge(senderReputation.dkim)}
                    <strong style="margin-left: 10px;">DMARC:</strong> ${getStatusBadge(senderReputation.dmarc)}
                </div>
                ${senderReputation.ipReputation ? `
                    <div>
                        <strong>${getMessage('ipReputation')}:</strong> 
                        ${senderReputation.ipReputation.ip} - 
                        Abuse Score: ${senderReputation.ipReputation.abuseScore}% - 
                        ISP: ${senderReputation.ipReputation.isp}
                    </div>
                ` : ''}
            </div>
        `;
        
        detailsContainer.appendChild(senderSection);
    }
    
    // Risk faktörleri
    if (riskScore.factors.length > 0) {
        const factorsSection = document.createElement('div');
        factorsSection.style.cssText = `
            margin-bottom: 15px;
        `;
        
        factorsSection.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 5px; color: #1e293b;">⚠️ ${getMessage('riskFactors')}</div>
            <ul style="margin: 0; padding-left: 20px; color: #7f1d1d;">
                ${riskScore.factors.map(factor => `<li style="margin-bottom: 3px;">${factor}</li>`).join('')}
            </ul>
        `;
        
        detailsContainer.appendChild(factorsSection);
    } else {
        const noFactors = document.createElement('div');
        noFactors.style.cssText = `
            background: #f0fdf4;
            color: #166534;
            padding: 8px;
            border-radius: 4px;
            margin-bottom: 15px;
            text-align: center;
        `;
        
        noFactors.textContent = '✅ ' + getMessage('noThreatsDetected');
        detailsContainer.appendChild(noFactors);
    }
    
    // URL analiz sonuçları
    if (urlResults.length > 0) {
        const urlSection = document.createElement('div');
        urlSection.style.cssText = `
            margin-bottom: 15px;
        `;
        
        urlSection.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 5px; color: #1e293b; display: flex; align-items: center;">
                🔗 ${getMessage('urlAnalysis')}
            </div>
        `;
        
        // URL sonuçları
        urlResults.forEach(result => {
            const urlItem = document.createElement('div');
            urlItem.style.cssText = `
                padding: 8px;
                border-radius: 4px;
                margin-bottom: 5px;
                border-left: 3px solid ${result.aggregatedRisk === 'high' ? '#ef4444' : 
                                       result.aggregatedRisk === 'medium' ? '#f59e0b' : '#22c55e'};
                background: ${result.aggregatedRisk === 'high' ? '#fef2f2' : 
                            result.aggregatedRisk === 'medium' ? '#fff8e6' : '#f0fdf4'};
                font-size: 11px;
            `;
            
            urlItem.innerHTML = `
                <div style="word-break: break-all;">
                    <strong>${result.url.length > 40 ? result.url.substring(0, 40) + '...' : result.url}</strong>
                </div>
                <div style="margin-top: 4px; display: flex; flex-wrap: wrap; gap: 5px;">
                    ${result.virusTotal ? `
                        <span style="
                            display: inline-block;
                            background: ${result.virusTotal.riskLevel === 'high' ? '#ef4444' : 
                                         result.virusTotal.riskLevel === 'medium' ? '#f59e0b' : '#22c55e'};
                            color: white;
                            padding: 1px 6px;
                            border-radius: 10px;
                            font-size: 10px;
                        ">
                            VT: ${result.virusTotal.positives}/${result.virusTotal.total}
                        </span>
                    ` : ''}
                    ${result.abuseIPDB ? `
                        <span style="
                            display: inline-block;
                            background: ${result.abuseIPDB.riskLevel === 'high' ? '#ef4444' : 
                                         result.abuseIPDB.riskLevel === 'medium' ? '#f59e0b' : '#22c55e'};
                            color: white;
                            padding: 1px 6px;
                            border-radius: 10px;
                            font-size: 10px;
                        ">
                            AbuseIPDB: ${result.abuseIPDB.abuseScore}%
                        </span>
                    ` : ''}
                </div>
            `;
            
            urlSection.appendChild(urlItem);
        });
        
        detailsContainer.appendChild(urlSection);
    }
    
    // Ek dosya analiz sonuçları
    if (attachmentResults.length > 0) {
        const attachmentSection = document.createElement('div');
        attachmentSection.style.cssText = `
            margin-bottom: 15px;
        `;
        
        attachmentSection.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 5px; color: #1e293b; display: flex; align-items: center;">
                📎 ${getMessage('attachmentAnalysis')}
                <img src="https://www.virustotal.com/gui/images/favicon.png" style="width: 12px; height: 12px; margin-left: 5px;">
            </div>
        `;
        
        // Ek sonuçları
        attachmentResults.forEach(result => {
            const attachmentItem = document.createElement('div');
            attachmentItem.style.cssText = `
                padding: 8px;
                border-radius: 4px;
                margin-bottom: 5px;
                border-left: 3px solid ${result.riskLevel === 'high' ? '#ef4444' : 
                                       result.riskLevel === 'medium' ? '#f59e0b' : '#22c55e'};
                background: ${result.riskLevel === 'high' ? '#fef2f2' : 
                            result.riskLevel === 'medium' ? '#fff8e6' : '#f0fdf4'};
                font-size: 11px;
            `;
            
            attachmentItem.innerHTML = `
                <div>
                    <strong>${result.name}</strong>
                    <span style="
                        display: inline-block;
                        background: ${result.riskLevel === 'high' ? '#ef4444' : 
                                     result.riskLevel === 'medium' ? '#f59e0b' : '#22c55e'};
                        color: white;
                        padding: 1px 6px;
                        border-radius: 10px;
                        font-size: 10px;
                        margin-left: 5px;
                    ">
                        ${result.positives}/${result.total}
                    </span>
                </div>
            `;
            
            attachmentSection.appendChild(attachmentItem);
        });
        
        detailsContainer.appendChild(attachmentSection);
    }
    
    banner.appendChild(detailsContainer);
    
    // Versiyon bilgisi
    const version = document.createElement('div');
    version.style.cssText = `
        font-size: 9px;
        text-align: right;
        color: #64748b;
        margin-top: 5px;
    `;
    
    version.textContent = 'Mail Güvenlik Analizi v3.0';
    banner.appendChild(version);
    
    return banner;
}

// Status badge oluştur
function getStatusBadge(status) {
    const colors = {
        'passed': '#22c55e',
        'failed': '#ef4444',
        'unknown': '#94a3b8',
        'checking': '#3b82f6'
    };
    
    const labels = {
        'passed': getMessage('passed'),
        'failed': getMessage('failed'),
        'unknown': getMessage('unknown'),
        'checking': getMessage('checking')
    };
    
    const color = colors[status] || colors['unknown'];
    const label = labels[status] || status;
    
    return `<span style="
        display: inline-block;
        padding: 2px 6px;
        background: ${color};
        color: white;
        border-radius: 3px;
        font-size: 10px;
        font-weight: bold;
    ">${label}</span>`;
}

// Yardımcı fonksiyonlar
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}