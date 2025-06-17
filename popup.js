console.log('🚀 Mail Security Extension popup loading v3.0');

// Global variables
let currentTab = null;
let contentScriptReady = false;

// i18n helper
function updateI18n() {
    document.querySelectorAll('[data-i18n]').forEach(elem => {
        const key = elem.getAttribute('data-i18n');
        const message = chrome.i18n.getMessage(key);
        if (message) {
            elem.textContent = message;
        }
    });
}

// Wait for DOM to load
document.addEventListener('DOMContentLoaded', function() {
    console.log('✅ DOM loaded, initializing...');
    
    // Update i18n
    updateI18n();
    
    // Load saved language preference
    loadLanguagePreference();
    
    // Get elements
    const analyzeBtn = document.getElementById('analyzeBtn');
    const demoBtn = document.getElementById('demoBtn');
    const status = document.getElementById('status');
    const analyzeTab = document.getElementById('analyzeTab');
    const settingsTab = document.getElementById('settingsTab');
    const analyzeContent = document.getElementById('analyzeContent');
    const settingsContent = document.getElementById('settingsContent');
    const saveSettingsBtn = document.getElementById('saveSettings');
    const languageSelector = document.getElementById('languageSelector');
    
    // Check content script status
    checkContentScriptStatus();
    
    // Load API keys
    loadApiKeys();
    
    // Tab switching
    analyzeTab.addEventListener('click', function() {
        analyzeTab.classList.add('active');
        settingsTab.classList.remove('active');
        analyzeContent.classList.add('active');
        settingsContent.classList.remove('active');
    });
    
    settingsTab.addEventListener('click', function() {
        settingsTab.classList.add('active');
        analyzeTab.classList.remove('active');
        settingsContent.classList.add('active');
        analyzeContent.classList.remove('active');
    });
    
    // Add event listeners
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', function() {
            console.log('🔍 Analyze button clicked!');
            analyzeCurrentEmail();
        });
    }
    
    if (demoBtn) {
        demoBtn.addEventListener('click', function() {
            console.log('🧪 Demo button clicked!');
            runDemoAnalysis();
        });
    }
    
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', function() {
            console.log('💾 Save settings clicked!');
            saveApiKeys();
        });
    }
    
    if (languageSelector) {
        languageSelector.addEventListener('change', function() {
            const selectedLang = languageSelector.value;
            saveLanguagePreference(selectedLang);
            // Reload extension to apply language change
            chrome.runtime.reload();
        });
    }
});

// Load language preference
async function loadLanguagePreference() {
    try {
        const result = await chrome.storage.local.get(['language']);
        const languageSelector = document.getElementById('languageSelector');
        
        if (result.language && languageSelector) {
            languageSelector.value = result.language;
        } else {
            // Default to browser language
            const browserLang = chrome.i18n.getUILanguage().split('-')[0];
            if (languageSelector && ['en', 'tr', 'es', 'de'].includes(browserLang)) {
                languageSelector.value = browserLang;
            }
        }
    } catch (error) {
        console.error('Error loading language preference:', error);
    }
}

// Save language preference
async function saveLanguagePreference(language) {
    try {
        await chrome.storage.local.set({ language: language });
        console.log('Language preference saved:', language);
    } catch (error) {
        console.error('Error saving language preference:', error);
    }
}

// Load API keys from storage
async function loadApiKeys() {
    try {
        const result = await chrome.storage.local.get(['virusTotalApiKey', 'abuseIPDBApiKey']);
        
        const vtInput = document.getElementById('virusTotalApiKey');
        const abuseInput = document.getElementById('abuseIPDBApiKey');
        
        if (result.virusTotalApiKey && vtInput) {
            vtInput.value = maskApiKey(result.virusTotalApiKey);
            vtInput.placeholder = chrome.i18n.getMessage('apiKeySet') || 'API key set';
        }
        
        if (result.abuseIPDBApiKey && abuseInput) {
            abuseInput.value = maskApiKey(result.abuseIPDBApiKey);
            abuseInput.placeholder = chrome.i18n.getMessage('apiKeySet') || 'API key set';
        }
    } catch (error) {
        console.error('Error loading API keys:', error);
    }
}

// Save API keys
async function saveApiKeys() {
    const vtInput = document.getElementById('virusTotalApiKey');
    const abuseInput = document.getElementById('abuseIPDBApiKey');
    const statusDiv = document.getElementById('settingsStatus');
    
    try {
        const keysToSave = {};
        
        // Check if VirusTotal key is new (not masked)
        if (vtInput && vtInput.value && !vtInput.value.includes('*')) {
            keysToSave.virusTotalApiKey = vtInput.value.trim();
        }
        
        // Check if AbuseIPDB key is new (not masked)
        if (abuseInput && abuseInput.value && !abuseInput.value.includes('*')) {
            keysToSave.abuseIPDBApiKey = abuseInput.value.trim();
        }
        
        // Save only if there are new keys
        if (Object.keys(keysToSave).length > 0) {
            await chrome.storage.local.set(keysToSave);
            
            // Reload masked keys
            await loadApiKeys();
            
            // Notify content script
            notifyContentScript();
            
            showStatus(statusDiv, chrome.i18n.getMessage('settingsSaved') || 'Settings saved successfully!', 'success');
        } else {
            showStatus(statusDiv, chrome.i18n.getMessage('noChanges') || 'No changes to save', 'info');
        }
        
    } catch (error) {
        console.error('Error saving API keys:', error);
        showStatus(statusDiv, chrome.i18n.getMessage('errorSavingSettings') || 'Error saving settings: ' + error.message, 'error');
    }
}

// Check if content script is active
async function checkContentScriptStatus() {
    const status = document.getElementById('status');
    if (!status) return;
    
    try {
        status.innerHTML = '⏳ ' + (chrome.i18n.getMessage('checkingContentScript') || 'Checking content script...');
        
        // First try direct messaging to content script
        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tabs || !tabs.length) throw new Error('No active tab found');
            
            currentTab = tabs[0];
            
            const isMailSite = checkIfMailSite(currentTab.url);
            if (!isMailSite) {
                status.innerHTML = '⚠️ ' + (chrome.i18n.getMessage('notOnMailSite') || 'Not on Outlook or Gmail page');
                status.style.background = '#fff3cd';
                status.style.borderLeft = '4px solid #f59e0b';
                return;
            }
            
            const response = await chrome.tabs.sendMessage(currentTab.id, { action: 'ping' });
            console.log('Direct ping response:', response);
            
            if (response && response.success) {
                contentScriptReady = true;
                status.innerHTML = `✅ ${chrome.i18n.getMessage('ready') || 'Ready'} - ${response.platform}`;
                status.style.background = '#d5f4e6';
                status.style.borderLeft = '4px solid #27ae60';
                
                // Enable analyze button
                const analyzeBtn = document.getElementById('analyzeBtn');
                if (analyzeBtn) {
                    analyzeBtn.disabled = false;
                }
            }
        } catch (directErr) {
            console.error('Direct content script check error:', directErr);
            
            status.innerHTML = `⚠️ ${chrome.i18n.getMessage('contentScriptNotResponding') || 'Content script not responding'} <button id="injectBtn" style="background: #007bff; color: white; border: none; padding: 3px 8px; border-radius: 4px; margin-left: 10px; cursor: pointer;">${chrome.i18n.getMessage('load') || 'Load'}</button>`;
            status.style.background = '#fff3cd';
            status.style.borderLeft = '4px solid #f59e0b';
            
            // Add event listener to inject button
            const injectBtn = document.getElementById('injectBtn');
            if (injectBtn) {
                injectBtn.addEventListener('click', injectContentScript);
            }
            
            // Disable analyze button
            const analyzeBtn = document.getElementById('analyzeBtn');
            if (analyzeBtn) {
                analyzeBtn.disabled = true;
            }
        }
    } catch (error) {
        console.error('Error checking content script status:', error);
        
        status.innerHTML = '❌ ' + (chrome.i18n.getMessage('error') || 'Error') + ': ' + error.message;
        status.style.background = '#f8d7da';
        status.style.borderLeft = '4px solid #dc3545';
    }
}

// Check if URL is a mail site
function checkIfMailSite(url) {
    if (!url) return false;
    
    const mailDomains = [
        'outlook.office.com',
        'outlook.live.com',
        'outlook.office365.com',
        'mail.google.com'
    ];
    
    return mailDomains.some(domain => url.includes(domain));
}

// Inject content script manually
async function injectContentScript() {
    const status = document.getElementById('status');
    if (!status) return;
    
    try {
        status.innerHTML = '⏳ ' + (chrome.i18n.getMessage('loadingContentScript') || 'Loading content script...');
        
        const result = await chrome.runtime.sendMessage({ action: 'injectContentScript' });
        console.log('Inject content script result:', result);
        
        if (result && result.success) {
            status.innerHTML = '✅ ' + (chrome.i18n.getMessage('contentScriptLoaded') || 'Content script loaded!');
            status.style.background = '#d5f4e6';
            status.style.borderLeft = '4px solid #27ae60';
            
            // Check status again after a short delay
            setTimeout(checkContentScriptStatus, 1000);
        } else {
            throw new Error(result?.error || 'Unknown error');
        }
    } catch (error) {
        console.error('Error injecting content script:', error);
        
        status.innerHTML = '❌ ' + (chrome.i18n.getMessage('errorLoadingContentScript') || 'Error loading content script') + ': ' + error.message;
        status.style.background = '#f8d7da';
        status.style.borderLeft = '4px solid #dc3545';
    }
}

// Analyze current email
async function analyzeCurrentEmail() {
    if (!contentScriptReady || !currentTab) {
        showError(chrome.i18n.getMessage('contentScriptNotReady') || 'Content script not ready or tab info missing');
        return;
    }
    
    // Check if API keys are configured
    const hasApiKeys = await checkApiKeys();
    if (!hasApiKeys) {
        // Switch to settings tab
        document.getElementById('settingsTab').click();
        showStatus(
            document.getElementById('settingsStatus'), 
            chrome.i18n.getMessage('apiKeyRequired') || 'Please configure your API keys first',
            'error'
        );
        return;
    }
    
    try {
        showLoading(true);
        updateLoadingText(chrome.i18n.getMessage('analyzingEmail') || 'Analyzing email...');
        
        const response = await chrome.tabs.sendMessage(currentTab.id, { 
            action: 'analyzeEmail'
        });
        
        console.log('Email analysis response:', response);
        
        if (response && response.success) {
            updateLoadingText(chrome.i18n.getMessage('analysisComplete') || 'Analysis complete');
            
            // Display results
            displayResults(response.result);
            
            // Hide loading after 2 seconds
            setTimeout(() => {
                showLoading(false);
                
                // Update status message
                const status = document.getElementById('status');
                if (status) {
                    const riskLevel = response.result.riskScore.level;
                    const riskText = riskLevel === 'high' ? chrome.i18n.getMessage('highRisk') : 
                                   riskLevel === 'medium' ? chrome.i18n.getMessage('mediumRisk') : 
                                   chrome.i18n.getMessage('lowRisk');
                    
                    status.innerHTML = '✅ ' + (chrome.i18n.getMessage('analysisComplete') || 'Analysis complete') + ' - ' + riskText;
                    
                    status.style.background = riskLevel === 'high' ? '#fef2f2' : 
                                            riskLevel === 'medium' ? '#fff8e6' : '#f0fdf4';
                    
                    status.style.borderLeft = '4px solid ' + 
                        (riskLevel === 'high' ? '#ef4444' : 
                         riskLevel === 'medium' ? '#f59e0b' : '#22c55e');
                }
            }, 2000);
            
        } else {
            throw new Error(response?.error || 'Unknown analysis error');
        }
    } catch (error) {
        console.error('Email analysis error:', error);
        showError((chrome.i18n.getMessage('analysisError') || 'Analysis error') + ': ' + error.message);
        showLoading(false);
    }
}

// Check if API keys are configured
async function checkApiKeys() {
    try {
        const result = await chrome.storage.local.get(['virusTotalApiKey']);
        return result.virusTotalApiKey && result.virusTotalApiKey.length > 0;
    } catch (error) {
        console.error('Error checking API keys:', error);
        return false;
    }
}

// Run demo analysis
async function runDemoAnalysis() {
    showLoading(true);
    updateLoadingText(chrome.i18n.getMessage('preparingDemo') || 'Preparing demo analysis...');
    
    // Demo email data
    const demoResult = {
        emailData: {
            subject: '🚨 URGENT: Your Microsoft Account Needs Verification',
            sender: 'security@microsofft-team.com',
            senderEmail: 'security@microsofft-team.com',
            body: '<p>Dear Customer,</p><p>Your Microsoft account requires immediate verification. Please <a href="http://microsoft-verify.tk/account">click here</a> to verify your account or it will be suspended.</p>',
            links: [
                'http://microsoft-verify.tk/account',
                'https://phishing-site.ml/login.php',
                'http://malware-download.ru/file.exe'
            ],
            attachments: [
                { name: 'Microsoft_Security_Update.exe', size: 1457000 },
                { name: 'Account_Details.docm', size: 245000 }
            ]
        },
        senderReputation: {
            domain: 'microsofft-team.com',
            trustScore: 15,
            domainAge: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
            spf: 'failed',
            dkim: 'failed',
            dmarc: 'failed',
            ipReputation: {
                ip: '185.234.219.133',
                abuseScore: 85,
                totalReports: 127,
                isp: 'Suspicious Hosting Provider',
                countryCode: 'RU'
            }
        },
        urlResults: [
            {
                url: 'http://microsoft-verify.tk/account',
                virusTotal: {
                    positives: 42,
                    total: 75,
                    riskLevel: 'high'
                },
                abuseIPDB: {
                    abuseScore: 92,
                    totalReports: 45,
                    riskLevel: 'high'
                },
                aggregatedRisk: 'high',
                aggregatedScore: 8.5
            },
            {
                url: 'https://phishing-site.ml/login.php',
                virusTotal: {
                    positives: 38,
                    total: 75,
                    riskLevel: 'high'
                },
                aggregatedRisk: 'high',
                aggregatedScore: 7.8
            },
            {
                url: 'http://malware-download.ru/file.exe',
                virusTotal: {
                    positives: 65,
                    total: 75,
                    riskLevel: 'high'
                },
                abuseIPDB: {
                    abuseScore: 100,
                    totalReports: 234,
                    riskLevel: 'high'
                },
                aggregatedRisk: 'high',
                aggregatedScore: 9.5
            }
        ],
        attachmentResults: [
            {
                name: 'Microsoft_Security_Update.exe',
                extension: 'exe',
                positives: 58,
                total: 75,
                riskLevel: 'high',
                scanDate: new Date().toISOString(),
                vtLink: 'https://www.virustotal.com/gui/file/123456/detection'
            },
            {
                name: 'Account_Details.docm',
                extension: 'docm',
                positives: 27,
                total: 75,
                riskLevel: 'medium',
                scanDate: new Date().toISOString(),
                vtLink: 'https://www.virustotal.com/gui/file/234567/detection'
            }
        ],
        riskScore: {
            score: 95,
            level: 'high',
            factors: [
                '🚨 ' + chrome.i18n.getMessage('senderReputation') + ': ' + chrome.i18n.getMessage('lowRisk') + ' (15/100)',
                '❌ SPF ' + chrome.i18n.getMessage('failed'),
                '❌ DMARC ' + chrome.i18n.getMessage('failed'),
                '🆕 Very new domain (15 days)',
                '🚫 Bad IP reputation (85% abuse score)',
                '🔗 Dangerous URL: http://microsoft-verify.tk/account',
                '🔗 Dangerous URL: https://phishing-site.ml/login.php',
                '🔗 Dangerous URL: http://malware-download.ru/file.exe',
                '📎 High risk attachment: Microsoft_Security_Update.exe (58/75)',
                '📎 Medium risk attachment: Account_Details.docm (27/75)',
                '📧 Suspicious word (subject): "urgent"',
                '🚨 Possible fake microsoft domain: microsofft-team.com',
                '⚡ Panic-inducing subject'
            ]
        }
    };
    
    // Simulate analysis stages
    await delay(1000);
    updateLoadingText(chrome.i18n.getMessage('checkingSenderReputation') || 'Checking sender reputation...');
    
    await delay(1500);
    updateLoadingText(chrome.i18n.getMessage('analyzingUrls') || 'Analyzing URLs with VirusTotal & AbuseIPDB...');
    
    await delay(1500);
    updateLoadingText(chrome.i18n.getMessage('analyzingAttachments') || 'Analyzing attachments...');
    
    await delay(1000);
    updateLoadingText(chrome.i18n.getMessage('highRiskDetected') || 'High risk detected!');
    
    await delay(500);
    
    // Display results
    displayResults(demoResult);
    
    // Hide loading after 1 second
    setTimeout(() => {
        showLoading(false);
        
        // Update status message
        const status = document.getElementById('status');
        if (status) {
            status.innerHTML = '✅ Demo analysis complete - HIGH RISK!';
            status.style.background = '#fef2f2';
            status.style.borderLeft = '4px solid #ef4444';
        }
    }, 1000);
}

// Display results in popup
function displayResults(results) {
    const { emailData, urlResults, attachmentResults, senderReputation, riskScore } = results;
    const resultsContainer = document.getElementById('results');
    
    if (!resultsContainer) return;
    
    // Show results
    resultsContainer.style.display = 'block';
    
    // Risk score
    const riskScoreDiv = document.getElementById('riskScore');
    if (riskScoreDiv) {
        riskScoreDiv.className = `risk-score risk-${riskScore.level}`;
        riskScoreDiv.innerHTML = `
            🛡️ ${chrome.i18n.getMessage('riskScore') || 'Risk Score'}: <span id="scoreValue">${riskScore.score}</span><br>
            <small style="font-weight: normal; opacity: 0.8;">📧 ${emailData.subject.length > 30 ? emailData.subject.substring(0, 30) + '...' : emailData.subject}</small>
        `;
    }
    
    // Sender reputation section
    if (senderReputation) {
        const senderSection = document.getElementById('senderReputationSection');
        const senderContent = document.getElementById('senderReputationContent');
        
        if (senderSection && senderContent) {
            senderSection.style.display = 'block';
            
            senderContent.innerHTML = `
                <div class="reputation-item">
                    <span>${chrome.i18n.getMessage('trustScore') || 'Trust Score'}:</span>
                    <strong style="color: ${senderReputation.trustScore < 30 ? '#ef4444' : 
                                           senderReputation.trustScore < 60 ? '#f59e0b' : '#22c55e'}">
                        ${senderReputation.trustScore}/100
                    </strong>
                </div>
                <div class="reputation-item">
                    <span>Domain:</span>
                    <span>${senderReputation.domain}</span>
                </div>
                ${senderReputation.domainAge ? `
                    <div class="reputation-item">
                        <span>${chrome.i18n.getMessage('domainAge') || 'Domain Age'}:</span>
                        <span>${Math.floor((new Date() - new Date(senderReputation.domainAge)) / (1000 * 60 * 60 * 24))} days</span>
                    </div>
                ` : ''}
                <div class="reputation-item">
                    <span>SPF:</span>
                    <span class="status-badge status-${senderReputation.spf}">
                        ${chrome.i18n.getMessage(senderReputation.spf) || senderReputation.spf}
                    </span>
                </div>
                <div class="reputation-item">
                    <span>DMARC:</span>
                    <span class="status-badge status-${senderReputation.dmarc}">
                        ${chrome.i18n.getMessage(senderReputation.dmarc) || senderReputation.dmarc}
                    </span>
                </div>
                ${senderReputation.ipReputation ? `
                    <div class="reputation-item">
                        <span>${chrome.i18n.getMessage('ipReputation') || 'IP Reputation'}:</span>
                        <span style="color: ${senderReputation.ipReputation.abuseScore > 50 ? '#ef4444' : '#22c55e'}">
                            ${senderReputation.ipReputation.abuseScore}% abuse
                        </span>
                    </div>
                ` : ''}
            `;
        }
    }
    
    // URL results
    const urlResultsDiv = document.getElementById('urlResults');
    if (urlResultsDiv) {
        if (urlResults.length === 0) {
            urlResultsDiv.innerHTML = '<p>' + (chrome.i18n.getMessage('noUrlsFound') || 'No URLs found in this email.') + '</p>';
        } else {
            urlResultsDiv.innerHTML = urlResults.map(result => {
                const shortUrl = result.url.length > 40 ? result.url.substring(0, 40) + '...' : result.url;
                return `
                    <div class="url-item ${result.aggregatedRisk === 'high' ? 'threat-detected' : result.aggregatedRisk === 'medium' ? 'threat-detected' : 'threat-clean'}">
                        <strong>🔗 ${shortUrl}</strong>
                        <div style="margin-top: 4px;">
                            ${result.virusTotal ? `
                                <span class="threat-score" style="background-color: ${result.virusTotal.riskLevel === 'high' ? '#e74c3c' : result.virusTotal.riskLevel === 'medium' ? '#f39c12' : '#27ae60'};">
                                    VT: ${result.virusTotal.positives}/${result.virusTotal.total}
                                </span>
                            ` : ''}
                            ${result.abuseIPDB ? `
                                <span class="threat-score" style="background-color: ${result.abuseIPDB.riskLevel === 'high' ? '#e74c3c' : result.abuseIPDB.riskLevel === 'medium' ? '#f39c12' : '#27ae60'}; margin-left: 5px;">
                                    AbuseIPDB: ${result.abuseIPDB.abuseScore}%
                                </span>
                            ` : ''}
                        </div>
                        ${result.aggregatedRisk === 'high' ? '<small style="color: #e74c3c; font-weight: bold;">⚠️ ' + (chrome.i18n.getMessage('highRisk') || 'HIGH RISK') + ' - ' + (chrome.i18n.getMessage('doNotClick') || 'Do not click!') + '</small>' : ''}
                    </div>
                `;
            }).join('');
        }
    }
    
    // Attachment results
    const attachmentResultsDiv = document.getElementById('attachmentResults');
    if (attachmentResultsDiv) {
        if (attachmentResults.length === 0) {
            attachmentResultsDiv.innerHTML = '<p>' + (chrome.i18n.getMessage('noAttachmentsFound') || 'No attachments found in this email.') + '</p>';
        } else {
            attachmentResultsDiv.innerHTML = attachmentResults.map(att => `
                <div class="attachment-item ${att.riskLevel === 'high' ? 'threat-detected' : att.riskLevel === 'medium' ? 'threat-detected' : 'threat-clean'}">
                    <strong>📎 ${att.name}</strong>
                    <span class="threat-score" style="background-color: ${att.riskLevel === 'high' ? '#e74c3c' : att.riskLevel === 'medium' ? '#f39c12' : '#27ae60'};">
                        ${att.positives}/${att.total}
                    </span>
                    <br><small>${chrome.i18n.getMessage('size') || 'Size'}: ${Math.round((att.size || 0) / 1024)} KB</small>
                    ${att.riskLevel === 'high' ? '<br><small style="color: #e74c3c; font-weight: bold;">⚠️ ' + (chrome.i18n.getMessage('dangerous') || 'DANGEROUS') + ' - ' + (chrome.i18n.getMessage('doNotDownload') || 'Do not download!') + '</small>' : ''}
                </div>
            `).join('');
        }
    }
    
    // Risk factors
    const riskFactorsDiv = document.getElementById('riskFactors');
    if (riskFactorsDiv) {
        if (riskScore.factors.length === 0) {
            riskFactorsDiv.innerHTML = '<div class="no-risks">✅ ' + (chrome.i18n.getMessage('noRiskFactorsDetected') || 'No significant risk factors detected') + '</div>';
        } else {
            riskFactorsDiv.innerHTML = `
                <div class="risk-factors">
                    <ul>
                        ${riskScore.factors.map(factor => `<li>${factor}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
    }
}

// UI helper functions
function showLoading(show) {
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    
    if (loading) {
        loading.style.display = show ? 'block' : 'none';
    }
    if (results) {
        results.style.display = show ? 'none' : results.style.display;
    }
}

function updateLoadingText(text) {
    const loadingText = document.getElementById('loadingText');
    if (loadingText) {
        loadingText.textContent = text;
    }
    console.log('⏳', text);
}

function showError(message) {
    const results = document.getElementById('results');
    if (results) {
        results.innerHTML = `
            <div style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 8px; border-left: 4px solid #dc3545;">
                <strong>❌ ${chrome.i18n.getMessage('error') || 'Error'}:</strong> ${message}
            </div>
        `;
        results.style.display = 'block';
    }
    showLoading(false);
    
    // Update status message
    const status = document.getElementById('status');
    if (status) {
        status.innerHTML = '❌ ' + (chrome.i18n.getMessage('error') || 'Error') + ': ' + message;
        status.style.background = '#f8d7da';
        status.style.borderLeft = '4px solid #dc3545';
    }
}

function showStatus(element, message, type) {
    if (!element) return;
    
    element.style.display = 'block';
    element.textContent = message;
    
    if (type === 'success') {
        element.style.background = '#d4edda';
        element.style.color = '#155724';
        element.style.border = '1px solid #c3e6cb';
    } else if (type === 'error') {
        element.style.background = '#f8d7da';
        element.style.color = '#721c24';
        element.style.border = '1px solid #f5c6cb';
    } else {
        element.style.background = '#d1ecf1';
        element.style.color = '#0c5460';
        element.style.border = '1px solid #bee5eb';
    }
    
    // Hide after 5 seconds
    setTimeout(() => {
        element.style.display = 'none';
    }, 5000);
}

// Content script notification
async function notifyContentScript() {
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs[0]) {
            // Send reload message to content script
            chrome.tabs.sendMessage(tabs[0].id, { 
                action: 'reloadApiKey' 
            }).catch(err => {
                console.log('Content script notification skipped:', err.message);
            });
        }
    } catch (error) {
        console.error('Error notifying content script:', error);
    }
}

// Mask API key
function maskApiKey(apiKey) {
    if (!apiKey || apiKey.length < 8) return apiKey;
    
    const visibleStart = 4;
    const visibleEnd = 4;
    const maskedLength = apiKey.length - visibleStart - visibleEnd;
    
    return apiKey.substring(0, visibleStart) + 
           '*'.repeat(maskedLength) + 
           apiKey.substring(apiKey.length - visibleEnd);
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

console.log('✅ Mail Security Extension popup.js loaded successfully!');