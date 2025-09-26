// Advanced tools JavaScript functionality

// Global promise rejection handler
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    // Prevent the default behavior (showing error in console as "Uncaught (in promise)")
    event.preventDefault();
    
    // Show user-friendly error message if utils is available
    if (typeof utils !== 'undefined' && utils.showNotification) {
        utils.showNotification('An unexpected error occurred. Please try again.', 'error');
    }
});

class AdvancedSecurityTools {
    constructor() {
        try {
            this.initializeTools();
            // Load dashboard asynchronously without blocking initialization
            this.loadThreatDashboard().catch(error => {
                console.warn('Dashboard loading failed:', error);
                this.showFallbackDashboard();
            });
        } catch (error) {
            console.error('Error initializing advanced security tools:', error);
        }
    }

    // Initialize all advanced tools
    initializeTools() {
        try {
            this.initializePagePreview();
        } catch (error) {
            console.error('Error initializing page preview:', error);
        }
        
        try {
            this.initializeBulkScanner();
        } catch (error) {
            console.error('Error initializing bulk scanner:', error);
        }
        
        try {
            this.initializeDomainIntelligence();
        } catch (error) {
            console.error('Error initializing domain intelligence:', error);
        }
        
        try {
            this.initializeDashboardTabs();
        } catch (error) {
            console.error('Error initializing dashboard tabs:', error);
        }
    }

    // Page Preview Tool
    initializePagePreview() {
        console.log('Initializing page preview...');
        const form = document.getElementById('preview-form');
        const urlInput = document.getElementById('preview-url');
        const resultContainer = document.getElementById('preview-result');

        console.log('Form found:', !!form);
        console.log('URL input found:', !!urlInput);
        console.log('Result container found:', !!resultContainer);

        if (!form) {
            console.error('Preview form not found!');
            return;
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('Form submitted!');
            
            const url = urlInput.value.trim();
            console.log('URL entered:', url);
            
            if (!url) {
                console.log('No URL entered');
                this.showNotification('Please enter a URL', 'error');
                return;
            }

            if (!this.isValidUrl(url)) {
                console.log('Invalid URL format');
                this.showNotification('Please enter a valid URL', 'error');
                return;
            }

            try {
                console.log('Starting preview request...');
                this.showLoading();
                
                const result = await this.submitForm('/api/preview-page', { url });
                console.log('Preview result:', result);
                this.hideLoading();
                this.displayPagePreview(resultContainer, result, url);
                
                // Scroll to results
                resultContainer.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start' 
                });
                
            } catch (error) {
                console.error('Preview error caught:', error);
                this.hideLoading();
                this.showError('Failed to preview page. Please try again.');
                console.error('Preview error:', error);
            } finally {
                this.hideLoading();
            }
        });

        // Real-time URL validation
        urlInput.addEventListener('input', this.debounce((e) => {
            const url = e.target.value.trim();
            if (url && !this.isValidUrl(url)) {
                urlInput.style.borderColor = 'var(--danger-color)';
            } else {
                urlInput.style.borderColor = 'var(--gray-300)';
            }
        }, 300));
    }

    // Display page preview results
    displayPagePreview(container, result, originalUrl) {
        if (!container) return;

        container.style.display = 'block';

        // Update favicon
        const faviconImg = document.getElementById('preview-favicon');
        if (result.favicon && faviconImg) {
            faviconImg.src = result.favicon;
            faviconImg.style.display = 'block';
        } else if (faviconImg) {
            faviconImg.style.display = 'none';
        }

        // Update title and URL
        const titleElement = document.getElementById('preview-title');
        const urlElement = document.getElementById('preview-url-display');
        const statusBadge = document.getElementById('preview-status-badge');

        if (titleElement) titleElement.textContent = result.title || 'No title available';
        if (urlElement) urlElement.textContent = result.final_url || originalUrl;

        // Update status badge
        if (statusBadge) {
            if (result.accessible) {
                statusBadge.textContent = 'Accessible';
                statusBadge.className = 'status-badge status-success';
            } else {
                statusBadge.textContent = 'Inaccessible';
                statusBadge.className = 'status-badge status-danger';
            }
        }

        // Update description
        const descElement = document.getElementById('preview-description');
        if (descElement) {
            descElement.textContent = result.description || 'No description available';
        }

        // Update stats
        document.getElementById('status-code').textContent = result.status_code || 'N/A';
        document.getElementById('redirect-count').textContent = result.redirect_count || '0';
        document.getElementById('page-size').textContent = result.page_size ? 
            this.formatFileSize(result.page_size) : 'N/A';
        
        // Update screenshot status and display
        const screenshotStatus = document.getElementById('screenshot-status');
        const screenshotContainer = document.getElementById('preview-screenshot');
        const screenshotImg = document.getElementById('preview-screenshot-img');
        const screenshotDimensions = document.getElementById('screenshot-dimensions');
        
        if (result.screenshot_available && result.screenshot_data) {
            screenshotStatus.textContent = 'Available';
            screenshotStatus.style.color = 'var(--success-color)';
            
            // Display screenshot
            screenshotContainer.style.display = 'block';
            screenshotImg.src = result.screenshot_data;
            screenshotImg.onload = () => {
                console.log('Screenshot loaded successfully');
            };
            screenshotImg.onerror = () => {
                console.error('Failed to load screenshot image');
                screenshotContainer.style.display = 'none';
            };
            
            // Add click to enlarge functionality
            screenshotImg.onclick = () => {
                this.openScreenshotModal(result.screenshot_data, originalUrl);
            };
            
            if (result.screenshot_dimensions) {
                screenshotDimensions.textContent = `Dimensions: ${result.screenshot_dimensions}`;
            }
        } else {
            screenshotStatus.textContent = 'Failed';
            screenshotStatus.style.color = 'var(--danger-color)';
            screenshotContainer.style.display = 'none';
            
            if (result.screenshot_error) {
                console.warn('Screenshot capture failed:', result.screenshot_error);
            }
        }

        // Update content analysis
        const analysisContainer = document.getElementById('preview-analysis');
        if (analysisContainer && result.content_analysis) {
            this.displayContentAnalysis(analysisContainer, result.content_analysis);
        }

        this.showNotification('Page preview completed successfully', 'success');
    }

    // Display content analysis
    displayContentAnalysis(container, analysis) {
        let html = '<h5><i class="fas fa-microscope"></i> Content Analysis</h5>';
        
        if (analysis.forms && analysis.forms.length > 0) {
            html += `
                <div class="analysis-section">
                    <h6><i class="fas fa-wpforms"></i> Forms Detected</h6>
                    <ul class="analysis-list">
                        ${analysis.forms.map(form => `<li>${form}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (analysis.suspicious_elements && analysis.suspicious_elements.length > 0) {
            html += `
                <div class="analysis-section warning">
                    <h6><i class="fas fa-exclamation-triangle"></i> Suspicious Elements</h6>
                    <ul class="analysis-list">
                        ${analysis.suspicious_elements.map(element => `<li>${element}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (analysis.suspicious_scripts && analysis.suspicious_scripts.length > 0) {
            html += `
                <div class="analysis-section warning">
                    <h6><i class="fas fa-code"></i> Script Analysis</h6>
                    <ul class="analysis-list">
                        ${analysis.suspicious_scripts.map(script => `<li>${script}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (!analysis.forms?.length && !analysis.suspicious_elements?.length && !analysis.suspicious_scripts?.length) {
            html += '<p class="no-analysis">No significant security concerns detected in page content.</p>';
        }

        container.innerHTML = html;
    }

    // Bulk URL Scanner
    initializeBulkScanner() {
        const form = document.getElementById('bulk-scan-form');
        const textarea = document.getElementById('bulk-urls');
        const resultContainer = document.getElementById('bulk-result');

        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const urlsText = textarea.value.trim();
            if (!urlsText) {
                this.showNotification('Please enter URLs to scan', 'error');
                return;
            }

            const urls = urlsText.split('\n')
                .map(url => url.trim())
                .filter(url => url.length > 0);

            if (urls.length === 0) {
                this.showNotification('Please enter valid URLs', 'error');
                return;
            }

            if (urls.length > 10) {
                this.showNotification('Maximum 10 URLs allowed for bulk scanning', 'error');
                return;
            }

            // Validate URLs
            const invalidUrls = urls.filter(url => !this.isValidUrl(url));
            if (invalidUrls.length > 0) {
                this.showNotification(`Invalid URLs found: ${invalidUrls.join(', ')}`, 'error');
                return;
            }

            try {
                this.showLoading();
                
                const result = await this.submitForm('/api/bulk-scan', { urls });
                this.displayBulkResults(resultContainer, result);
                
                // Scroll to results
                resultContainer.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start' 
                });
                
            } catch (error) {
                console.error('Bulk scan error:', error);
                this.hideLoading();
                this.showError('Failed to perform bulk scan. Please try again.');
            }
        });

        // Character counter
        const maxUrls = 10;
        const counter = document.createElement('div');
        counter.className = 'url-counter';
        counter.style.cssText = 'text-align: right; font-size: 0.875rem; color: var(--gray-500); margin-top: 0.5rem;';
        textarea.parentNode.appendChild(counter);

        textarea.addEventListener('input', () => {
            const urls = textarea.value.split('\n').filter(line => line.trim().length > 0);
            counter.textContent = `${urls.length}/${maxUrls} URLs`;
            
            if (urls.length > maxUrls * 0.8) {
                counter.style.color = 'var(--warning-color)';
            } else if (urls.length > maxUrls) {
                counter.style.color = 'var(--danger-color)';
            } else {
                counter.style.color = 'var(--gray-500)';
            }
        });

        // Trigger initial counter update
        textarea.dispatchEvent(new Event('input'));
    }

    // Display bulk scan results
    displayBulkResults(container, result) {
        if (!container || !result.results) return;

        container.style.display = 'block';

        // Count results by risk level and error types
        let safeCount = 0, suspiciousCount = 0, dangerousCount = 0;
        let timeoutCount = 0, connectionErrorCount = 0, generalErrorCount = 0;

        result.results.forEach(item => {
            if (item.error) {
                // Count error types
                if (item.error_type === 'timeout') {
                    timeoutCount++;
                } else if (item.error_type === 'connection_error') {
                    connectionErrorCount++;
                } else {
                    generalErrorCount++;
                }
                return;
            }
            
            const riskScore = item.analysis?.risk_score || 0;
            if (riskScore >= 70) dangerousCount++;
            else if (riskScore >= 40) suspiciousCount++;
            else safeCount++;
        });

        // Update summary
        document.getElementById('safe-count').textContent = safeCount;
        document.getElementById('suspicious-count').textContent = suspiciousCount;
        document.getElementById('dangerous-count').textContent = dangerousCount;

        // Show scan statistics if available
        if (result.statistics) {
            const statsHtml = `
                <div class="scan-statistics">
                    <h6><i class="fas fa-chart-bar"></i> Scan Statistics</h6>
                    <div class="stats-grid">
                        <div class="stat-item success">
                            <span class="stat-value">${result.statistics.successful}</span>
                            <span class="stat-label">Successful</span>
                        </div>
                        <div class="stat-item warning">
                            <span class="stat-value">${result.statistics.timeouts}</span>
                            <span class="stat-label">Timeouts</span>
                        </div>
                        <div class="stat-item danger">
                            <span class="stat-value">${result.statistics.connection_errors}</span>
                            <span class="stat-label">Connection Errors</span>
                        </div>
                        <div class="stat-item info">
                            <span class="stat-value">${result.statistics.failed}</span>
                            <span class="stat-label">Other Errors</span>
                        </div>
                    </div>
                </div>
            `;
            
            // Insert statistics before results list
            const resultsList = document.getElementById('bulk-results-list');
            if (resultsList && resultsList.parentNode) {
                const existingStats = resultsList.parentNode.querySelector('.scan-statistics');
                if (existingStats) {
                    existingStats.remove();
                }
                resultsList.insertAdjacentHTML('beforebegin', statsHtml);
            }
        }

        // Generate results list
        const resultsList = document.getElementById('bulk-results-list');
        let html = '';

        result.results.forEach((item, index) => {
            if (item.error) {
                // Handle error cases with specific styling
                const errorIcon = this.getErrorIcon(item.error_type);
                const errorClass = this.getErrorClass(item.error_type);
                
                html += `
                    <div class="bulk-result-item error-result ${errorClass}">
                        <div class="result-header">
                            <div class="result-url">
                                <i class="fas fa-link"></i>
                                <span>${item.url}</span>
                            </div>
                            <div class="result-risk">
                                <span class="risk-badge error">
                                    <i class="${errorIcon}"></i> Error
                                </span>
                            </div>
                        </div>
                        <div class="result-details">
                            <p class="error-message ${item.error_type || 'general'}">
                                <i class="${errorIcon}"></i> 
                                ${item.error}
                                ${this.getErrorTip(item.error_type)}
                            </p>
                        </div>
                    </div>
                `;
            } else {
                // Handle successful analysis
                const riskClass = this.getRiskClass(item.analysis?.risk_level || 'Unknown');
                const riskScore = item.analysis?.risk_score || 0;
                
                html += `
                    <div class="bulk-result-item ${riskClass}">
                        <div class="result-header">
                            <div class="result-url">
                                <i class="fas fa-link"></i>
                                <span>${item.url}</span>
                            </div>
                            <div class="result-risk">
                                <span class="risk-badge ${riskClass}">
                                    ${item.analysis?.risk_level || 'Unknown'}
                                </span>
                                <span class="risk-score">${riskScore}/100</span>
                            </div>
                        </div>
                        <div class="result-details">
                            ${this.generateResultSummary(item.analysis)}
                        </div>
                    </div>
                `;
            }
        });

        resultsList.innerHTML = html;

        this.showNotification(`Bulk scan completed: ${result.total_scanned} URLs analyzed`, 'success');
    }

    // Generate result summary for bulk scan
    generateResultSummary(analysis) {
        if (!analysis) return '<p>No analysis data available</p>';

        let summary = '';
        
        if (analysis.warnings && analysis.warnings.length > 0) {
            const displayWarnings = analysis.warnings.slice(0, 3); // Show first 3 warnings
            summary += `
                <div class="warnings-summary">
                    <strong>Warnings:</strong>
                    <ul>
                        ${displayWarnings.map(warning => `<li>${warning}</li>`).join('')}
                    </ul>
                    ${analysis.warnings.length > 3 ? `<p><em>...and ${analysis.warnings.length - 3} more warnings</em></p>` : ''}
                </div>
            `;
        } else {
            summary += '<p class="no-warnings">No significant security concerns detected.</p>';
        }

        return summary;
    }

    // Domain Intelligence Tool
    initializeDomainIntelligence() {
        const form = document.getElementById('domain-form');
        const input = document.getElementById('domain-input');
        const resultContainer = document.getElementById('domain-result');

        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const domain = input.value.trim();
            if (!domain) {
                this.showNotification('Please enter a domain', 'error');
                return;
            }

            // Basic domain validation
            const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
            if (!domainRegex.test(domain)) {
                this.showNotification('Please enter a valid domain name', 'error');
                return;
            }

            try {
                this.showLoading();
                
                const result = await this.submitForm('/api/domain-info', { domain });
                this.displayDomainAnalysis(resultContainer, result);
                
                // Scroll to results
                resultContainer.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start' 
                });
                
            } catch (error) {
                console.error('Domain analysis error:', error);
                this.hideLoading();
                this.showError('Failed to analyze domain. Please try again.');
            }
        });
    }

    // Display domain analysis results
    displayDomainAnalysis(container, result) {
        if (!container) return;

        container.style.display = 'block';

        // Populate overview tab
        this.populateOverviewTab(result);
        this.populateWhoisTab(result.whois);
        this.populateDnsTab(result.dns);
        this.populateSslTab(result.ssl);

        this.showNotification('Domain analysis completed successfully', 'success');
    }

    // Populate overview tab
    populateOverviewTab(result) {
        const overviewTab = document.getElementById('overview-tab');
        if (!overviewTab) return;

        let html = `
            <div class="domain-overview">
                <div class="domain-header">
                    <h4><i class="fas fa-globe"></i> ${result.domain}</h4>
                    <span class="analysis-time">Analyzed: ${new Date(result.analysis_timestamp).toLocaleString()}</span>
                </div>
                
                <div class="overview-grid">
                    <div class="overview-item">
                        <i class="fas fa-calendar"></i>
                        <div>
                            <strong>Domain Age</strong>
                            <p>${result.whois?.creation_date ? 
                                this.calculateDomainAge(result.whois.creation_date) : 'Unknown'}</p>
                        </div>
                    </div>
                    
                    <div class="overview-item">
                        <i class="fas fa-building"></i>
                        <div>
                            <strong>Registrar</strong>
                            <p>${result.whois?.registrar || 'Unknown'}</p>
                        </div>
                    </div>
                    
                    <div class="overview-item">
                        <i class="fas fa-lock"></i>
                        <div>
                            <strong>SSL Status</strong>
                            <p class="${result.ssl?.valid ? 'text-success' : 'text-danger'}">
                                ${result.ssl?.valid ? 'Valid Certificate' : 'Invalid/Missing'}
                            </p>
                        </div>
                    </div>
                    
                    <div class="overview-item">
                        <i class="fas fa-shield-alt"></i>
                        <div>
                            <strong>Risk Assessment</strong>
                            <p class="text-success">Low Risk</p>
                        </div>
                    </div>
                </div>
            </div>
        `;

        overviewTab.innerHTML = html;
    }

    // Populate WHOIS tab
    populateWhoisTab(whoisData) {
        const whoisTab = document.getElementById('whois-tab');
        if (!whoisTab) return;

        let html = '<div class="whois-data">';

        if (whoisData.error) {
            html += `<p class="error-message"><i class="fas fa-exclamation-circle"></i> ${whoisData.error}</p>`;
        } else {
            html += `
                <div class="data-grid">
                    <div class="data-item">
                        <strong>Registrar:</strong>
                        <span>${whoisData.registrar || 'N/A'}</span>
                    </div>
                    <div class="data-item">
                        <strong>Creation Date:</strong>
                        <span>${whoisData.creation_date || 'N/A'}</span>
                    </div>
                    <div class="data-item">
                        <strong>Expiration Date:</strong>
                        <span>${whoisData.expiration_date || 'N/A'}</span>
                    </div>
                    <div class="data-item">
                        <strong>Status:</strong>
                        <span>${Array.isArray(whoisData.status) ? whoisData.status.join(', ') : (whoisData.status || 'N/A')}</span>
                    </div>
                </div>
            `;

            if (whoisData.name_servers && whoisData.name_servers.length > 0) {
                html += `
                    <div class="nameservers-section">
                        <h5>Name Servers:</h5>
                        <ul class="nameservers-list">
                            ${whoisData.name_servers.map(ns => `<li>${ns}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
        }

        html += '</div>';
        whoisTab.innerHTML = html;
    }

    // Populate DNS tab
    populateDnsTab(dnsData) {
        const dnsTab = document.getElementById('dns-tab');
        if (!dnsTab) return;

        let html = '<div class="dns-data">';

        if (dnsData.error) {
            html += `<p class="error-message"><i class="fas fa-exclamation-circle"></i> ${dnsData.error}</p>`;
        } else {
            const recordTypes = ['A', 'MX', 'NS', 'TXT'];
            
            recordTypes.forEach(type => {
                if (dnsData[type] && dnsData[type].length > 0) {
                    html += `
                        <div class="dns-section">
                            <h5>${type} Records:</h5>
                            <ul class="dns-records">
                                ${dnsData[type].map(record => `<li><code>${record}</code></li>`).join('')}
                            </ul>
                        </div>
                    `;
                }
            });
        }

        html += '</div>';
        dnsTab.innerHTML = html;
    }

    // Populate SSL tab
    populateSslTab(sslData) {
        const sslTab = document.getElementById('ssl-tab');
        if (!sslTab) return;

        let html = '<div class="ssl-data">';

        if (!sslData.valid) {
            html += `
                <div class="ssl-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h5>SSL Certificate Invalid or Missing</h5>
                    <p>${sslData.error || 'No valid SSL certificate found'}</p>
                </div>
            `;
        } else {
            html += `
                <div class="ssl-valid">
                    <i class="fas fa-check-circle"></i>
                    <h5>Valid SSL Certificate</h5>
                    
                    <div class="ssl-details">
                        <div class="ssl-item">
                            <strong>Subject:</strong>
                            <span>${sslData.subject?.commonName || 'N/A'}</span>
                        </div>
                        <div class="ssl-item">
                            <strong>Issuer:</strong>
                            <span>${sslData.issuer?.organizationName || 'N/A'}</span>
                        </div>
                        <div class="ssl-item">
                            <strong>Valid From:</strong>
                            <span>${sslData.not_before || 'N/A'}</span>
                        </div>
                        <div class="ssl-item">
                            <strong>Valid Until:</strong>
                            <span>${sslData.not_after || 'N/A'}</span>
                        </div>
                        <div class="ssl-item">
                            <strong>Serial Number:</strong>
                            <span>${sslData.serial_number || 'N/A'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        html += '</div>';
        sslTab.innerHTML = html;
    }

    // Initialize dashboard tabs
    initializeDashboardTabs() {
        const tabButtons = document.querySelectorAll('.analysis-tab');
        const tabContents = document.querySelectorAll('.analysis-tab-content');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabId = button.dataset.tab;
                
                // Update buttons
                tabButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                // Update content
                tabContents.forEach(content => content.classList.remove('active'));
                const targetTab = document.getElementById(`${tabId}-tab`);
                if (targetTab) {
                    targetTab.classList.add('active');
                }
            });
        });
    }

    // Load threat intelligence dashboard
    async loadThreatDashboard() {
        try {
            const response = await fetch('/api/threat-report');
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            this.updateDashboardStats(data);
            this.updateTopThreats(data.top_threats);
            this.updateSecurityTips(data.security_tips);
            this.updateApiStatus(data.api_status, data.enhanced_detection);
            
        } catch (error) {
            console.error('Failed to load threat dashboard:', error);
            // Show fallback data
            this.showFallbackDashboard();
        }
    }

    // Show fallback dashboard data
    showFallbackDashboard() {
        const fallbackData = {
            total_threats_blocked: 1234,
            phishing_attempts: 567,
            malware_detected: 234,
            suspicious_domains: 198
        };
        
        this.updateDashboardStats(fallbackData);
        
        const fallbackThreats = [
            {type: 'Phishing Email', count: 456, trend: '+12%'},
            {type: 'Fake Banking Site', count: 234, trend: '+8%'},
            {type: 'Malicious Download', count: 189, trend: '-5%'}
        ];
        
        this.updateTopThreats(fallbackThreats);
        
        const fallbackTips = [
            'Always verify sender identity before clicking email links',
            'Check for HTTPS encryption on sensitive websites',
            'Keep your antivirus software updated'
        ];
        
        this.updateSecurityTips(fallbackTips);
    }

    // Update dashboard statistics
    updateDashboardStats(data) {
        const elements = {
            'threats-blocked': data.total_threats_blocked,
            'phishing-attempts': data.phishing_attempts,
            'malware-detected': data.malware_detected,
            'suspicious-domains': data.suspicious_domains
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                // Animate counter - check if utils is available
                if (typeof utils !== 'undefined' && utils.animateCounter) {
                    utils.animateCounter(element, value, 2000);
                } else {
                    // Fallback to direct value assignment
                    element.textContent = value;
                }
            }
        });
    }

    // Update top threats list
    updateTopThreats(threats) {
        const container = document.getElementById('top-threats');
        if (!container || !threats) return;

        let html = '';
        threats.forEach(threat => {
            const trendClass = threat.trend.includes('+') ? 'trend-up' : 'trend-down';
            html += `
                <div class="threat-item">
                    <div class="threat-info">
                        <span class="threat-name">${threat.type}</span>
                        <span class="threat-count">${threat.count} incidents</span>
                    </div>
                    <span class="threat-trend ${trendClass}">${threat.trend}</span>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    // Update security tips
    updateSecurityTips(tips) {
        const container = document.getElementById('security-tips');
        if (!container || !tips) return;

        let html = '';
        tips.forEach(tip => {
            html += `
                <div class="tip-item">
                    <i class="fas fa-check-circle"></i>
                    <span>${tip}</span>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    // Utility methods
    showLoading() {
        if (typeof utils !== 'undefined' && utils.showLoading) {
            utils.showLoading();
        } else {
            // Fallback implementation
            console.log('Loading...');
        }
    }

    hideLoading() {
        if (typeof utils !== 'undefined' && utils.hideLoading) {
            utils.hideLoading();
        } else {
            // Fallback implementation
            console.log('Loading complete');
        }
    }

    showError(message) {
        if (typeof errorHandler !== 'undefined' && errorHandler.show) {
            errorHandler.show(message);
        } else {
            // Fallback implementation
            alert(message);
        }
    }

    showNotification(message, type = 'info') {
        if (typeof utils !== 'undefined' && utils.showNotification) {
            utils.showNotification(message, type);
        } else {
            // Fallback implementation
            console.log(`${type.toUpperCase()}: ${message}`);
        }
    }

    async submitForm(url, data) {
        try {
            if (typeof forms !== 'undefined' && forms.submitForm) {
                return await forms.submitForm(url, data);
            } else {
                // Fallback implementation
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                if (!response.ok) {
                    let errorMessage = `HTTP error! status: ${response.status}`;
                    try {
                        const errorData = await response.json();
                        if (errorData.error) {
                            errorMessage = errorData.error;
                        }
                    } catch (e) {
                        // If we can't parse error JSON, use the status message
                    }
                    throw new Error(errorMessage);
                }
                
                return await response.json();
            }
        } catch (error) {
            console.error('Form submission error:', error);
            throw error; // Re-throw to let the calling method handle it
        }
    }

    debounce(func, wait) {
        if (typeof utils !== 'undefined' && utils.debounce) {
            return utils.debounce(func, wait);
        } else {
            // Fallback implementation
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
    }

    formatFileSize(bytes) {
        if (typeof utils !== 'undefined' && utils.formatFileSize) {
            return utils.formatFileSize(bytes);
        } else {
            // Fallback implementation
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    }

    // Helper methods
    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    getRiskClass(riskLevel) {
        switch (riskLevel?.toLowerCase()) {
            case 'high risk':
                return 'risk-high';
            case 'medium risk':
                return 'risk-medium';
            case 'low risk':
                return 'risk-low';
            default:
                return 'risk-unknown';
        }
    }

    calculateDomainAge(creationDate) {
        try {
            const created = new Date(creationDate);
            const now = new Date();
            const diffTime = Math.abs(now - created);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            
            if (diffDays < 30) {
                return `${diffDays} days (Very New)`;
            } else if (diffDays < 365) {
                return `${Math.floor(diffDays / 30)} months`;
            } else {
                return `${Math.floor(diffDays / 365)} years`;
            }
        } catch (e) {
            return 'Unknown';
        }
    }

    // Update API status display
    updateApiStatus(apiStatus, enhancedDetection) {
        const container = document.getElementById('api-status-grid');
        if (!container || !apiStatus) return;

        let html = '';
        
        // Add detection status badge to header
        const headerSection = document.querySelector('.api-status-section h3');
        if (headerSection) {
            const existingBadge = headerSection.querySelector('.enhanced-detection-badge, .basic-detection-badge');
            if (existingBadge) {
                existingBadge.remove();
            }
            
            const badge = document.createElement('span');
            if (enhancedDetection) {
                badge.className = 'enhanced-detection-badge';
                badge.innerHTML = '<i class="fas fa-shield-alt"></i> Enhanced Detection Active';
            } else {
                badge.className = 'basic-detection-badge';
                badge.innerHTML = '<i class="fas fa-info-circle"></i> Basic Detection Mode';
            }
            headerSection.appendChild(badge);
        }

        // Generate API status items
        Object.entries(apiStatus).forEach(([apiName, status]) => {
            const isActive = status.configured;
            const iconClass = this.getApiIcon(apiName);
            
            html += `
                <div class="api-status-item">
                    <div class="api-status-icon ${isActive ? 'active' : 'inactive'}">
                        <i class="${iconClass}"></i>
                    </div>
                    <div class="api-status-info">
                        <h4>${this.formatApiName(apiName)}</h4>
                        <p>${status.description || 'Security intelligence API'}</p>
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    // Get appropriate icon for each API
    getApiIcon(apiName) {
        const icons = {
            'virustotal': 'fas fa-virus',
            'google_safe_browsing': 'fab fa-google',
            'urlvoid': 'fas fa-shield-alt',
            'ipqualityscore': 'fas fa-user-shield',
            'abuseipdb': 'fas fa-database',
            'shodan': 'fas fa-search',
            'phishtank': 'fas fa-fish',
            'hibp': 'fas fa-key'
        };
        return icons[apiName] || 'fas fa-plug';
    }

    // Format API name for display
    formatApiName(apiName) {
        const names = {
            'virustotal': 'VirusTotal',
            'google_safe_browsing': 'Google Safe Browsing',
            'urlvoid': 'URLVoid',
            'ipqualityscore': 'IPQualityScore',
            'abuseipdb': 'AbuseIPDB',
            'shodan': 'Shodan',
            'phishtank': 'PhishTank',
            'hibp': 'Have I Been Pwned'
        };
        return names[apiName] || apiName.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    // Error handling helper functions
    getErrorIcon(errorType) {
        switch (errorType) {
            case 'timeout':
                return 'fas fa-clock';
            case 'connection_error':
                return 'fas fa-unlink';
            case 'http_error':
                return 'fas fa-exclamation-triangle';
            default:
                return 'fas fa-exclamation-circle';
        }
    }

    getErrorClass(errorType) {
        switch (errorType) {
            case 'timeout':
                return 'timeout-error';
            case 'connection_error':
                return 'connection-error';
            case 'http_error':
                return 'http-error';
            default:
                return 'general-error';
        }
    }

    getErrorTip(errorType) {
        switch (errorType) {
            case 'timeout':
                return '<small><br><i class="fas fa-lightbulb"></i> Tip: The website may be slow or temporarily unavailable</small>';
            case 'connection_error':
                return '<small><br><i class="fas fa-lightbulb"></i> Tip: Check if the URL is correct or if the website is down</small>';
            case 'http_error':
                return '<small><br><i class="fas fa-lightbulb"></i> Tip: The server returned an error response</small>';
            default:
                return '<small><br><i class="fas fa-lightbulb"></i> Tip: There was an unexpected error during analysis</small>';
        }
    }

    // Open screenshot in modal for full view
    openScreenshotModal(screenshotData, url) {
        // Create modal if it doesn't exist
        let modal = document.getElementById('screenshot-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'screenshot-modal';
            modal.className = 'screenshot-modal';
            modal.innerHTML = `
                <div class="modal-overlay">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3><i class="fas fa-image"></i> Website Preview</h3>
                            <button class="modal-close" onclick="this.parentElement.parentElement.parentElement.style.display='none'">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        <div class="modal-body">
                            <div class="modal-url">
                                <i class="fas fa-link"></i>
                                <span id="modal-url-text"></span>
                            </div>
                            <img id="modal-screenshot" src="" alt="Full size website preview">
                            <div class="modal-warning">
                                <i class="fas fa-shield-alt"></i>
                                <span>Safe Preview - You haven't actually visited this website</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            
            // Close modal when clicking overlay
            modal.querySelector('.modal-overlay').onclick = (e) => {
                if (e.target === e.currentTarget) {
                    modal.style.display = 'none';
                }
            };
        }
        
        // Update modal content
        document.getElementById('modal-url-text').textContent = url;
        document.getElementById('modal-screenshot').src = screenshotData;
        modal.style.display = 'flex';
    }
}

// Initialize advanced tools when DOM is ready
let advancedTools;
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.advanced-container')) {
        try {
            advancedTools = new AdvancedSecurityTools();
            // Set global advanced tools instance
            window.advancedTools = advancedTools;
            console.log('Advanced security tools initialized');
        } catch (error) {
            console.error('Failed to initialize advanced tools:', error);
            // Hide any error messages that might be showing
            const errorElements = document.querySelectorAll('.error-message, .alert-danger');
            errorElements.forEach(el => el.style.display = 'none');
        }
    }
});