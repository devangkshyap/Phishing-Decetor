// Scanner-specific JavaScript functionality

class SecurityScanner {
    constructor() {
        this.currentTab = 'url';
        this.initializeTabs();
        this.initializeForms();
        this.initializeFileUpload();
    }

    // Initialize tab switching
    initializeTabs() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabId = button.dataset.tab;
                this.switchTab(tabId);
            });
        });
    }

    // Switch between scanner tabs
    switchTab(tabId) {
        // Update buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabId}-tab`).classList.add('active');

        this.currentTab = tabId;
        
        // Clear previous results
        const resultContainer = document.getElementById(`${tabId}-result`);
        if (resultContainer) {
            resultContainer.style.display = 'none';
        }
    }

    // Initialize all forms
    initializeForms() {
        this.initializeUrlForm();
        this.initializeEmailForm();
        this.initializeFileForm();
    }

    // URL scanner form
    initializeUrlForm() {
        const form = document.getElementById('url-form');
        const input = document.getElementById('url-input');
        const resultContainer = document.getElementById('url-result');

        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const url = input.value.trim();
            if (!url) {
                utils.showNotification('Please enter a URL', 'error');
                return;
            }

            if (!this.isValidUrl(url)) {
                utils.showNotification('Please enter a valid URL', 'error');
                return;
            }

            try {
                const result = await forms.submitForm('/api/scan-url', { url });
                this.displayResult(resultContainer, result, 'URL');
                
                // Scroll to results
                resultContainer.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start' 
                });
                
            } catch (error) {
                errorHandler.show('Failed to analyze URL. Please try again.');
            }
        });

        // Real-time URL validation
        input.addEventListener('input', utils.debounce((e) => {
            const url = e.target.value.trim();
            if (url && !this.isValidUrl(url)) {
                input.style.borderColor = 'var(--danger-color)';
            } else {
                input.style.borderColor = 'var(--gray-300)';
            }
        }, 300));
    }

    // Email scanner form
    initializeEmailForm() {
        const form = document.getElementById('email-form');
        const senderInput = document.getElementById('sender-email');
        const contentInput = document.getElementById('email-content');
        const resultContainer = document.getElementById('email-result');

        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const senderEmail = senderInput.value.trim();
            const emailContent = contentInput.value.trim();

            if (!emailContent) {
                utils.showNotification('Please enter email content', 'error');
                return;
            }

            if (senderEmail && !this.isValidEmail(senderEmail)) {
                utils.showNotification('Please enter a valid sender email', 'error');
                return;
            }

            try {
                const result = await forms.submitForm('/api/scan-email', {
                    sender_email: senderEmail,
                    email_content: emailContent
                });
                
                this.displayResult(resultContainer, result, 'Email');
                
                // Scroll to results
                resultContainer.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start' 
                });
                
            } catch (error) {
                errorHandler.show('Failed to analyze email. Please try again.');
            }
        });

        // Character counter for email content
        const maxLength = 10000;
        const counter = document.createElement('div');
        counter.className = 'character-counter';
        counter.style.cssText = 'text-align: right; font-size: 0.875rem; color: var(--gray-500); margin-top: 0.5rem;';
        contentInput.parentNode.appendChild(counter);

        contentInput.addEventListener('input', () => {
            const length = contentInput.value.length;
            counter.textContent = `${length}/${maxLength} characters`;
            
            if (length > maxLength * 0.9) {
                counter.style.color = 'var(--warning-color)';
            } else if (length > maxLength) {
                counter.style.color = 'var(--danger-color)';
            } else {
                counter.style.color = 'var(--gray-500)';
            }
        });

        // Trigger initial counter update
        contentInput.dispatchEvent(new Event('input'));
    }

    // File scanner form
    initializeFileForm() {
        const form = document.getElementById('file-form');
        const resultContainer = document.getElementById('file-result');

        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const fileInput = document.getElementById('file-input');
            const file = fileInput.files[0];

            if (!file) {
                utils.showNotification('Please select a file', 'error');
                return;
            }

            if (!this.isAllowedFileType(file)) {
                utils.showNotification('File type not allowed', 'error');
                return;
            }

            if (file.size > 16 * 1024 * 1024) { // 16MB
                utils.showNotification('File size exceeds 16MB limit', 'error');
                return;
            }

            try {
                const formData = new FormData();
                formData.append('file', file);

                const result = await forms.uploadFile('/api/scan-file', formData);
                this.displayResult(resultContainer, result, 'File', file);
                
                // Scroll to results
                resultContainer.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start' 
                });
                
            } catch (error) {
                errorHandler.show('Failed to analyze file. Please try again.');
            }
        });
    }

    // Initialize file upload functionality
    initializeFileUpload() {
        const uploadArea = document.getElementById('file-upload-area');
        const fileInput = document.getElementById('file-input');
        const fileInfo = document.getElementById('file-info');
        const scanButton = document.getElementById('scan-file-btn');
        const removeButton = document.getElementById('remove-file');

        if (!uploadArea || !fileInput) return;

        // Click to upload
        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });

        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--primary-color)';
            uploadArea.style.background = 'rgba(99, 102, 241, 0.05)';
        });

        uploadArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--gray-300)';
            uploadArea.style.background = 'var(--light-color)';
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--gray-300)';
            uploadArea.style.background = 'var(--light-color)';
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                this.handleFileSelection(files[0]);
            }
        });

        // File selection
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                this.handleFileSelection(file);
            }
        });

        // Remove file
        if (removeButton) {
            removeButton.addEventListener('click', () => {
                this.clearFileSelection();
            });
        }
    }

    // Handle file selection
    handleFileSelection(file) {
        const fileInfo = document.getElementById('file-info');
        const scanButton = document.getElementById('scan-file-btn');
        const uploadArea = document.getElementById('file-upload-area');

        if (!fileInfo || !scanButton) return;

        // Validate file
        if (!this.isAllowedFileType(file)) {
            utils.showNotification('File type not allowed', 'error');
            this.clearFileSelection();
            return;
        }

        if (file.size > 16 * 1024 * 1024) { // 16MB
            utils.showNotification('File size exceeds 16MB limit', 'error');
            this.clearFileSelection();
            return;
        }

        // Update UI
        const fileName = fileInfo.querySelector('.file-name');
        const fileSize = fileInfo.querySelector('.file-size');

        if (fileName) fileName.textContent = file.name;
        if (fileSize) fileSize.textContent = utils.formatFileSize(file.size);

        fileInfo.style.display = 'flex';
        scanButton.disabled = false;
        uploadArea.style.display = 'none';

        utils.showNotification('File selected successfully', 'success');
    }

    // Clear file selection
    clearFileSelection() {
        const fileInput = document.getElementById('file-input');
        const fileInfo = document.getElementById('file-info');
        const scanButton = document.getElementById('scan-file-btn');
        const uploadArea = document.getElementById('file-upload-area');

        if (fileInput) fileInput.value = '';
        if (fileInfo) fileInfo.style.display = 'none';
        if (scanButton) scanButton.disabled = true;
        if (uploadArea) uploadArea.style.display = 'block';
    }

    // Display scan results
    displayResult(container, result, type, file = null) {
        if (!container) return;

        container.style.display = 'block';
        const content = container.querySelector('.result-content');
        
        if (!content) return;

        // Risk level styling
        const riskClass = this.getRiskClass(result.risk_level);
        
        let html = `
            <div class="risk-assessment">
                <div class="risk-level ${riskClass}">
                    <i class="fas fa-${this.getRiskIcon(result.risk_level)}"></i>
                    <span><strong>Risk Level:</strong> ${result.risk_level}</span>
                </div>
                <div class="risk-score">
                    <div class="score-bar">
                        <div class="score-fill" style="width: ${result.risk_score}%; background: ${this.getScoreColor(result.risk_score)}"></div>
                    </div>
                    <span class="score-text">Risk Score: ${result.risk_score}/100</span>
                </div>
            </div>
        `;

        // File information
        if (file && result.file_info) {
            html += `
                <div class="file-analysis-info">
                    <h4><i class="fas fa-info-circle"></i> File Information</h4>
                    <div class="file-details-grid">
                        <div class="detail-item">
                            <strong>Name:</strong> ${result.file_info.filename}
                        </div>
                        <div class="detail-item">
                            <strong>Size:</strong> ${result.file_info.size}
                        </div>
                        <div class="detail-item">
                            <strong>Type:</strong> ${result.file_info.type}
                        </div>
                        <div class="detail-item">
                            <strong>Hash:</strong> ${result.file_info.hash}
                        </div>
                    </div>
                </div>
            `;
        }

        // Warnings
        if (result.warnings && result.warnings.length > 0) {
            html += `
                <div class="warnings-list">
                    <h4><i class="fas fa-exclamation-triangle"></i> Security Warnings</h4>
                    <ul>
                        ${result.warnings.map(warning => `<li>${warning}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        // Recommendations
        if (result.recommendations && result.recommendations.length > 0) {
            html += `
                <div class="recommendations-list">
                    <h4><i class="fas fa-lightbulb"></i> Security Recommendations</h4>
                    <ul>
                        ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        // Action buttons
        html += `
            <div class="result-actions">
                <button class="btn btn-primary share-btn" data-type="${type}">
                    <i class="fas fa-share"></i>
                    Share Results
                </button>
                <button class="btn btn-secondary export-btn" data-type="${type}">
                    <i class="fas fa-file-pdf"></i>
                    Export PDF Report
                </button>
            </div>
        `;

        content.innerHTML = html;

        // Add event listeners for action buttons
        const shareBtn = content.querySelector('.share-btn');
        const exportBtn = content.querySelector('.export-btn');
        
        if (shareBtn) {
            shareBtn.addEventListener('click', () => {
                this.shareResult(type, result);
            });
        }
        
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportResult(type, result);
            });
        }

        // Animate score bar
        setTimeout(() => {
            const scoreFill = content.querySelector('.score-fill');
            if (scoreFill) {
                scoreFill.style.transition = 'width 1s ease-out';
            }
        }, 100);

        utils.showNotification(`${type} analysis completed`, 'success');
    }

    // Get risk class for styling
    getRiskClass(riskLevel) {
        switch (riskLevel.toLowerCase()) {
            case 'high risk':
                return 'risk-high';
            case 'medium risk':
                return 'risk-medium';
            case 'low risk':
                return 'risk-low';
            default:
                return 'risk-low';
        }
    }

    // Get risk icon
    getRiskIcon(riskLevel) {
        switch (riskLevel.toLowerCase()) {
            case 'high risk':
                return 'exclamation-triangle';
            case 'medium risk':
                return 'exclamation-circle';
            case 'low risk':
                return 'check-circle';
            default:
                return 'info-circle';
        }
    }

    // Get score color
    getScoreColor(score) {
        if (score >= 70) return 'var(--danger-color)';
        if (score >= 40) return 'var(--warning-color)';
        return 'var(--success-color)';
    }

    // Validation helpers
    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    isValidEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    isAllowedFileType(file) {
        const allowedTypes = [
            'text/plain',
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
            'video/mp4',
            'video/x-msvideo',
            'video/quicktime'
        ];
        
        const allowedExtensions = ['txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'mp4', 'avi', 'mov'];
        const extension = file.name.split('.').pop().toLowerCase();
        
        return allowedTypes.includes(file.type) || allowedExtensions.includes(extension);
    }

    // Share results
    shareResult(type, result) {
        try {
            if (navigator.share) {
                navigator.share({
                    title: `CyberGuard ${type} Analysis Results`,
                    text: `Risk Level: ${result.risk_level} (${result.risk_score}/100)`,
                    url: window.location.href
                }).then(() => {
                    utils.showNotification('Results shared successfully', 'success');
                }).catch((error) => {
                    console.error('Share failed:', error);
                    this.fallbackShare(type, result);
                });
            } else {
                this.fallbackShare(type, result);
            }
        } catch (error) {
            console.error('Share error:', error);
            this.fallbackShare(type, result);
        }
    }

    // Fallback share method
    fallbackShare(type, result) {
        try {
            const text = `CyberGuard ${type} Analysis Results\nRisk Level: ${result.risk_level} (${result.risk_score}/100)\nAnalyzed at: ${new Date().toLocaleString()}`;
            
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    utils.showNotification('Results copied to clipboard', 'success');
                }).catch(() => {
                    this.manualCopy(text);
                });
            } else {
                this.manualCopy(text);
            }
        } catch (error) {
            console.error('Fallback share error:', error);
            utils.showNotification('Unable to share results. Please copy manually.', 'error');
        }
    }

    // Manual copy fallback
    manualCopy(text) {
        try {
            // Create a temporary textarea element
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            
            if (document.execCommand('copy')) {
                utils.showNotification('Results copied to clipboard', 'success');
            } else {
                utils.showNotification('Please copy the results manually', 'info');
                console.log('Results to copy:', text);
            }
            
            document.body.removeChild(textarea);
        } catch (error) {
            console.error('Manual copy error:', error);
            utils.showNotification('Please copy the results manually', 'info');
            console.log('Results to copy:', text);
        }
    }

    // Export results as PDF
    async exportResult(type, result) {
        try {
            // Show loading notification
            utils.showNotification('Generating PDF report...', 'info');
            
            const data = {
                type: type,
                timestamp: new Date().toISOString(),
                analysis: result,
                platform: 'CyberGuard Security Platform',
                version: '1.0'
            };

            // Send data to PDF export endpoint
            const response = await fetch('/api/export-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result_data = await response.json();
            
            if (!result_data.success) {
                throw new Error(result_data.error || 'PDF generation failed');
            }

            // Convert base64 to blob and download
            const binaryString = atob(result_data.pdf_data);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            const blob = new Blob([bytes], { type: 'application/pdf' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = result_data.filename || `cyberguard-${type.toLowerCase()}-analysis-${new Date().toISOString().split('T')[0]}.pdf`;
            a.style.display = 'none';
            
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            // Clean up the URL object
            setTimeout(() => {
                URL.revokeObjectURL(url);
            }, 1000);

            utils.showNotification(`PDF report exported successfully (${Math.round(result_data.size / 1024)}KB)`, 'success');
            
        } catch (error) {
            console.error('Export error:', error);
            utils.showNotification('Failed to export PDF report. Trying JSON fallback...', 'warning');
            
            // Fallback to JSON export
            this.exportResultAsJSON(type, result);
        }
    }

    // Fallback JSON export function
    exportResultAsJSON(type, result) {
        try {
            const data = {
                type: type,
                timestamp: new Date().toISOString(),
                analysis: result,
                platform: 'CyberGuard Security Platform',
                version: '1.0'
            };

            const jsonString = JSON.stringify(data, null, 2);
            const blob = new Blob([jsonString], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `cyberguard-${type.toLowerCase()}-analysis-${new Date().toISOString().split('T')[0]}.json`;
            a.style.display = 'none';
            
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            // Clean up the URL object
            setTimeout(() => {
                URL.revokeObjectURL(url);
            }, 1000);

            utils.showNotification('JSON report exported as fallback', 'info');
            
        } catch (error) {
            console.error('JSON export error:', error);
            
            // Final fallback: copy to clipboard
            try {
                const data = {
                    type: type,
                    timestamp: new Date().toISOString(),
                    analysis: result
                };
                const jsonString = JSON.stringify(data, null, 2);
                
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(jsonString).then(() => {
                        utils.showNotification('Report data copied to clipboard', 'info');
                    }).catch(() => {
                        console.log('Export data:', jsonString);
                        utils.showNotification('Export failed. Check console for data.', 'error');
                    });
                } else {
                    console.log('Export data:', jsonString);
                    utils.showNotification('Export failed. Check console for data.', 'error');
                }
            } catch (clipboardError) {
                console.error('Clipboard export error:', clipboardError);
                utils.showNotification('All export methods failed. Please try again.', 'error');
            }
        }
    }
}

// Initialize scanner when DOM is ready
let scanner;
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.scanner-container')) {
        scanner = new SecurityScanner();
        // Set global scanner instance for onclick handlers
        window.scanner = scanner;
        console.log('Security scanner initialized');
    }
});