// Phishing Email Analyzer - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const uploadContent = document.getElementById('uploadContent');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const removeFile = document.getElementById('removeFile');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loading = document.getElementById('loading');
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    const results = document.getElementById('results');
    const apiStatus = document.getElementById('apiStatus');

    let selectedFile = null;
    let aiAvailable = false;

    // Check AI status on load
    checkAIStatus();

    // Upload Zone Click
    uploadZone.addEventListener('click', () => fileInput.click());

    // Drag and Drop
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    // File Input Change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    // Remove File
    removeFile.addEventListener('click', (e) => {
        e.stopPropagation();
        clearFile();
    });

    // Analyze Button
    analyzeBtn.addEventListener('click', analyzeEmail);

    // Collapsible Headers
    document.querySelectorAll('.card-header.collapsible').forEach(header => {
        header.addEventListener('click', () => {
            const targetId = header.getAttribute('data-target');
            const target = document.getElementById(targetId);
            target.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        });
    });

    // Body Toggle
    const plainTextBtn = document.getElementById('plainTextBtn');
    const htmlBtn = document.getElementById('htmlBtn');
    const plainTextBody = document.getElementById('plainTextBody');
    const htmlBody = document.getElementById('htmlBody');

    plainTextBtn.addEventListener('click', () => {
        plainTextBtn.classList.add('active');
        htmlBtn.classList.remove('active');
        plainTextBody.style.display = 'block';
        htmlBody.style.display = 'none';
    });

    htmlBtn.addEventListener('click', () => {
        htmlBtn.classList.add('active');
        plainTextBtn.classList.remove('active');
        htmlBody.style.display = 'block';
        plainTextBody.style.display = 'none';
    });

    // Handle File Selection
    function handleFile(file) {
        if (!file.name.toLowerCase().endsWith('.eml')) {
            showError('Please select an .eml file');
            return;
        }

        selectedFile = file;
        uploadContent.style.display = 'none';
        fileInfo.style.display = 'flex';
        fileName.textContent = file.name;
        analyzeBtn.disabled = false;
        hideError();
        results.style.display = 'none';
    }

    // Clear File
    function clearFile() {
        selectedFile = null;
        fileInput.value = '';
        uploadContent.style.display = 'block';
        fileInfo.style.display = 'none';
        analyzeBtn.disabled = true;
        results.style.display = 'none';
        hideError();
    }

    // Show Error
    function showError(message) {
        errorText.textContent = message;
        errorMessage.style.display = 'flex';
    }

    // Hide Error
    function hideError() {
        errorMessage.style.display = 'none';
    }

    // Analyze Email
    async function analyzeEmail() {
        if (!selectedFile) return;

        // Show loading
        loading.style.display = 'block';
        results.style.display = 'none';
        hideError();
        analyzeBtn.disabled = true;

        // Prepare form data
        const formData = new FormData();
        formData.append('file', selectedFile);

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Analysis failed');
            }

            displayResults(data);
        } catch (error) {
            showError(error.message);
        } finally {
            loading.style.display = 'none';
            analyzeBtn.disabled = false;
        }
    }

    // Display Results
    function displayResults(data) {
        results.style.display = 'block';

        // Risk Score
        const aiAnalysis = data.ai_analysis || {};
        const riskScore = aiAnalysis.risk_score || 0;
        const riskLevel = (aiAnalysis.risk_level || 'Low').toLowerCase();

        animateRiskGauge(riskScore);
        updateRiskBadge(riskLevel);

        // AI Summary
        document.getElementById('aiSummary').textContent = aiAnalysis.summary || 'No summary available';

        // Analysis Method
        const methodText = data.analysis_method === 'ai' 
            ? '🤖 AI-powered analysis (Cloud AI)' 
            : '📋 Rule-based analysis (AI unavailable)';
        document.getElementById('analysisMethod').textContent = methodText;

        // Indicators
        const indicatorList = document.getElementById('indicatorList');
        indicatorList.innerHTML = '';
        const indicators = aiAnalysis.indicators || [];
        if (indicators.length === 0) {
            indicatorList.innerHTML = '<li><i class="fas fa-check-circle"></i> No significant indicators found</li>';
        } else {
            indicators.forEach(indicator => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${escapeHtml(indicator)}`;
                indicatorList.appendChild(li);
            });
        }

        // Recommendations
        const recommendationList = document.getElementById('recommendationList');
        recommendationList.innerHTML = '';
        const recommendations = aiAnalysis.recommendations || [];
        recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fas fa-check-circle"></i> ${escapeHtml(rec)}`;
            recommendationList.appendChild(li);
        });

        // Basic Info
        displayBasicInfo(data.basic_info || {});

        // Authentication Results
        displayAuthResults(data.auth_results || {});

        // Received Chain
        displayReceivedChain(data.received_chain || []);

        // All Headers
        displayHeaders(data.headers || []);

        // Links
        displayLinks(data.links || []);

        // Attachments
        displayAttachments(data.attachments || []);

        // Body
        displayBody(data.body || {});

        // Scroll to results
        results.scrollIntoView({ behavior: 'smooth' });
    }

    // Animate Risk Gauge
    function animateRiskGauge(score) {
        const gaugeCircle = document.getElementById('gaugeCircle');
        const riskScoreEl = document.getElementById('riskScore');

        // Calculate degrees (0-100 -> 0-360)
        const degrees = Math.min(score, 100) * 3.6;

        // Determine color based on score
        let color;
        if (score < 25) {
            color = '#10b981'; // Green
        } else if (score < 50) {
            color = '#f59e0b'; // Yellow
        } else if (score < 75) {
            color = '#ef4444'; // Red
        } else {
            color = '#8b5cf6'; // Purple
        }

        // Animate
        let currentScore = 0;
        const duration = 1000;
        const startTime = performance.now();

        function animate(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            currentScore = Math.round(progress * score);
            const currentDegrees = progress * degrees;

            riskScoreEl.textContent = currentScore;
            gaugeCircle.style.background = `conic-gradient(${color} ${currentDegrees}deg, #111827 ${currentDegrees}deg)`;
            gaugeCircle.style.boxShadow = `0 0 30px ${color}40`;

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        }

        requestAnimationFrame(animate);
    }

    // Update Risk Badge
    function updateRiskBadge(level) {
        const badge = document.getElementById('riskBadge');
        badge.className = 'risk-badge ' + level;
        badge.textContent = level.charAt(0).toUpperCase() + level.slice(1);
    }

    // Display Basic Info
    function displayBasicInfo(info) {
        const table = document.getElementById('basicInfoTable').querySelector('tbody');
        table.innerHTML = '';

        const fields = [
            { key: 'from', label: 'From' },
            { key: 'to', label: 'To' },
            { key: 'cc', label: 'Cc' },
            { key: 'subject', label: 'Subject' },
            { key: 'date', label: 'Date' },
            { key: 'message_id', label: 'Message-ID' },
            { key: 'reply_to', label: 'Reply-To' },
            { key: 'return_path', label: 'Return-Path' }
        ];

        fields.forEach(field => {
            const value = info[field.key];
            if (value) {
                const tr = document.createElement('tr');
                tr.innerHTML = `<th>${field.label}</th><td>${escapeHtml(value)}</td>`;
                table.appendChild(tr);
            }
        });
    }

    // Display Auth Results
    function displayAuthResults(auth) {
        ['spf', 'dkim', 'dmarc'].forEach(type => {
            const badge = document.getElementById(type + 'Badge');
            const statusEl = badge.querySelector('.auth-status');
            const status = (auth[type]?.status || 'unknown').toLowerCase();
            
            statusEl.textContent = status;
            statusEl.className = 'auth-status ' + status;
        });
    }

    // Display Received Chain
    function displayReceivedChain(chain) {
        const container = document.getElementById('receivedChainContent');
        container.innerHTML = '';

        if (chain.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-route"></i><p>No received headers found</p></div>';
            return;
        }

        chain.forEach(hop => {
            const div = document.createElement('div');
            div.className = 'chain-hop';
            div.innerHTML = `
                <div class="hop-number">${hop.hop}</div>
                <div class="hop-details">
                    ${hop.from ? `<p><span class="label">From:</span> <span class="value">${escapeHtml(hop.from)}</span></p>` : ''}
                    ${hop.by ? `<p><span class="label">By:</span> <span class="value">${escapeHtml(hop.by)}</span></p>` : ''}
                    ${hop.timestamp ? `<p class="hop-timestamp"><i class="fas fa-clock"></i> ${escapeHtml(hop.timestamp)}</p>` : ''}
                </div>
            `;
            container.appendChild(div);
        });
    }

    // Display Headers
    function displayHeaders(headers) {
        const table = document.getElementById('headersTable').querySelector('tbody');
        table.innerHTML = '';

        if (headers.length === 0) {
            table.innerHTML = '<tr><td colspan="2" class="empty-state">No headers found</td></tr>';
            return;
        }

        headers.forEach(header => {
            const tr = document.createElement('tr');
            tr.innerHTML = `<th>${escapeHtml(header.key)}</th><td>${escapeHtml(header.value)}</td>`;
            table.appendChild(tr);
        });
    }

    // Display Links
    function displayLinks(links) {
        const container = document.getElementById('linksContainer');
        const countEl = document.getElementById('linkCount');
        container.innerHTML = '';
        countEl.textContent = links.length;

        if (links.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-link"></i><p>No links found in email</p></div>';
            return;
        }

        links.forEach(link => {
            const div = document.createElement('div');
            div.className = 'link-item' + (link.suspicious ? ' suspicious' : '');
            
            let reasonsHtml = '';
            if (link.reasons && link.reasons.length > 0) {
                reasonsHtml = '<div class="link-reasons">' + 
                    link.reasons.map(r => `<span class="reason-tag">${escapeHtml(r)}</span>`).join('') +
                    '</div>';
            }

            div.innerHTML = `
                <i class="fas fa-link link-icon"></i>
                <div class="link-details">
                    <div class="link-url">${escapeHtml(link.url)}</div>
                    <div class="link-meta">
                        <span><i class="fas fa-globe"></i> ${escapeHtml(link.domain)}</span>
                    </div>
                    ${reasonsHtml}
                </div>
            `;
            container.appendChild(div);
        });
    }

    // Display Attachments
    function displayAttachments(attachments) {
        const section = document.getElementById('attachmentsSection');
        const container = document.getElementById('attachmentsContainer');
        const countEl = document.getElementById('attachmentCount');

        if (attachments.length === 0) {
            section.style.display = 'none';
            return;
        }

        section.style.display = 'block';
        countEl.textContent = attachments.length;
        container.innerHTML = '';

        attachments.forEach(att => {
            const div = document.createElement('div');
            div.className = 'attachment-item' + (att.dangerous ? ' dangerous' : '');
            
            const icon = getFileIcon(att.content_type, att.filename);
            
            div.innerHTML = `
                <i class="${icon} attachment-icon"></i>
                <div class="attachment-details">
                    <div class="attachment-name">${escapeHtml(att.filename)}</div>
                    <div class="attachment-meta">
                        <span>${escapeHtml(att.content_type)}</span>
                        <span>${escapeHtml(att.size_formatted)}</span>
                        ${att.dangerous ? '<span style="color: var(--accent-red);"><i class="fas fa-exclamation-triangle"></i> Potentially dangerous</span>' : ''}
                    </div>
                    ${att.md5 ? `<div class="attachment-hash">MD5: ${escapeHtml(att.md5)}</div>` : ''}
                </div>
            `;
            container.appendChild(div);
        });
    }

    // Get File Icon
    function getFileIcon(contentType, filename) {
        if (contentType.startsWith('image/')) return 'fas fa-file-image';
        if (contentType.includes('pdf')) return 'fas fa-file-pdf';
        if (contentType.includes('zip') || contentType.includes('rar')) return 'fas fa-file-archive';
        if (contentType.includes('excel') || contentType.includes('spreadsheet')) return 'fas fa-file-excel';
        if (contentType.includes('word') || contentType.includes('document')) return 'fas fa-file-word';
        if (filename.endsWith('.exe') || filename.endsWith('.scr')) return 'fas fa-file-code';
        return 'fas fa-file';
    }

    // Display Body
    function displayBody(body) {
        const plainTextBody = document.getElementById('plainTextBody');
        const htmlBody = document.getElementById('htmlBody');

        plainTextBody.textContent = body.plain_text || '(No plain text content)';
        
        if (body.html) {
            // Create sandboxed iframe for HTML content
            htmlBody.innerHTML = `<iframe sandbox="allow-same-origin" style="width: 100%; height: 400px; border: none; border-radius: 8px;" srcdoc="${escapeHtml(body.html).replace(/"/g, '"')}"></iframe>`;
        } else {
            htmlBody.innerHTML = '<p style="color: var(--text-muted); padding: 1rem;">No HTML content available</p>';
        }
    }

    // Escape HTML
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Check AI Status
    async function checkAIStatus() {
        const statusText = apiStatus.querySelector('.status-text');
        
        try {
            const response = await fetch('/check-ai');
            const data = await response.json();
            
            aiAvailable = data.available;
            
            if (data.available) {
                apiStatus.className = 'api-status available';
                statusText.textContent = `AI Ready (${data.provider}: ${data.model || 'Cloud AI'})`;
            } else {
                apiStatus.className = 'api-status unavailable';
                let msg = 'AI Unavailable - Set ';
                if (!data.openrouter_configured && !data.ollama_configured) {
                    msg += 'OPENROUTER_API_KEY or OLLAMA_API_KEY';
                }
                statusText.textContent = msg;
            }
        } catch (error) {
            apiStatus.className = 'api-status error';
            statusText.textContent = 'Status check failed';
            console.error('Failed to check AI status:', error);
        }
    }
});
