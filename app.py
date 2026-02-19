"""
Phishing Email Analyzer - Flask Web Application
A comprehensive .eml file analyzer with AI-powered risk scoring
"""

import os
import re
import json
import hashlib
import requests
import unicodedata
import magic
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import traceback
from werkzeug.utils import secure_filename

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Security configuration
ALLOWED_EXTENSIONS = {'.eml'}
MAX_FILENAME_LENGTH = 255
MIN_FILE_SIZE = 100  # Minimum 100 bytes for a valid email
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max for .eml files

# AI API configuration - supports both OpenRouter and Ollama Cloud
# Set OPENROUTER_API_KEY for OpenRouter or OLLAMA_API_KEY for Ollama Cloud
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', '')
OLLAMA_API_KEY = os.environ.get('OLLAMA_API_KEY', '')

# API URLs
OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions'
OLLAMA_CLOUD_URL = os.environ.get('OLLAMA_CLOUD_URL', 'https://api.ollama.com/api/chat')

# Default models
OPENROUTER_MODEL = os.environ.get('OPENROUTER_MODEL', 'meta-llama/llama-3.1-8b-instruct:free')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'gpt-oss:120b-cloud')


class EMLParser:
    """Comprehensive EML file parser"""
    
    def __init__(self, eml_content):
        self.msg = BytesParser(policy=policy.default).parsebytes(eml_content)
        self.content = eml_content
        
    def get_all_headers(self):
        """Extract all email headers"""
        headers = []
        for key in self.msg.keys():
            value = self.msg.get(key)
            if value:
                headers.append({
                    'key': key,
                    'value': value
                })
        return headers
    
    def get_basic_info(self):
        """Extract basic email information"""
        from_addr = self.msg.get('From', '')
        to_addr = self.msg.get('To', '')
        cc_addr = self.msg.get('Cc', '')
        subject = self.msg.get('Subject', '')
        date_str = self.msg.get('Date', '')
        message_id = self.msg.get('Message-ID', '')
        reply_to = self.msg.get('Reply-To', '')
        return_path = self.msg.get('Return-Path', '')
        
        # Parse date
        formatted_date = ''
        if date_str:
            try:
                dt = parsedate_to_datetime(date_str)
                formatted_date = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
            except:
                formatted_date = date_str
        
        return {
            'from': from_addr,
            'to': to_addr,
            'cc': cc_addr,
            'subject': subject,
            'date': formatted_date,
            'message_id': message_id,
            'reply_to': reply_to,
            'return_path': return_path
        }
    
    def get_received_chain(self):
        """Parse Received headers to show email routing"""
        received_headers = self.msg.get_all('Received', [])
        chain = []
        
        for i, header in enumerate(received_headers):
            entry = {
                'hop': len(received_headers) - i,
                'raw': header,
                'from': '',
                'by': '',
                'with': '',
                'timestamp': ''
            }
            
            # Parse "from" part
            from_match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
            if from_match:
                entry['from'] = from_match.group(1)
            
            # Parse "by" part
            by_match = re.search(r'by\s+([^\s]+)', header, re.IGNORECASE)
            if by_match:
                entry['by'] = by_match.group(1)
            
            # Parse timestamp (usually at the end in parentheses or after semicolon)
            time_match = re.search(r';\s*(.+)$', header)
            if time_match:
                try:
                    dt = parsedate_to_datetime(time_match.group(1).strip())
                    entry['timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    entry['timestamp'] = time_match.group(1).strip()
            
            chain.append(entry)
        
        return chain
    
    def get_auth_results(self):
        """Extract authentication results (SPF, DKIM, DMARC)"""
        auth_results = {
            'spf': {'status': 'unknown', 'details': ''},
            'dkim': {'status': 'unknown', 'details': ''},
            'dmarc': {'status': 'unknown', 'details': ''}
        }
        
        # Check Authentication-Results header
        auth_header = self.msg.get('Authentication-Results', '')
        if auth_header:
            # SPF
            spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
            if spf_match:
                auth_results['spf']['status'] = spf_match.group(1).lower()
                auth_results['spf']['details'] = auth_header
            
            # DKIM
            dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
            if dkim_match:
                auth_results['dkim']['status'] = dkim_match.group(1).lower()
                auth_results['dkim']['details'] = auth_header
            
            # DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
            if dmarc_match:
                auth_results['dmarc']['status'] = dmarc_match.group(1).lower()
                auth_results['dmarc']['details'] = auth_header
        
        # Check Received-SPF header
        received_spf = self.msg.get('Received-SPF', '')
        if received_spf and auth_results['spf']['status'] == 'unknown':
            auth_results['spf']['status'] = received_spf.split()[0].lower() if received_spf else 'unknown'
            auth_results['spf']['details'] = received_spf
        
        # Check DKIM-Signature header presence
        dkim_sig = self.msg.get('DKIM-Signature', '')
        if dkim_sig and auth_results['dkim']['status'] == 'unknown':
            auth_results['dkim']['status'] = 'present'
            auth_results['dkim']['details'] = 'DKIM signature present (verification requires DNS lookup)'
        
        return auth_results
    
    def get_body(self):
        """Extract email body (plain text and HTML)"""
        plain_text = ''
        html_content = ''
        
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                # Skip attachments
                if 'attachment' in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        decoded = payload.decode(charset, errors='ignore')
                        
                        if content_type == 'text/plain' and not plain_text:
                            plain_text = decoded
                        elif content_type == 'text/html' and not html_content:
                            html_content = decoded
                except Exception as e:
                    pass
        else:
            try:
                payload = self.msg.get_payload(decode=True)
                if payload:
                    charset = self.msg.get_content_charset() or 'utf-8'
                    content = payload.decode(charset, errors='ignore')
                    if self.msg.get_content_type() == 'text/html':
                        html_content = content
                    else:
                        plain_text = content
            except:
                pass
        
        # Clean HTML for display
        clean_html = ''
        if html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            # Remove scripts and styles
            for script in soup(['script', 'style']):
                script.decompose()
            clean_html = str(soup)
        
        return {
            'plain_text': plain_text,
            'html': clean_html,
            'raw_html': html_content
        }
    
    def get_links(self):
        """Extract all links from email body"""
        links = []
        seen_urls = set()
        
        body = self.get_body()
        content = body['plain_text'] + ' ' + body['raw_html']
        
        # Find all URLs
        url_pattern = r'https?://[^\s<>"\']+'
        found_urls = re.findall(url_pattern, content)
        
        for url in found_urls:
            # Clean URL
            url = url.rstrip('.,;:)>\'"')
            if url in seen_urls:
                continue
            seen_urls.add(url)
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Check for suspicious patterns
            suspicious = self._is_suspicious_url(url, domain)
            
            links.append({
                'url': url,
                'domain': domain,
                'path': path if path else '/',
                'suspicious': suspicious['flag'],
                'reasons': suspicious['reasons']
            })
        
        return links
    
    def _is_suspicious_url(self, url, domain):
        """Check if URL is suspicious"""
        reasons = []
        flag = False
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'shorturl.at']
        if domain.lower() in shorteners:
            reasons.append('URL shortener')
            flag = True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.work', '.click']
        if any(domain.lower().endswith(tld) for tld in suspicious_tlds):
            reasons.append('Suspicious TLD')
            flag = True
        
        # Check for IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            reasons.append('IP address instead of domain')
            flag = True
        
        # Check for suspicious keywords in URL
        suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'banking', 'password', 'confirm']
        if any(kw in url.lower() for kw in suspicious_keywords):
            reasons.append('Contains suspicious keywords')
            flag = True
        
        # Check for encoded characters
        if '%' in url:
            reasons.append('Contains URL-encoded characters')
            flag = True
        
        return {'flag': flag, 'reasons': reasons}
    
    def get_attachments(self):
        """Extract attachment information"""
        attachments = []
        
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_disposition = str(part.get('Content-Disposition', ''))
                if 'attachment' in content_disposition or part.get_filename():
                    filename = part.get_filename() or 'Unknown'
                    content_type = part.get_content_type()
                    
                    try:
                        payload = part.get_payload(decode=True)
                        size = len(payload) if payload else 0
                        md5_hash = hashlib.md5(payload).hexdigest() if payload else ''
                        sha256_hash = hashlib.sha256(payload).hexdigest() if payload else ''
                    except:
                        size = 0
                        md5_hash = ''
                        sha256_hash = ''
                    
                    # Check for dangerous extensions
                    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.zip', '.rar']
                    is_dangerous = any(filename.lower().endswith(ext) for ext in dangerous_extensions)
                    
                    attachments.append({
                        'filename': filename,
                        'content_type': content_type,
                        'size': size,
                        'size_formatted': self._format_size(size),
                        'md5': md5_hash,
                        'sha256': sha256_hash,
                        'dangerous': is_dangerous
                    })
        
        return attachments
    
    def _format_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


class CloudAIAnalyzer:
    """AI-powered email analyzer supporting both OpenRouter and Ollama Cloud"""
    
    def __init__(self):
        # Prefer OpenRouter, fallback to Ollama Cloud
        if OPENROUTER_API_KEY:
            self.api_key = OPENROUTER_API_KEY
            self.model = OPENROUTER_MODEL
            self.api_url = OPENROUTER_API_URL
            self.provider = 'openrouter'
        elif OLLAMA_API_KEY:
            self.api_key = OLLAMA_API_KEY
            self.model = OLLAMA_MODEL
            self.api_url = OLLAMA_CLOUD_URL
            self.provider = 'ollama'
        else:
            self.api_key = None
            self.model = None
            self.api_url = None
            self.provider = None
    
    def is_available(self):
        """Check if any API key is configured"""
        return bool(self.api_key)
    
    def analyze_email(self, email_data):
        """Analyze email and return risk assessment with retry logic"""
        if not self.is_available():
            print("No API key configured")
            return None
        
        prompt = self._build_prompt(email_data)
        
        # Retry logic for transient failures
        max_retries = 3
        last_error = None
        
        for attempt in range(max_retries):
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                }
                
                # Add OpenRouter-specific headers
                if self.provider == 'openrouter':
                    headers["HTTP-Referer"] = "https://phishing-email-analyzer.local"
                    headers["X-Title"] = "Phishing Email Analyzer"
                
                payload = {
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": """You are a cybersecurity expert specializing in phishing email analysis. You MUST respond ONLY with valid JSON - no markdown, no code blocks, no explanations outside the JSON.

STRICT SCORING RUBRIC - Calculate the risk_score by adding these EXACT points:

AUTHENTICATION (Max 55 points):
- SPF = fail: +20 points
- SPF = softfail or unknown: +5 points
- DKIM = fail: +20 points
- DKIM = unknown: +5 points
- DMARC = fail: +15 points
- DMARC = unknown: +5 points

SENDER MANIPULATION (Max 35 points):
- Reply-To domain differs from From domain: +15 points
- Return-Path domain differs from From domain: +10 points
- Display name impersonates brand but different domain: +10 points

LINKS (Max 40 points):
- Each suspicious link: +8 points (max 24 points)
- URL shortener detected: +8 points
- IP address used in URL: +8 points

ATTACHMENTS (Max 30 points):
- Each dangerous attachment: +15 points (max 30 points)

CONTENT (Max 20 points):
- Urgency keywords ("act now", "immediate", "urgent", "limited time"): +5 points
- Requests for credentials/sensitive info: +10 points
- Generic greeting ("Dear Customer", "Dear User"): +5 points

RISK LEVELS (MUST match score range):
- 0-25: "Low"
- 26-50: "Medium"  
- 51-75: "High"
- 76-100: "Critical"

You MUST:
1. Calculate score using the rubric above
2. Assign risk_level based on the score range
3. List each indicator found with its point value
4. Provide specific, actionable recommendations

Response format (JSON only):
{"risk_score": <number>, "risk_level": "<Low|Medium|High|Critical>", "summary": "<summary>", "indicators": ["<indicator>"], "recommendations": ["<recommendation>"]}"""
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0,  # Zero temperature for consistent, deterministic output
                    "seed": 42,  # Fixed seed for reproducibility
                    "stream": False  # Required for Ollama Cloud to return single JSON
                }
                
                print(f"Calling {self.provider} API with model {self.model} (attempt {attempt + 1}/{max_retries})")
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                    timeout=90  # Increased timeout for complex analysis
                )
                
                print(f"API Response Status: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    # Handle different API response formats
                    if self.provider == 'ollama':
                        # Ollama Cloud returns: {"message": {"content": "..."}}
                        content = result.get('message', {}).get('content', '')
                    else:
                        # OpenRouter returns: {"choices": [{"message": {"content": "..."}}]}
                        content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                    print(f"AI Response: {content[:200]}...")
                    return self._parse_response(content)
                elif response.status_code in [429, 502, 503, 504]:
                    # Retryable errors (rate limit, gateway issues)
                    last_error = f"Retryable error: {response.status_code}"
                    print(f"Retrying due to: {last_error}")
                    import time
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    print(f"API error: {response.status_code} - {response.text}")
                    return None
                    
            except requests.exceptions.Timeout:
                last_error = "Request timeout"
                print(f"Timeout on attempt {attempt + 1}, retrying...")
                continue
            except Exception as e:
                print(f"Cloud AI error: {e}")
                import traceback
                traceback.print_exc()
                last_error = str(e)
                continue
        
        print(f"All retry attempts failed. Last error: {last_error}")
        return None
    
    def _build_prompt(self, email_data):
        """Build comprehensive analysis prompt with improved data extraction"""
        basic_info = email_data.get('basic_info', {})
        links = email_data.get('links', [])
        attachments = email_data.get('attachments', [])
        auth = email_data.get('auth_results', {})
        body = email_data.get('body', {})
        headers = email_data.get('headers', [])
        received_chain = email_data.get('received_chain', [])
        
        # Extract key security headers
        security_headers = self._extract_security_headers(headers)
        
        # Build enhanced links analysis
        links_analysis = self._build_links_analysis(links)
        
        # Build attachments analysis
        attachments_analysis = "No attachments"
        if attachments:
            attachments_analysis = '\n'.join([
                f"- {a['filename']} | Type: {a['content_type']} | Size: {a['size_formatted']} | Dangerous: {a['dangerous']}"
                for a in attachments
            ])
        
        # Build body preview with smart truncation (increased to 2500 chars)
        body_preview = self._extract_body_preview(body, max_length=2500)
        
        # Build received chain summary (first 5 hops)
        chain_summary = self._build_chain_summary(received_chain[:5])
        
        # Analyze sender domains
        sender_analysis = self._analyze_sender_domains(basic_info)
        
        prompt = f"""Analyze this email for phishing indicators and provide a comprehensive risk assessment.

═══════════════════════════════════════════════════════════════
EMAIL METADATA
═══════════════════════════════════════════════════════════════
From: {basic_info.get('from', 'N/A')}
To: {basic_info.get('to', 'N/A')}
Cc: {basic_info.get('cc', 'N/A')}
Subject: {basic_info.get('subject', 'N/A')}
Date: {basic_info.get('date', 'N/A')}
Message-ID: {basic_info.get('message_id', 'N/A')}
Return-Path: {basic_info.get('return_path', 'N/A')}
Reply-To: {basic_info.get('reply_to', 'N/A')}

SENDER DOMAIN ANALYSIS:
{sender_analysis}

═══════════════════════════════════════════════════════════════
AUTHENTICATION RESULTS
═══════════════════════════════════════════════════════════════
SPF: {auth.get('spf', {}).get('status', 'unknown').upper()}
DKIM: {auth.get('dkim', {}).get('status', 'unknown').upper()}
DMARC: {auth.get('dmarc', {}).get('status', 'unknown').upper()}
Auth Details: {auth.get('spf', {}).get('details', 'N/A')[:200] if auth.get('spf', {}).get('details') else 'N/A'}

═══════════════════════════════════════════════════════════════
EMAIL ROUTING (First 5 Hops)
═══════════════════════════════════════════════════════════════
{chain_summary}

═══════════════════════════════════════════════════════════════
SECURITY HEADERS
═══════════════════════════════════════════════════════════════
{security_headers}

═══════════════════════════════════════════════════════════════
LINKS ANALYSIS ({len(links)} links found)
═══════════════════════════════════════════════════════════════
{links_analysis}

═══════════════════════════════════════════════════════════════
ATTACHMENTS ({len(attachments)} found)
═══════════════════════════════════════════════════════════════
{attachments_analysis}

═══════════════════════════════════════════════════════════════
EMAIL BODY PREVIEW
═══════════════════════════════════════════════════════════════
{body_preview}

═══════════════════════════════════════════════════════════════
ANALYSIS INSTRUCTIONS
═══════════════════════════════════════════════════════════════
Based on all the above data, provide a comprehensive phishing analysis.

Respond ONLY with valid JSON in this exact format (no markdown, no code blocks):
{{
    "risk_score": <number 0-100>,
    "risk_level": "<Low|Medium|High|Critical>",
    "summary": "<Brief 2-3 sentence summary explaining the key findings>",
    "indicators": ["<specific indicator 1>", "<specific indicator 2>"],
    "recommendations": ["<actionable recommendation 1>", "<actionable recommendation 2>"]
}}"""
        
        return prompt
    
    def _extract_security_headers(self, headers):
        """Extract security-relevant headers"""
        security_headers = {}
        important_headers = [
            'X-Originating-IP', 'X-Sender-IP', 'X-Spam-Status', 'X-Spam-Score',
            'X-Spam-Flag', 'X-Priority', 'X-MS-Exchange-Organization-SCL',
            'X-Forefront-Antispam-Report', 'List-Id', 'List-Unsubscribe',
            'X-Mailer', 'User-Agent', 'X-Google-Smtp-Source', 'X-Gm-Message-State',
            'Received-SPF', 'Authentication-Results', 'X-Auto-Response-Suppress'
        ]
        
        for header in headers:
            key = header.get('key', '')
            if key in important_headers:
                value = header.get('value', '')
                # Truncate long values
                if len(value) > 150:
                    value = value[:150] + '...'
                security_headers[key] = value
        
        if not security_headers:
            return "No security-specific headers found"
        
        return '\n'.join([f"- {k}: {v}" for k, v in security_headers.items()])
    
    def _build_links_analysis(self, links):
        """Build detailed links analysis"""
        if not links:
            return "No links found in email body"
        
        suspicious_count = sum(1 for l in links if l.get('suspicious'))
        
        lines = [f"Total: {len(links)} links | Suspicious: {suspicious_count}\n"]
        
        for i, link in enumerate(links[:15], 1):  # Limit to 15 links
            status = "⚠️ SUSPICIOUS" if link.get('suspicious') else "✓ OK"
            reasons = ', '.join(link.get('reasons', [])) or 'None'
            lines.append(f"{i}. {link['url']}")
            lines.append(f"   Domain: {link['domain']} | Status: {status}")
            if link.get('suspicious'):
                lines.append(f"   Reasons: {reasons}")
        
        if len(links) > 15:
            lines.append(f"\n... and {len(links) - 15} more links")
        
        return '\n'.join(lines)
    
    def _extract_body_preview(self, body, max_length=2500):
        """Extract body preview with smart truncation"""
        plain_text = body.get('plain_text', '')
        html = body.get('html', '')
        
        # Prefer plain text, fall back to stripped HTML
        if plain_text:
            text = plain_text
        elif html:
            # Strip HTML tags for preview
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
        else:
            return "No email body content found"
        
        # Smart truncation - try to end at sentence
        text = text.strip()
        if len(text) <= max_length:
            return text
        
        truncated = text[:max_length]
        # Try to find last complete sentence
        last_period = truncated.rfind('.')
        last_question = truncated.rfind('?')
        last_exclaim = truncated.rfind('!')
        last_sentence_end = max(last_period, last_question, last_exclaim)
        
        if last_sentence_end > max_length * 0.7:
            truncated = truncated[:last_sentence_end + 1]
        
        return truncated + "\n\n[Content truncated for analysis...]"
    
    def _build_chain_summary(self, received_chain):
        """Build readable summary of received chain"""
        if not received_chain:
            return "No received chain information available"
        
        lines = []
        for hop in received_chain:
            hop_num = hop.get('hop', '?')
            from_server = hop.get('from', 'unknown')
            by_server = hop.get('by', 'unknown')
            timestamp = hop.get('timestamp', 'unknown')
            
            lines.append(f"Hop {hop_num}: {from_server} → {by_server} ({timestamp})")
        
        return '\n'.join(lines)
    
    def _analyze_sender_domains(self, basic_info):
        """Analyze sender domains for inconsistencies"""
        from_addr = basic_info.get('from', '')
        return_path = basic_info.get('return_path', '')
        reply_to = basic_info.get('reply_to', '')
        
        from_domain = extract_domain(from_addr)
        return_path_domain = extract_domain(return_path)
        reply_to_domain = extract_domain(reply_to)
        
        analysis_lines = []
        
        # Check for display name spoofing
        if '<' in from_addr and '>' in from_addr:
            display_name = from_addr.split('<')[0].strip().strip('"')
            actual_email = from_addr.split('<')[1].split('>')[0]
            actual_domain = extract_domain(actual_email)
            if display_name and actual_domain:
                analysis_lines.append(f"Display Name: '{display_name}' vs Domain: @{actual_domain}")
                # Check for domain impersonation in display name
                common_brands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'bank', 'facebook', 'twitter', 'linkedin']
                for brand in common_brands:
                    if brand in display_name.lower() and brand not in actual_domain.lower():
                        analysis_lines.append(f"⚠️ WARNING: Display name mentions '{brand}' but domain is different!")
        
        analysis_lines.append(f"From Domain: {from_domain or 'N/A'}")
        
        if return_path_domain:
            if return_path_domain != from_domain:
                analysis_lines.append(f"⚠️ Return-Path Domain: {return_path_domain} (DIFFERS from From domain)")
            else:
                analysis_lines.append(f"Return-Path Domain: {return_path_domain} (matches)")
        
        if reply_to_domain:
            if reply_to_domain != from_domain:
                analysis_lines.append(f"⚠️ Reply-To Domain: {reply_to_domain} (DIFFERS from From domain)")
            else:
                analysis_lines.append(f"Reply-To Domain: {reply_to_domain} (matches)")
        
        return '\n'.join(analysis_lines)
    
    def _parse_response(self, response_text):
        """Parse AI response"""
        try:
            # Clean the response - remove markdown code blocks if present
            cleaned = response_text.strip()
            if cleaned.startswith('```'):
                # Remove markdown code blocks
                lines = cleaned.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                cleaned = '\n'.join(lines)
            
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', cleaned)
            if json_match:
                result = json.loads(json_match.group())
                # Validate required fields
                required_fields = ['risk_score', 'risk_level', 'summary', 'indicators', 'recommendations']
                if all(field in result for field in required_fields):
                    return result
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
        except Exception as e:
            print(f"Parse error: {e}")
        
        # Return default if parsing fails
        return {
            'risk_score': 50,
            'risk_level': 'Medium',
            'summary': 'AI analysis completed but response parsing failed. Manual review recommended.',
            'indicators': ['Unable to parse detailed AI indicators - manual review required'],
            'recommendations': ['Review email manually', 'Verify sender through alternative channels']
        }


def rule_based_analysis(email_data):
    """Fallback rule-based analysis when AI is not available"""
    score = 0
    indicators = []
    
    basic_info = email_data.get('basic_info', {})
    links = email_data.get('links', [])
    attachments = email_data.get('attachments', [])
    auth = email_data.get('auth_results', {})
    
    # Check domain mismatch
    from_domain = extract_domain(basic_info.get('from', ''))
    return_path_domain = extract_domain(basic_info.get('return_path', ''))
    reply_to_domain = extract_domain(basic_info.get('reply_to', ''))
    
    if from_domain and return_path_domain and from_domain != return_path_domain:
        score += 15
        indicators.append(f"Domain mismatch: From domain ({from_domain}) differs from Return-Path ({return_path_domain})")
    
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        score += 10
        indicators.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})")
    
    # Check authentication
    if auth.get('spf', {}).get('status') == 'fail':
        score += 20
        indicators.append("SPF authentication failed")
    elif auth.get('spf', {}).get('status') == 'unknown':
        score += 5
        indicators.append("SPF status unknown")
    
    if auth.get('dkim', {}).get('status') == 'fail':
        score += 20
        indicators.append("DKIM authentication failed")
    
    if auth.get('dmarc', {}).get('status') == 'fail':
        score += 15
        indicators.append("DMARC authentication failed")
    
    # Check subject for phishing keywords
    subject = basic_info.get('subject', '').lower()
    phishing_keywords = ['urgent', 'verify', 'update your account', 'login', 'password', 
                        'confirm', 'suspended', 'unusual activity', 'security alert',
                        'click here', 'act now', 'limited time', 'winner']
    found_keywords = [kw for kw in phishing_keywords if kw in subject]
    if found_keywords:
        score += 10
        indicators.append(f"Phishing keywords in subject: {', '.join(found_keywords)}")
    
    # Check links
    suspicious_links = [l for l in links if l.get('suspicious')]
    if suspicious_links:
        score += min(len(suspicious_links) * 10, 30)
        indicators.append(f"{len(suspicious_links)} suspicious link(s) detected")
    
    # Check attachments
    dangerous_attachments = [a for a in attachments if a.get('dangerous')]
    if dangerous_attachments:
        score += min(len(dangerous_attachments) * 15, 30)
        indicators.append(f"{len(dangerous_attachments)} potentially dangerous attachment(s)")
    
    # Determine risk level
    if score >= 70:
        risk_level = 'Critical'
    elif score >= 50:
        risk_level = 'High'
    elif score >= 25:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    
    return {
        'risk_score': min(score, 100),
        'risk_level': risk_level,
        'summary': f"Rule-based analysis completed. Risk score: {min(score, 100)}/100",
        'indicators': indicators if indicators else ['No significant phishing indicators detected'],
        'recommendations': [
            'Verify sender identity through alternative channels',
            'Do not click on suspicious links',
            'Report suspicious emails to your security team'
        ]
    }


def extract_domain(email_address):
    """Extract domain from email address"""
    if not email_address:
        return None
    match = re.search(r'@([\w.-]+)', email_address)
    if match:
        return match.group(1).lower()
    return None


# File Security Validation Functions
def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and other attacks"""
    if not filename:
        return 'unknown.eml'
    
    # Use werkzeug's secure_filename as base
    safe_name = secure_filename(filename)
    
    # Remove any remaining dangerous characters
    safe_name = re.sub(r'[^\w\-_\.]', '_', safe_name)
    
    # Remove null bytes and unicode control characters
    safe_name = ''.join(char for char in safe_name if ord(char) > 31)
    
    # Normalize unicode characters
    safe_name = unicodedata.normalize('NFKD', safe_name)
    
    # Limit length
    if len(safe_name) > MAX_FILENAME_LENGTH:
        # Preserve extension
        name_part = safe_name[:-4][:MAX_FILENAME_LENGTH - 4]
        safe_name = name_part + '.eml'
    
    # Ensure it still has .eml extension
    if not safe_name.lower().endswith('.eml'):
        safe_name = safe_name + '.eml'
    
    return safe_name


def validate_file_extension(filename):
    """Validate file extension"""
    if not filename:
        return False, "No filename provided"
    
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File extension '{ext}' is not allowed. Only .eml files are accepted."
    
    return True, None


def validate_mime_type(file_content):
    """Validate MIME type using magic bytes"""
    try:
        mime = magic.Magic(mime=True)
        detected_type = mime.from_buffer(file_content[:1024])
        
        # EML files are typically text/plain or message/rfc822
        allowed_mimes = [
            'text/plain',
            'message/rfc822',
            'application/octet-stream',  # Sometimes detected for .eml
            'text/html'  # Some email clients export as HTML
        ]
        
        if detected_type not in allowed_mimes:
            return False, f"Invalid file type detected: {detected_type}. Only email files are allowed."
        
        return True, None
    except Exception as e:
        # If magic library fails, continue with other validations
        print(f"MIME type detection warning: {e}")
        return True, None


def validate_email_structure(file_content):
    """Validate that the content is actually an email file"""
    if len(file_content) < MIN_FILE_SIZE:
        return False, f"File too small. Minimum size is {MIN_FILE_SIZE} bytes."
    
    # Check for common email headers in the first 2048 bytes
    header_preview = file_content[:2048].decode('utf-8', errors='ignore')
    
    # Required email headers (at least one should be present)
    email_headers = [
        'From:', 'To:', 'Subject:', 'Date:', 'Received:', 
        'Message-ID:', 'Return-Path:', 'DKIM-Signature:',
        'Content-Type:', 'MIME-Version:'
    ]
    
    found_headers = sum(1 for header in email_headers if header in header_preview)
    
    if found_headers < 2:
        return False, "File does not appear to be a valid email. Required email headers not found."
    
    # Try to parse with email parser
    try:
        test_parser = BytesParser(policy=policy.default).parsebytes(file_content)
        # Check if parser found any headers
        if len(list(test_parser.keys())) < 2:
            return False, "File structure is not valid email format."
    except Exception as e:
        return False, f"File cannot be parsed as email: {str(e)}"
    
    return True, None


def validate_file_content(file_content):
    """Check for malicious content patterns"""
    # Check for embedded executable signatures
    executable_signatures = [
        b'MZ',           # DOS/PE executable
        b'\x7fELF',      # Linux ELF
        b'\xca\xfe\xba\xbe',  # Java class
        b'PK\x03\x04',   # ZIP/JAR (could contain malware)
        b'Rar!',         # RAR archive
        b'\x1f\x8b',     # GZIP
    ]
    
    # Only check if file starts with these (embedded in email is fine)
    file_start = file_content[:4]
    for sig in executable_signatures:
        if file_start.startswith(sig):
            return False, "File appears to be an executable, not an email file."
    
    return True, None


def validate_file_size(file_content):
    """Validate file size constraints"""
    size = len(file_content)
    
    if size < MIN_FILE_SIZE:
        return False, f"File too small ({size} bytes). Minimum size is {MIN_FILE_SIZE} bytes."
    
    if size > MAX_FILE_SIZE:
        return False, f"File too large ({size} bytes). Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB."
    
    return True, None


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # Check if file was selected
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Sanitize filename (prevent path traversal attacks)
    safe_filename = sanitize_filename(file.filename)
    
    # Validate file extension
    ext_valid, ext_error = validate_file_extension(safe_filename)
    if not ext_valid:
        return jsonify({'error': ext_error}), 400
    
    # Read file content
    try:
        content = file.read()
    except Exception as e:
        return jsonify({'error': 'Failed to read file'}), 400
    
    # Validate file size
    size_valid, size_error = validate_file_size(content)
    if not size_valid:
        return jsonify({'error': size_error}), 400
    
    # Validate MIME type (magic bytes check)
    mime_valid, mime_error = validate_mime_type(content)
    if not mime_valid:
        return jsonify({'error': mime_error}), 400
    
    # Validate file content (check for executables)
    content_valid, content_error = validate_file_content(content)
    if not content_valid:
        return jsonify({'error': content_error}), 400
    
    # Validate email structure (check for valid email headers)
    email_valid, email_error = validate_email_structure(content)
    if not email_valid:
        return jsonify({'error': email_error}), 400
    
    # All validations passed - parse the email
    try:
        parser = EMLParser(content)
        
        email_data = {
            'basic_info': parser.get_basic_info(),
            'headers': parser.get_all_headers(),
            'received_chain': parser.get_received_chain(),
            'auth_results': parser.get_auth_results(),
            'body': parser.get_body(),
            'links': parser.get_links(),
            'attachments': parser.get_attachments()
        }
        
        # Try AI analysis first
        analyzer = CloudAIAnalyzer()
        ai_result = analyzer.analyze_email(email_data)
        
        if ai_result:
            email_data['ai_analysis'] = ai_result
            email_data['analysis_method'] = 'ai'
        else:
            # Fallback to rule-based
            email_data['ai_analysis'] = rule_based_analysis(email_data)
            email_data['analysis_method'] = 'rule-based'
            email_data['ai_unavailable'] = True
        
        return jsonify(email_data)
    
    except Exception as e:
        return jsonify({'error': f'Error parsing email: {str(e)}'}), 500


@app.route('/check-ai')
def check_ai():
    """Check if AI service is configured and available"""
    analyzer = CloudAIAnalyzer()
    return jsonify({
        'available': analyzer.is_available(),
        'provider': analyzer.provider,
        'model': analyzer.model,
        'openrouter_configured': bool(OPENROUTER_API_KEY),
        'ollama_configured': bool(OLLAMA_API_KEY)
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))