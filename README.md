# 🛡️ Phishing Email Analyzer

A comprehensive .eml file analyzer with AI-powered risk scoring. Built with Flask for deployment on Render.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **📧 Full EML Parsing** - Extracts all email headers, body content, and attachments
- **🔗 Link Analysis** - Detects suspicious URLs, URL shorteners, and dangerous TLDs
- **🔐 Authentication Check** - Validates SPF, DKIM, and DMARC status
- **🛤️ Received Chain** - Shows the email routing path hop-by-hop
- **📎 Attachment Analysis** - Lists attachments with hashes and danger flags
- **🤖 AI-Powered Scoring** - Uses cloud AI for intelligent risk assessment
- **📊 Visual Dashboard** - Beautiful dark-themed UI with animated risk gauge
- **🚀 Render Ready** - Configured for easy deployment on Render

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- API key from OpenRouter or Ollama Cloud

### Installation

1. Clone the repository:
```bash
git clone https://github.com/aboodmidani/phishing-email-analyzer.git
cd phishing-email-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

> **Note for Linux users:** The `python-magic` library requires `libmagic`:
> ```bash
> sudo apt-get install libmagic1  # Debian/Ubuntu
> sudo dnf install file-devel     # Fedora
> sudo pacman -S file             # Arch Linux
> ```
>
> **Note for macOS users:**
> ```bash
> brew install libmagic
> ```

3. Set your API key (choose one):
```bash
# Option 1: OpenRouter (recommended - has free tier)
export OPENROUTER_API_KEY="your-openrouter-api-key"

# Option 2: Ollama Cloud
export OLLAMA_API_KEY="your-ollama-cloud-api-key"
```

4. Run the application:
```bash
python app.py
```

5. Open http://localhost:5000 in your browser

## 🤖 AI Integration

The app supports two cloud AI providers:

### Option 1: OpenRouter (Recommended)

OpenRouter provides access to many AI models with a free tier.

1. Go to [OpenRouter](https://openrouter.ai/)
2. Sign up for a free account
3. Navigate to [Keys](https://openrouter.ai/keys) and create a new API key
4. Set the API key:
   ```bash
   export OPENROUTER_API_KEY="sk-or-v1-xxxxx"
   ```

**Free Models Available:**
- `meta-llama/llama-3.1-8b-instruct:free` (default)
- `google/gemma-2-9b-it:free`
- `mistralai/mistral-7b-instruct:free`

### Option 2: Ollama Cloud

Ollama Cloud provides managed Ollama infrastructure.

1. Go to [Ollama Cloud](https://ollama.com/cloud)
2. Sign up and get your API key
3. Set the API key:
   ```bash
   export OLLAMA_API_KEY="your-ollama-key"
   ```

### Fallback Mode

If no API key is configured, the app automatically uses rule-based analysis which checks:
- Domain mismatches (From vs Return-Path vs Reply-To)
- SPF/DKIM/DMARC authentication failures
- Phishing keywords in subject
- Suspicious links
- Dangerous attachments

## 🔧 Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENROUTER_API_KEY` | `""` | OpenRouter API key |
| `OLLAMA_API_KEY` | `""` | Ollama Cloud API key |
| `OPENROUTER_MODEL` | `meta-llama/llama-3.1-8b-instruct:free` | OpenRouter model |
| `OLLAMA_MODEL` | `llama3.1` | Ollama model |
| `PORT` | `5000` | Server port |

## 🌐 Deploy on Render

1. Push your code to GitHub

2. Create a new Web Service on Render

3. Connect your GitHub repository

4. Set environment variables:
   - `OPENROUTER_API_KEY` - Your OpenRouter API key (recommended)
   - Or `OLLAMA_API_KEY` - Your Ollama Cloud API key

5. Deploy!

## 📋 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web interface |
| `/analyze` | POST | Upload and analyze .eml file |
| `/check-ai` | GET | Check AI service status |

### Example API Usage

```bash
curl -X POST -F "file=@email.eml" http://localhost:5000/analyze
```

## 📁 Project Structure

```
phishing-email-analyzer/
├── app.py                 # Flask application with EML parser & AI analyzer
├── requirements.txt       # Python dependencies
├── render.yaml           # Render deployment config
├── templates/
│   └── index.html        # Main HTML template
├── static/
│   ├── css/
│   │   └── style.css     # Dark cybersecurity theme
│   └── js/
│       └── app.js        # Frontend JavaScript
└── README.md
```

## 🔒 Security Features

### File Upload Security

The application implements multiple layers of security to prevent malicious file uploads:

- **Filename Sanitization** - Removes path traversal characters, null bytes, and dangerous characters
- **Extension Validation** - Only `.eml` files are accepted
- **MIME Type Detection** - Uses magic bytes to verify actual file type
- **Executable Detection** - Blocks files starting with executable signatures (PE, ELF, Java, ZIP, RAR)
- **Email Structure Validation** - Verifies file contains valid email headers and can be parsed
- **File Size Limits** - Minimum 100 bytes, maximum 10MB

### Phishing Detection

The analyzer checks for multiple phishing indicators:

### Email Authentication
- **SPF** (Sender Policy Framework) validation
- **DKIM** (DomainKeys Identified Mail) signature presence
- **DMARC** (Domain-based Message Authentication) policy

### Link Analysis
- URL shortener detection (bit.ly, tinyurl, etc.)
- Suspicious TLD detection (.ru, .cn, .tk, etc.)
- IP address URLs (http://192.168.1.1/...)
- Suspicious keywords in URLs (login, verify, password, etc.)
- URL-encoded characters

### Attachment Analysis
- Dangerous file extensions (.exe, .scr, .bat, .ps1, .vbs, .js, .jar)
- File hash calculation (MD5, SHA256)

### Content Analysis
- Phishing keywords in subject
- Domain mismatch detection
- Reply-To vs From domain comparison

### AI Analysis
- Consistent scoring with strict rubric (temperature=0, fixed seed)
- 10-category phishing indicator checklist
- Risk levels: Low (0-25), Medium (26-50), High (51-75), Critical (76-100)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OpenRouter](https://openrouter.ai/) for cloud AI access
- [Ollama](https://ollama.com/) for local and cloud AI
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing