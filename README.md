# 🛡️ Cybersecurity Tools

This repository contains two cybersecurity tools:

**Phishing Email Analyzer** - A tool that analyzes email headers and content to detect potential phishing attempts.

Demo: https://phishing-email-analyzer.streamlit.app/

---

## 📧 Phishing Email Analyzer

### 📌 About
Phishing Email Analyzer helps detect phishing emails by analyzing their metadata and content. It scans for suspicious links, domain mismatches, and common phishing keywords.

### 🚀 Features
✅ Analyzes email headers and extracts metadata  
✅ Detects suspicious links and phishing keywords  
✅ Calculates a risk score and categorizes emails as Low, Medium, or High risk  

### 🔧 Installation
Install required dependencies:
```sh
pip install streamlit
```

### ▶️ Usage
Run the Streamlit app:
```sh
streamlit run phishing_analyzer.py
```

Upload an **.eml** file to analyze phishing risks.

### 🛠️ How It Works
- Extracts email headers (From, Return-Path, etc.).
- Analyzes email body content for suspicious words and links.
- Assigns a risk score and provides a security recommendation.

---

## 🔗 Contributing
Feel free to submit **issues** or **pull requests** if you'd like to improve these tools!

## 📜 License
This project is licensed under the **MIT License**.
