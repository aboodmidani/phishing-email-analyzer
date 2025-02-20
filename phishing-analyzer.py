import os
import re
import email
import streamlit as st
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

def extract_email_metadata(email_file):
    with open(email_file, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    metadata = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Return-Path": msg.get("Return-Path"),
        "Received": msg.get_all("Received", []),
        "Links": extract_links(msg)
    }
    return metadata

def extract_links(msg):
    links = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/html", "text/plain"]:
                try:
                    content = part.get_payload(decode=True).decode(errors='ignore')
                    links.extend(re.findall(r"https?://[\w./?=&-]+", content))
                except Exception:
                    pass
    return links

def analyze_email(email_file):
    metadata = extract_email_metadata(email_file)

    score = 0
    suspicious_reasons = []

    sender_domain = extract_domain(metadata["From"])
    return_path_domain = extract_domain(metadata["Return-Path"])
    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        score += 2
        suspicious_reasons.append("Mismatch between From and Return-Path domains.")

    phishing_keywords = ["urgent", "verify", "update your account", "login", "payment required"]
    if metadata["Subject"] and any(word in metadata["Subject"].lower() for word in phishing_keywords):
        score += 2
        suspicious_reasons.append("Phishing keywords found in subject.")

    for link in metadata["Links"]:
        domain = extract_domain(link)
        if domain and (domain.endswith(".ru") or domain in ["bit.ly", "tinyurl.com"]):
            score += 3
            suspicious_reasons.append(f"Suspicious link detected: {link}")

    risk_level = "Low"
    if score >= 3:
        risk_level = "Medium"
    if score >= 5:
        risk_level = "High"

    return {"Score": score, "Risk Level": risk_level, "Reasons": suspicious_reasons}

def extract_domain(email_address_or_url):
    if email_address_or_url:
        match = re.search(r'@([\w.-]+)', email_address_or_url)
        if match:
            return match.group(1)
        parsed_url = urlparse(email_address_or_url)
        return parsed_url.netloc if parsed_url.netloc else None
    return None

# Streamlit UI
st.title("Phishing Email Analyzer")

uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])

if uploaded_file is not None:
    with open("temp_email.eml", "wb") as f:
        f.write(uploaded_file.getbuffer())

    result = analyze_email("temp_email.eml")
    
    st.write("## Analysis Result")
    st.json(result)
