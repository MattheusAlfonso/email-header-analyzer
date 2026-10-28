[ 🇺🇸 English ](README.md) | [ 🇪🇸 Español ](README.es.md) | [ 🇧🇷 Português ](README.pt.md)

---

# 🛡️ Phishing & Email Header Security Analyzer (PHP/HTML5)

A lightweight Cybersec / Threat Intel web tool built in PHP and HTML5 that parses raw email headers, extracts Indicators of Compromise (IoCs), evaluates SPF/DKIM/DMARC authentication states, and calculates a risk score for phishing detection.

![Project Preview](preview.png)

## 🎯 Purpose & Scope
Inspired by real-world corporate incident response workflows (such as email triage and social engineering mitigation at ALEGO), this application automates raw header parsing using regular expressions (Regex) to detect email spoofing and suspicious origin IPs.

## 🛡️ Security & Analysis Features
* **Regex Header Parsing:** Extracts `From:`, `Return-Path:`, origin `IP` address, and authentication flags (`spf=`, `dkim=`, `dmarc=`).
* **Domain Mismatch Detection:** Identifies divergences between the `From` domain and the `Return-Path` domain (indicative of spoofing).
* **Risk Scoring Engine:** Evaluates SPF/DKIM failures and domain mismatches to categorize threat levels (**LOW**, **MEDIUM**, **HIGH**).
* **Input Sanitization:** Applies `htmlspecialchars()` and `trim()` to prevent Reflected XSS from untrusted header payloads.

---
*Developed as part of the Cybersecurity Portfolio for international software & threat analysis roles.*