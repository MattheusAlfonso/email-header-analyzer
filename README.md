[ 🇺🇸 English ](README.md) | [ 🇪🇸 Español ](README.es.md) | [ 🇧🇷 Português ](README.pt.md)

---

# Phishing & Email Header Analyzer (PHP)

![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?logo=php&logoColor=white)
![Topic](https://img.shields.io/badge/topic-Phishing%20Triage-orange)
![Focus](https://img.shields.io/badge/focus-Email%20Security-0284c7)

A triage tool for suspicious e-mails: paste the raw headers and get the sender indicators, SPF / DKIM / DMARC results, domain-alignment checks and a 0–100 risk score with an explanation for every point.

It comes from my day-to-day work in security awareness and phishing prevention: it turns "this e-mail looks weird" into concrete, explainable evidence.

![Analyzer Preview](preview.png)

## What it checks

| Indicator | Why it matters | Points |
|---|---|---|
| `DMARC=fail` | The `From` domain failed its owner's own policy. Strongest spoofing signal. | +30 |
| `SPF=fail` | The sending IP is not authorized by the domain | +25 |
| `SPF=softfail / none / permerror` | Weak or missing sender authorization | +15 |
| `DKIM=fail` | Signature does not match: message altered or forged | +25 |
| `DKIM=none / permerror` | Message is not signed | +10 |
| `Reply-To` domain ≠ `From` domain | Replies are diverted to the attacker. Classic BEC / phishing tactic. | +20 |
| `Return-Path` domain ≠ `From` domain | Possible spoofing. Lower weight: legitimate newsletters (SendGrid, Mailchimp…) also do this. | +15 |

Score ≥ 60 → **HIGH**, ≥ 30 → **MEDIUM**, otherwise **LOW**. Subdomains of the same domain (`mail.company.com` / `company.com`) are treated as aligned.

## Parsing decisions

- **Only the top `Authentication-Results` header is trusted.** It is added by *your* mail server. An attacker can write `spf=pass` anywhere else in the headers they control.
- **Headers are matched at the start of the line** (`^From:`), so `X-Original-From:` is not mistaken for `From:`.
- **Folded headers are unfolded** (RFC 5322): long values continued on the next line are parsed correctly.
- **Origin IP** = the IPv4 address in the **last** `Received` header, since each server adds its own line at the top.
- **Input is parsed raw and escaped only on output.** An earlier version escaped before parsing, which broke the regexes and showed `&lt;` on screen.

## Security of the tool itself

The tool processes attacker-controlled text, so it is hardened too: every value is HTML-encoded on output, input is capped at 64 KB, and a strict Content-Security-Policy blocks any script that might slip through.

## Try it

```text
Return-Path: <billing@secure-pay-update.ru>
Authentication-Results: mx.company.com;
       spf=fail smtp.mailfrom=secure-pay-update.ru;
       dkim=none;
       dmarc=fail header.from=paypal.com
Received: from mail.secure-pay-update.ru ([185.220.101.4])
From: "PayPal" <service@paypal.com>
Reply-To: support@secure-pay-update.ru
Subject: Your account has been limited
```

Expected result: **HIGH** risk (score 100), with SPF, DKIM, DMARC, Reply-To and Return-Path flags.

## How to run

Requirements: PHP 8.0+.

```bash
git clone https://github.com/MattheusAlfonso/email-header-analyzer.git
cd email-header-analyzer
php -S localhost:8000
```

Open <http://localhost:8000>.

## Roadmap

- [ ] Extract URLs from the body and check them against threat-intel feeds (VirusTotal, URLhaus)
- [ ] IPv6 and private-IP detection in `Received` hops
- [ ] Look-alike domain detection (`paypa1.com`, punycode)
- [ ] Upload `.eml` files directly

---
*Part of my [cybersecurity portfolio](https://mattheusalfonso.github.io).*
