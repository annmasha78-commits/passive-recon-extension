# passive-recon-extension
A high-performance Chrome Extension (Manifest V3) for automated passive web reconnaissance, header analysis, and PDF security report generation
# 🔍 Passive Recon Pro - Web Reconnaissance Browser Extension

![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Category](https://img.shields.io/badge/Category-Cybersecurity%20%26%20Bug%20Bounty-orange.svg)

**Passive Recon Pro** is a lightweight, high-performance Chrome Extension designed for ethical hackers, penetration testers, and bug bounty hunters. It passively intercepts network traffic, analyzes HTTP headers, detects underlying technologies, and generates comprehensive **PDF/Visual Reports** without sending intrusive payloads to the target.

---

## ✨ Key Features

* **⚡ Passive Interception:** Automatically monitors network traffic and HTTP headers in real-time via Manifest V3 Service Workers.
* **🛡️ Security Header Analysis:** Instantly flags missing or misconfigured headers (e.g., CSP, HSTS, X-Frame-Options, CORS).
* **📊 Visual Analytics Dashboard:** Displays endpoint distribution and security findings using dynamic `Chart.js` graphs.
* **📄 Automated PDF Reporting:** Export professional, client-ready PDF assessment reports using embedded `jsPDF` and `AutoTable` engines.
* **⚙️ Custom Recon Rules:** Configurable detection rules via `options.js` and declarative network rulesets.

---

## 🛠️ Tech Stack & Dependencies

* **Core:** JavaScript (ES6+), HTML5, CSS3
* **Extension Standard:** Chrome Extension Manifest V3
* **Libraries Integrated:**
  * `Chart.js` (Visual Data Representations)
  * `jsPDF` & `jspdf.plugin.autotable` (Client-side PDF Generation)

---

## 🚀 Installation & Manual Loading

Since this extension is in active development, you can load it directly into any Chromium-based browser (Chrome, Edge, Brave):

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/passive-recon-pro.git](https://github.com/YOUR_USERNAME/passive-recon-pro.git)
