# SecCheckAI - AI-Powered Security Analysis Platform

**My Cloud and DevOps Project 2026**

SecCheckAI is an intelligent security analysis platform that uses AI to detect vulnerabilities, assess risk levels, and provide actionable recommendations for websites and applications.

---

## 🎯 Problem Statement

Small businesses and developers often lack access to comprehensive security tools. Security breaches cost billions annually, yet many organizations don't know where to start with security analysis.

SecCheck AI solves this by providing an easy-to-use, AI-powered platform that anyone can use to identify security threats and get clear recommendations.

---

## ✨ Features

### Core Features
- 🔐 **User Authentication** - Secure registration and login with JWT
- 🤖 **AI-Powered Analysis** - Smart threat detection based on input patterns
- 📊 **Risk Scoring** - Context-aware risk assessment (0-100)
- 🚨 **Threat Detection** - Identifies SQL injection, XSS, and other vulnerabilities
- 💡 **Smart Recommendations** - Actionable security advice
- 📈 **Analysis History** - Track all past security scans
- 📊 **Dashboard Stats** - Visual summary of security posture

### Security Checks Performed
| Check | Description |
|-------|-------------|
| SQL Injection | Detects SQL query patterns |
| XSS Attacks | Identifies script/HTML injection risks |
| Authentication | Checks for weak auth mechanisms |
| Encryption | Verifies HTTPS usage |
| File Upload | Detects upload vulnerabilities |
| API Security | Identifies misconfigured endpoints |
| Command Injection | Detects eval/exec patterns |
| Session Management | Checks cookie/token security |

---

## 🖥️ Tech Stack

### Backend
- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** SQLite
- **Authentication:** JWT + bcrypt
- **AI:** Ready for Alibaba Qwen integration

### Frontend
- **HTML5** - Semantic structure
- **CSS3** - Modern responsive design
- **JavaScript** - Vanilla JS with fetch API

### DevOps
- **Version Control:** Git & GitHub
- **Cloud:** Alibaba Cloud (deployment ready)

---

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- npm

### Backend Setup

```bash
# Navigate to backend
cd backend

# Install dependencies
npm install

# Start server
node server.jsy
