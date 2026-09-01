# AI-Enabled Hybrid File Encryption and Intelligent Threat Detection System

> **Computer Networks and Security (CNS) Academic Mini Project**

A complete, production-grade cybersecurity web application that combines **Hybrid Cryptography (AES-256 + RSA-2048)**, **SHA-256 Integrity Verification**, and **Machine Learning Anomaly Detection (Scikit-Learn Isolation Forest)** to secure sensitive files against unauthorized access and cyber threats.

---

## 📌 Table of Contents

- [Project Objective](#-project-objective)
- [Key Features](#-key-features)
- [Technology Stack](#-technology-stack)
- [System Architecture & Workflow](#-system-architecture--workflow)
- [Hybrid Cryptography Mechanics](#-hybrid-cryptography-mechanics)
- [Machine Learning Threat Detection](#-machine-learning-threat-detection)
- [Project Directory Structure](#-project-directory-structure)
- [Installation & Running Locally](#-installation--running-locally)
- [Viva Voce Q&A Preparation](#-viva-voce-qa-preparation)
- [Future Improvements](#-future-improvements)

---

## 🎯 Project Objective

Traditional symmetric file encryption systems face secret key distribution challenges, while public-key asymmetric algorithms are computationally too slow for bulk files. Furthermore, encrypted storage platforms often lack real-time behavior monitoring.

This project solves both problems by:
1. Combining **AES-256** (fast symmetric file encryption) with **RSA-2048** (secure asymmetric key envelope protection) and **SHA-256** checksum integrity verification.
2. Implementing an **Isolation Forest ML Model** that analyzes real-time user behavior (login failures, decryption frequencies, automated request bursts) to dynamically classify activity into 🟢 **NORMAL**, 🟡 **SUSPICIOUS**, or 🔴 **POTENTIAL THREAT**, blocking risky actions automatically.

---

## 🚀 Key Features

* **🔐 User Authentication & Authorization**: JWT-based secure session management with salted PBKDF2 / SHA-256 password hashing.
* **🛡️ AES-256 File Cipher**: High-speed symmetric cipher encrypts files of any format (documents, images, videos, binaries).
* **🔑 RSA-2048 Key Envelope Protection**: Asymmetric public/private key cryptography encrypts the 256-bit AES key, preventing key leakage.
* **🔍 SHA-256 Checksum Verification**: Guarantees file integrity before and after decryption (`✅ FILE INTEGRITY VERIFIED` vs `🚨 FILE INTEGRITY FAILED`).
* **🤖 AI Threat Detection Radar**: Scikit-Learn Isolation Forest model evaluates activity anomaly scores in real-time.
* **📊 Security Audit Logging**: Searchable and filterable security event log tracking registrations, logins, encryptions, decryptions, and threat triggers.
* **📈 Interactive Telemetry Dashboard**: Real-time charts powered by Chart.js displaying user activity timelines and threat level distributions.
* **🧪 Viva Demonstration Attack Simulator**: Interactive panel to simulate brute-force decryption attacks and credential stuffing for live demo.

---

## 💻 Technology Stack

### Backend
* **Python 3.10+**
* **FastAPI**: Asynchronous high-performance web framework.
* **SQLAlchemy & SQLite**: ORM and lightweight embedded database.
* **Cryptography**: Python standard cryptography library (AES-256-GCM, RSA-2048 OAEP, SHA-256).
* **Scikit-Learn**: Machine learning library for Isolation Forest anomaly detection.
* **NumPy & Pandas**: Data manipulation for feature vectors.
* **PyJWT & Passlib**: Authentication and password security.

### Frontend
* **HTML5 & CSS3**: Modern cybersecurity dark theme (glassmorphism, cyber neon accents, responsive layout).
* **Vanilla JavaScript (ES6+)**: SPA view management, REST API fetch, drag-and-drop file upload.
* **Chart.js**: Telemetry and security graphs.
* **FontAwesome**: Modern cybersecurity icon set.

---

## 🏗️ System Architecture & Workflow

```
[ User Uploads File ]
          │
          ▼
[ SHA-256 Checksum Generated ]
          │
          ▼
[ AES-256 Key Generated & File Encrypted ]
          │
          ▼
[ RSA-2048 Encrypts AES Secret Key ]
          │
          ▼
[ Encrypted File Payload + Key Envelope + Hash Stored in DB ]
          │
          ▼
[ Decryption Request → AI Threat Detection Check ]
          │
  ┌───────┴────────────────────────┐
  ▼                                ▼
[ Normal Behavior ]      [ Threat Detected ]
  │                                │
  ▼                                ▼
[ RSA Decrypts AES Key ]   [ Decryption Blocked 🚨 ]
  │
  ▼
[ AES Decrypts File ]
  │
  ▼
[ SHA-256 Verified → File Download Allowed ]
```

---

## 📁 Project Directory Structure

```
hybrid-encryption-ai-threat-detection/
├── backend/
│   ├── main.py              # FastAPI application router & endpoints
│   ├── database.py          # SQLAlchemy SQLite database setup
│   ├── models.py            # ORM Database Models (User, FileRecord, SecurityLog, UserActivity)
│   ├── schemas.py           # Pydantic validation schemas
│   ├── auth.py              # Password hashing & JWT authentication
│   ├── encryption.py        # AES-256 + RSA-2048 + SHA-256 hybrid engine
│   ├── decryption.py        # RSA unwrap + AES decrypt + integrity check
│   ├── ai_detection.py      # Scikit-Learn IsolationForest threat detector
│   └── security_logs.py     # Audit logger helper
├── frontend/
│   ├── index.html           # Single Page Application HTML layout
│   ├── css/
│   │   └── style.css        # Dark cybersecurity design system
│   └── js/
│       └── app.js           # Client-side SPA router, API calls, Chart.js setup
├── uploads/
│   ├── encrypted_files/     # Encrypted payload files
│   ├── decrypted_files/     # Decrypted download files
│   └── keys/                # RSA public/private key store
├── database/
│   └── security.db          # SQLite database file
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation
```

---

## ⚡ Installation & Running Locally

### 1. Prerequisites
Ensure you have Python 3.10+ installed on your system.

### 2. Install Dependencies
Navigate to the project root directory and run:

```bash
pip install -r requirements.txt
```

### 3. Start the FastAPI Server
Launch the application using Uvicorn:

```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### 4. Access the Cyber Portal
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 🎓 Viva Voce Q&A Preparation

| Question | Answer |
| :--- | :--- |
| **Q1: Why is this called Hybrid Cryptography?** | **A:** Symmetric encryption (AES-256) is extremely fast for large files but hard to share keys securely. Asymmetric encryption (RSA-2048) is secure for key exchange but slow. Hybrid cryptography encrypts the file with AES-256 and then encrypts the AES key with RSA-2048. |
| **Q2: What role does SHA-256 play?** | **A:** SHA-256 generates a unique 256-bit cryptographic fingerprint of the original file. When decrypting, a new hash is generated and compared against the original to ensure the file was not modified or corrupted. |
| **Q3: How does the AI Threat Detection work?** | **A:** The system uses Scikit-Learn's `IsolationForest` algorithm. It monitors feature vectors (failed logins, decryption request counts, failed decryptions, request rates). Anomalous behaviors require fewer decision tree splits and yield negative anomaly scores, classifying activity into Normal, Suspicious, or Threat. |
| **Q4: Where are the RSA keys generated?** | **A:** RSA-2048 key pairs are generated server-side using the Python `cryptography` library and stored securely in `uploads/keys/`. The private key is never exposed to the frontend browser. |

---

## 🔮 Future Improvements

1. **Hardware Security Module (HSM) Integration**: Storing RSA private keys in hardware modules or cloud key vaults (AWS KMS / Azure Key Vault).
2. **Multi-Factor Authentication (MFA)**: TOTP authenticator integration for sensitive decryption actions.
3. **Advanced ML Features**: Incorporating IP geolocation anomaly detection and time-series LSTM models for continuous behavioral monitoring.
