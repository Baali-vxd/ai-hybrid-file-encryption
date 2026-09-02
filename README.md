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
- [Future Improvements](#-future-improvements)

---

## 🎯 Project Objective

Traditional symmetric file encryption systems face secret key distribution challenges, while public-key asymmetric algorithms are computationally too slow for bulk files. Furthermore, encrypted storage platforms often lack real-time behavior monitoring.

This project solves both problems by:
1. Combining **AES-256-GCM** (fast symmetric file encryption) with **RSA-2048 OAEP** (secure asymmetric key envelope protection) and **SHA-256** checksum integrity verification.
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

## 🔐 Hybrid Cryptography Mechanics

The application utilizes a **hybrid cryptographic architecture** to achieve maximum data protection and performance efficiency:

1. **Symmetric Payload Encryption (AES-256-GCM)**:
   - File payload is encrypted using Galois/Counter Mode (GCM), providing both confidentiality and built-in message authentication (16-byte authentication tag).
   - Each file encryption operation generates a unique random 256-bit (32-byte) AES secret key and a 96-bit (12-byte) Initialization Vector (IV).

2. **Asymmetric Key Envelope Protection (RSA-2048 OAEP)**:
   - The 256-bit AES key is encrypted using RSA-2048 with Optimal Asymmetrical Encryption Padding (OAEP) and SHA-256 digest function.
   - The private key remains securely stored server-side (`uploads/keys/rsa_private.pem`) and is never exposed over API responses or client-side storage.

3. **Cryptographic Checksum Verification (SHA-256)**:
   - Prior to encryption, a SHA-256 digest (64-character hexadecimal fingerprint) of the raw file is computed and recorded.
   - Upon decryption, a fresh SHA-256 digest of the unencrypted file payload is computed and compared against the original hash to confirm data integrity.

---

## 🤖 Machine Learning Threat Detection

The system incorporates an **Isolation Forest (iForest)** unsupervised machine learning algorithm from `scikit-learn` to detect anomalous user behavior in real-time:

### Feature Vector Specification
For each incoming request (particularly decryption operations), the system collects a 5-dimensional feature vector:
1. `failed_logins`: Count of recent failed authentication attempts.
2. `encryption_requests`: Total encryption actions performed by the user session.
3. `decryption_requests`: Total decryption actions requested.
4. `failed_decryptions`: Count of consecutive failed or suspicious decryption requests.
5. `access_frequency`: Rate of API calls per minute (detecting automated script bursts).

### Classification & Anomaly Scoring
The Isolation Forest isolates observations by randomly selecting a feature and splitting the value. Anomalies require fewer splits and isolate quickly:

| Classification | Threat Level | Criteria / Anomaly Score Threshold | System Action |
| :--- | :--- | :--- | :--- |
| 🟢 **NORMAL** | Low | Score >= -0.05, typical user behavior | Operation Granted |
| 🟡 **SUSPICIOUS** | Medium | Score < -0.05 or 1-2 failed attempts | Operation Allowed + Flagged in Audit Log |
| 🔴 **POTENTIAL THREAT** | High | Score < -0.15 or >= 3 decryption failures | Operation Blocked 🚨 + Security Alert Logged |

---

## 📁 Project Directory Structure

```
ai-hybrid-file-encryption/
├── backend/
│   ├── main.py              # FastAPI application router & REST endpoints
│   ├── database.py          # SQLAlchemy SQLite database session setup
│   ├── models.py            # ORM Database Models (User, FileRecord, SecurityLog, UserActivity)
│   ├── schemas.py           # Pydantic validation schemas
│   ├── auth.py              # Password hashing (PBKDF2/SHA256) & JWT authentication
│   ├── encryption.py        # AES-256 + RSA-2048 + SHA-256 hybrid engine
│   ├── decryption.py        # RSA unwrap + AES decrypt + integrity check
│   ├── ai_detection.py      # Scikit-Learn IsolationForest threat detector
│   └── security_logs.py     # Audit logger helper
├── frontend/
│   ├── index.html           # Single Page Application HTML layout
│   ├── css/
│   │   └── style.css        # Dark cybersecurity design system
│   └── js/
│       └── app.js           # Client-side SPA router, API calls, Chart.js telemetry
├── uploads/
│   ├── encrypted_files/     # Encrypted payload storage
│   ├── decrypted_files/     # Temporary decrypted download cache
│   └── keys/                # Server-side RSA-2048 public/private key store
├── database/
│   └── security.db          # SQLite database file
├── requirements.txt         # Python dependencies manifest
└── README.md                # Project documentation
```

---

## ⚡ Installation & Running Locally

### 1. Prerequisites
Ensure you have Python 3.10 or higher installed on your system.

### 2. Install Dependencies
Navigate to the project root directory and run:

```bash
pip install -r requirements.txt
```

### 3. Start the FastAPI Server
Launch the application server using Uvicorn:

```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### 4. Access the Cyber Portal
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 🔮 Future Improvements

1. **Hardware Security Module (HSM) Integration**: Storing RSA private keys in hardware modules or cloud key vaults (AWS KMS / Azure Key Vault).
2. **Multi-Factor Authentication (MFA)**: TOTP authenticator integration for sensitive decryption actions.
3. **Advanced ML Features**: Incorporating IP geolocation anomaly detection and time-series LSTM models for continuous behavioral monitoring.

