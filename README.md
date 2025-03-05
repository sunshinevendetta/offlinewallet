# Offline Wallet Generator v1.0

## 🚀 Why This Exists

most wallet generators just dump your seed phrase or private key in a plain text file with zero protection. if someone gets their hands on that file, that's it. your access is gone. no second chances. joke software. so i built this to not be a joke.

most wallets don’t encrypt your keys when generating them. if you lose that file or someone gets it, you’re finished. saving it on google drive or any cloud service is a **big no**. but if the file is **encrypted**, you can save it anywhere because nobody but you can decrypt it.

sometimes you need **thousands** of wallets for whatever reason. maybe you’re spreading funds across multiple addresses. maybe you just like being paranoid. either way, doing this manually is stupid. this lets you **generate mass wallets in one click**.

built for **security-first** crypto users.

## 🔥 Features

- **Generate Unlimited Wallets** → Seed phrases or private keys
- **Encryption Built-in** → No raw keys lying around
- **Three Security Levels**:
  - **No password** (not recommended)
  - **Password-only encryption**
  - **Password + 2FA encryption** (best)
- **Multi-Format Export** → Save as JSON, CSV, or TXT
- **Offline** → No tracking, no bullshit, just local wallet generation
- **Two Encryption Algorithms**:
  - **AES-256**
  - **ChaCha20-Poly1305**
- **Fast & Lightweight** → No dependencies beyond the required libraries

## 🔑 How It Works

1. **Choose wallet type** → Private key or Seed phrase  
2. **Select quantity** → Generate 1 to 10,000 wallets  
3. **Set security level** → No password, Password-only, or Password + 2FA  
4. **Save encrypted wallet file** → Store it anywhere, even cloud  
5. **Decrypt only when needed** → Using the app, import into any wallet  

## 🔒 Encryption Explained

the whole point of this tool is **never exposing raw keys**.  

when you generate wallets, the output is **encrypted** before saving.  
if you **set a password**, it uses **Argon2id** to derive a strong key.  
if you enable **2FA**, even if someone gets the file **they also need your live TOTP code**.  

each file stores:
- **Wallet Data** → Private key / Seed phrase
- **Encryption Method** → AES-256 or ChaCha20-Poly1305
- **HMAC-SHA256** → Ensures file integrity, prevents tampering  

this means even if someone gets your encrypted file, they can’t do **shit** without your credentials.  

## 💻 Usage

### **Generating Wallets**
1. **Run the app**  
2. **Select Wallet Type** → Private Key / Seed Phrase  
3. **Set Number of Wallets**  
4. **Choose Encryption** → No password / Password / Password + 2FA  
5. **Save File** → Encrypted file stored locally  

### **Decrypting & Importing**
1. **Run the app**  
2. **Load the Encrypted File**  
3. **Enter Password & 2FA (if enabled)**  
4. **View Wallets & Export**  

## 📁 File Formats

- `.enc` → Default encrypted file
- `.json` → Structured JSON export
- `.csv` → Spreadsheet-compatible
- `.txt` → Raw readable format

## 🛠 Supported Platforms

- **Windows**
- **MacOS**
- **Linux**
- **Android (via Python scripting)**

## ⚡ Open Source & No Tracking

this is **100% offline**. no telemetry, no data collection, no logs. you generate wallets, you store them however you want. nobody gets to mess with your keys except **you**.

🔗 **[GitHub Repo](https://github.com/sunshinevendetta/offlinewallet.git)**  

---

**made for those who actually care about keeping their crypto secure.**  
**use it, share it, improve it.**
