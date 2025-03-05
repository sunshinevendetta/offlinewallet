## **Offline Wallet Generator v1.0**  
_A truly offline, encrypted, secure, and easy-to-use wallet generator._

### **Why This Exists**
Most wallet generators just throw your seed phrase or private key into a plain text file with **zero protection**. If someone gets their hands on that file, that’s it—your access is gone. No second chances. That’s **a joke**.  
I built this to **not be a joke**.

Most wallets **don’t encrypt your keys** when generating them. If you lose the file or someone gets it, **you’re done**. And saving it in a Google Drive or cloud service? That’s a **big no**.  

But **if the file is encrypted**, then hell yeah, you can store it anywhere. Nobody except **you** can decrypt it.

---

## **What This Does**
- Generates **private keys** or **seed phrases** securely.
- Encrypts the output with **Argon2 + AES-256** or **ChaCha20-Poly1305**.
- Supports **password encryption** and optional **2FA authentication** for decryption.
- Saves wallets in **JSON, CSV, or TXT** format.
- Works **fully offline**—no tracking, no leaks, **your keys, your rules**.

---

## **How It Works**
1. **Choose Private Key or Seed Phrase** generation.
2. **Pick how many wallets** to generate (1-10,000).
3. **Set a password** (optional) or use **password + 2FA** for extra security.
4. **Save the encrypted file** (nobody can steal your keys).
5. **Decrypt later** only if you have the correct password (and 2FA if enabled).
6. **Import your wallet** into any standard crypto wallet app.

---

## **How To Use**
### **1. Download & Run the App**
- **Windows**: [Download `offlinewallet.exe`](https://github.com/sunshinevendetta/offlinewallet/releases/latest)  
- **MacOS**: [Download `offlinewallet.dmg`](https://github.com/sunshinevendetta/offlinewallet/releases/latest)  
- **Linux**: Coming soon

### **2. Run It Manually (If You Prefer)**
If you don’t want to use the prebuilt app, you can **run it manually**. Here’s what you need.

#### **Requirements**
- **Python 3.10+**
- Required Python Libraries:
  ```sh
  pip install -r requirements.txt
  ```
  If you don’t have `requirements.txt`, manually install:
  ```sh
  pip install pyqt5 cryptography argon2-cffi eth-account mnemonic qrcode zxcvbn pyotp
  ```

#### **Run the app**
```sh
python offlinewallet.py
```

---

## **For Developers: Build It Yourself**
If you want to compile your own `.exe` or `.app`, here’s how.

### **Windows (Build .exe)**
1. Install dependencies:
   ```sh
   pip install pyinstaller
   ```
2. Run:
   ```sh
   pyinstaller --onefile --windowed --name "offlinewallet" offlinewallet.py
   ```
3. The `.exe` will be in the **`dist/`** folder.

---

### **MacOS (Build .app)**
1. Install `py2app`:
   ```sh
   pip install py2app
   ```
2. Use this `setup.py`:
   ```python
   from setuptools import setup
   APP = ['offlinewallet.py']
   OPTIONS = {
       'argv_emulation': True,
       'packages': ['PyQt5', 'cryptography', 'argon2', 'argon2_cffi', 'eth_account', 'mnemonic', 'qrcode', 'zxcvbn', 'pyotp'],
       'excludes': ['tkinter'],
       'plist': {
           'CFBundleName': 'OfflineWallet',
           'CFBundleVersion': '1.0.0',
           'NSHighResolutionCapable': 'True'
       }
   }
   setup(app=APP, options={'py2app': OPTIONS}, setup_requires=['py2app'])
   ```
3. Build it:
   ```sh
   python setup.py py2app
   ```
4. Your `.app` will be in `dist/OfflineWallet.app`

---

## **Security Features**
- **Argon2 Key Derivation** (slow & secure, resistant to brute force).
- **AES-256 or ChaCha20-Poly1305** encryption.
- **HMAC integrity check** (detects tampering).
- **Optional 2FA** (time-based one-time passwords).
- **No internet connection required** (fully offline).

---

## **FAQ**
**Q: Why not use a browser-based generator?**  
A: **Hell no.** Web-based generators **can leak your keys**. You should never generate wallets on a website.

**Q: Can I store my encrypted file in Google Drive?**  
A: **Yes,** but only if you enabled password encryption. Without it, your file is as good as stolen.

**Q: What if I lose my password?**  
A: **Game over.** There’s **no recovery**. You must store it securely.

**Q: Why include 2FA?**  
A: Even if someone steals your encrypted file **and** cracks your password, **they still need your real-time 2FA code**.

---

## **Final Notes**
- **Your keys, your responsibility.** If you mess up, **nobody can help you.**
- **No backdoors, no recovery.** That’s the price of true security.
- **Use at your own risk.** I made this for myself, you get to use it **if you know what you're doing**.

---

💀 **Made by [SunshineVendetta](https://x.com/sunshinevndetta)** | No tracking | No spyware | No BS  
💰 Donations: `0x3eCa5f038A7f32367d03A0385534ffC918E2342b`  
🚀 **Download & Stay Safe:** [Github Releases](https://github.com/sunshinevendetta/offlinewallet/releases/latest)  
