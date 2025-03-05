import os
import sys
import secrets
import json
import base64
import logging
from io import BytesIO
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import argon2
from argon2.low_level import hash_secret, Type
import pyotp
import qrcode
from zxcvbn import zxcvbn
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from mnemonic import Mnemonic
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget, QFileDialog,
    QLineEdit, QMessageBox, QComboBox, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem,
    QDialog, QProgressDialog, QInputDialog
)
from PyQt5.QtGui import QPixmap, QImage, QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer


logging.basicConfig(
    filename='walletgen_secure.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

#########################################################
#                  CONSTANTS & HELPERS                  #
#########################################################

SALT_SIZE = 16
HEADER_LENGTH_SIZE = 4
CHACHA_NONCE_SIZE = 12
KEY_LENGTH = 32
HMAC_SIZE = 32
MAX_WALLETS = 10000 

class CryptoError(Exception):
    """Custom exception for cryptographic operations."""
    pass

class ValidationError(Exception):
    """Custom exception for input validation."""
    pass

def dynamic_salt() -> bytes:
    """Generates a cryptographically secure random salt for each encryption session."""
    return os.urandom(SALT_SIZE)

def derive_factor_argon2(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte cryptographic factor from a password using Argon2id."""
    try:
        if not password or not isinstance(password, str):
            raise ValidationError("Password must be a non-empty string")
        key = hash_secret(
            password.encode('utf-8'),
            salt,
            time_cost=2,
            memory_cost=2**16,  # 64 MiB
            parallelism=2,
            hash_len=KEY_LENGTH,
            type=Type.ID
        )
        logger.debug(f"Derived Argon2 key with salt: {salt.hex()}")
        return key
    except Exception as e:
        logger.error(f"Argon2 key derivation failed: {str(e)}")
        raise CryptoError(f"Key derivation failed: {str(e)}")

def derive_master_key(factors: List[bytes], salt: bytes) -> bytes:
    """Combines factor bytes and derives a 32-byte master key via HKDF-SHA256."""
    try:
        if not factors or not all(isinstance(f, bytes) for f in factors):
            raise ValidationError("Factors must be a non-empty list of bytes")
        combined = b''.join(factors)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            info=b"master key",
            backend=default_backend()
        )
        key = hkdf.derive(combined)
        logger.debug(f"Master key derived: {key.hex()}")
        return key
    except Exception as e:
        logger.error(f"Master key derivation failed: {str(e)}")
        raise CryptoError(f"Master key derivation failed: {str(e)}")

def derive_encryption_key(master_key: bytes, salt: bytes) -> bytes:
    """Derives a 32-byte encryption key from the master key using HKDF-SHA256."""
    try:
        if not isinstance(master_key, bytes) or len(master_key) != KEY_LENGTH:
            raise ValidationError("Invalid master key format")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            info=b"encryption",
            backend=default_backend()
        )
        key = hkdf.derive(master_key)
        logger.debug(f"Encryption key derived: {key.hex()}")
        return key
    except Exception as e:
        logger.error(f"Encryption key derivation failed: {str(e)}")
        raise CryptoError(f"Encryption key derivation failed: {str(e)}")

def add_integrity(data: bytes, key: bytes, salt: bytes) -> bytes:
    """Appends a 32-byte HMAC-SHA256 to ensure data integrity."""
    try:
        if not data or not isinstance(data, bytes):
            raise ValidationError("Data must be non-empty bytes")
        hmac_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            info=b"hmac",
            backend=default_backend()
        )
        hmac_key = hmac_hkdf.derive(key)
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        mac = h.finalize()
        logger.debug(f"HMAC added, total length: {len(data + mac)}")
        return data + mac
    except Exception as e:
        logger.error(f"HMAC addition failed: {str(e)}")
        raise CryptoError(f"HMAC addition failed: {str(e)}")

def verify_integrity(data: bytes, key: bytes, salt: bytes) -> bytes:
    """Verifies the HMAC-SHA256 and returns the plaintext if valid."""
    try:
        if len(data) < HMAC_SIZE:
            raise ValidationError(f"Data too short for HMAC: length {len(data)}")
        data_part = data[:-HMAC_SIZE]
        mac_part = data[-HMAC_SIZE:]
        hmac_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            info=b"hmac",
            backend=default_backend()
        )
        hmac_key = hmac_hkdf.derive(key)
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data_part)
        h.verify(mac_part)
        logger.debug(f"HMAC verified, data length: {len(data_part)}, content: {data_part.hex()[:50]}...")
        return data_part
    except Exception as e:
        logger.error(f"HMAC verification failed: {str(e)}, data: {data.hex()[:50]}...")
        raise CryptoError(f"HMAC verification failed: {str(e)}")

#########################################################
#                    ENCRYPT / DECRYPT                  #
#########################################################

def encrypt_with_aes(data: bytes, key: bytes) -> bytes:
    """Encrypts data using AES-256 in Fernet mode."""
    try:
        if not data or not isinstance(data, bytes):
            raise ValidationError("Data must be non-empty bytes")
        if len(key) != KEY_LENGTH:
            raise ValidationError("Invalid AES key length")
        fernet = Fernet(base64.urlsafe_b64encode(key))
        encrypted = fernet.encrypt(data)
        logger.debug(f"AES encrypted, length: {len(encrypted)}")
        return encrypted
    except Exception as e:
        logger.error(f"AES encryption failed: {str(e)}")
        raise CryptoError(f"AES encryption failed: {str(e)}")

def decrypt_with_aes(token: bytes, key: bytes) -> bytes:
    """Decrypts AES-256 encrypted data using Fernet mode."""
    try:
        if not token or not isinstance(token, bytes):
            raise ValidationError("Token must be non-empty bytes")
        if len(key) != KEY_LENGTH:
            raise ValidationError("Invalid AES key length")
        fernet = Fernet(base64.urlsafe_b64encode(key))
        decrypted = fernet.decrypt(token)
        logger.debug(f"AES decrypted, length: {len(decrypted)}, content: {decrypted.hex()[:50]}...")
        return decrypted
    except Exception as e:
        logger.error(f"AES decryption failed: {str(e)}, token: {token.hex()[:50]}...")
        raise CryptoError(f"AES decryption failed: {str(e)}")

def encrypt_with_chacha(data: bytes, key: bytes) -> bytes:
    """Encrypts data using ChaCha20-Poly1305 with a random nonce."""
    try:
        if not data or not isinstance(data, bytes):
            raise ValidationError("Data must be non-empty bytes")
        if len(key) != KEY_LENGTH:
            raise ValidationError("Invalid ChaCha20 key length")
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(CHACHA_NONCE_SIZE)
        ct = chacha.encrypt(nonce, data, None)
        logger.debug(f"ChaCha20 encrypted, length: {len(nonce + ct)}")
        return nonce + ct
    except Exception as e:
        logger.error(f"ChaCha20 encryption failed: {str(e)}")
        raise CryptoError(f"ChaCha20 encryption failed: {str(e)}")

def decrypt_with_chacha(token: bytes, key: bytes) -> bytes:
    """Decrypts ChaCha20-Poly1305 encrypted data using the provided nonce."""
    try:
        if len(token) < CHACHA_NONCE_SIZE:
            raise ValidationError("Invalid ChaCha20 data length")
        if len(key) != KEY_LENGTH:
            raise ValidationError("Invalid ChaCha20 key length")
        chacha = ChaCha20Poly1305(key)
        nonce = token[:CHACHA_NONCE_SIZE]
        ct = token[CHACHA_NONCE_SIZE:]
        decrypted = chacha.decrypt(nonce, ct, None)
        logger.debug(f"ChaCha20 decrypted, length: {len(decrypted)}, content: {decrypted.hex()[:50]}...")
        return decrypted
    except Exception as e:
        logger.error(f"ChaCha20 decryption failed: {str(e)}, token: {token.hex()[:50]}...")
        raise CryptoError(f"ChaCha20 decryption failed: {str(e)}")

#########################################################
#                      QR GENERATION                    #
#########################################################

class QRWorker(QThread):
    """Worker thread for generating QR codes asynchronously."""
    finished = pyqtSignal(QPixmap)

    def __init__(self, data: str):
        super().__init__()
        self.data = data

    def run(self) -> None:
        try:
            qr = qrcode.QRCode(
                version=1,
                box_size=6,
                border=2,
                error_correction=qrcode.constants.ERROR_CORRECT_L
            )
            qr.add_data(self.data)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            buf = BytesIO()
            img.save(buf, format='PNG')
            qimg = QImage.fromData(buf.getvalue(), "PNG")
            pix = QPixmap.fromImage(qimg)
            self.finished.emit(pix)
            logger.debug("QR code generated successfully")
        except Exception as e:
            logger.error(f"QR code generation failed: {str(e)}")

#########################################################
#                  2FA PAIRING DIALOG                   #
#########################################################

class TwoFAPairingDialog(QDialog):
    """Dialog for pairing 2FA with TOTP, displaying a QR code and secret."""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("2FA Pairing")
        self.setModal(True)
        self.totp_secret = pyotp.random_base32()
        self.totp_uri = pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name="OfflineWalletGen", issuer_name="WalletGenApp"
        )
        self.qr_label = QLabel()
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI layout for 2FA pairing."""
        layout = QVBoxLayout(self)
        self.worker = QRWorker(self.totp_uri)
        self.worker.finished.connect(self.handle_qr_finished)
        self.worker.start()
        layout.addWidget(self.qr_label)
        instructions = QLabel(
            "Scan the QR code with your authenticator app.\n"
            "Securely store the TOTP secret below (do NOT save with wallet file):\n"
            f"<b>{self.totp_secret}</b>"
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter current 2FA code")
        layout.addWidget(self.code_input)
        btn_layout = QHBoxLayout()
        self.save_qr_btn = QPushButton("Save QR Code")
        self.confirm_btn = QPushButton("Confirm Pairing")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.save_qr_btn)
        btn_layout.addWidget(self.confirm_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)
        self.save_qr_btn.clicked.connect(self.save_qr)
        self.confirm_btn.clicked.connect(self.verify_code)
        self.cancel_btn.clicked.connect(self.reject)

    def handle_qr_finished(self, pix: QPixmap) -> None:
        """Handle the completion of QR code generation."""
        self.qr_label.setPixmap(pix.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.qr_pixmap = pix

    def save_qr(self) -> None:
        """Save the QR code to a file."""
        if hasattr(self, 'qr_pixmap'):
            qr_file, _ = QFileDialog.getSaveFileName(
                self, "Save QR Code", f"2fa_qr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png", "PNG Files (*.png)"
            )
            if qr_file:
                self.qr_pixmap.save(qr_file, "PNG", quality=95)
                QMessageBox.information(self, "QR Saved", f"QR code saved to {qr_file}")
                logger.info(f"QR code saved to {qr_file}")

    def verify_code(self) -> None:
        """Verify the TOTP code entered by the user."""
        code = self.code_input.text().strip()
        totp = pyotp.TOTP(self.totp_secret)
        if totp.verify(code, valid_window=1):
            QMessageBox.information(self, "2FA Paired", "2FA pairing successful!")
            logger.info("2FA pairing confirmed successfully")
            self.accept()
        else:
            QMessageBox.warning(self, "Invalid Code", "Incorrect or expired TOTP code. Please try again.")
            logger.warning("Invalid TOTP code entered")

#########################################################
#           WALLET GENERATION WORKER (THREAD)           #
#########################################################

class WalletGenerationWorker(QThread):
    """Worker thread for generating wallets asynchronously with progress updates."""
    progress = pyqtSignal(int)
    finished = pyqtSignal('PyQt_PyObject', bytes, str, bool) 

    def __init__(self, gen_type: str, amount: int, password: str, use_2fa: bool, algo_choice: str):
        super().__init__()
        self.gen_type = gen_type
        self.amount = min(amount, MAX_WALLETS)  
        self.password = password
        self.use_2fa = use_2fa
        self.algo_choice = algo_choice

    def run(self) -> None:
        """Generate wallets and emit progress signals."""
        try:
            wallets = []
            total = self.amount

            if self.gen_type == "Private Key":
                for i in range(total):
                    priv_key = "0x" + secrets.token_hex(32)
                    acct = Account.from_key(priv_key)
                    wallets.append({"address": acct.address, "private_key": priv_key, "seed_phrase": ""})
                    self.progress.emit(int((i + 1) / total * 100))
                    QThread.msleep(10)  # Small delay for UI responsiveness
            else:
                Account.enable_unaudited_hdwallet_features()
                mnemo = Mnemonic("english")
                for i in range(total):
                    seed_phrase = mnemo.generate(strength=256)
                    acct = Account.from_mnemonic(seed_phrase)
                    wallets.append({"address": acct.address, "private_key": "", "seed_phrase": seed_phrase})
                    self.progress.emit(int((i + 1) / total * 100))
                    QThread.msleep(10)

            salt = dynamic_salt()
            header = {
                "algorithm": "AES-256" if "AES-256" in self.algo_choice else "ChaCha20-Poly1305",
                "auth_method": "Password + 2FA" if self.use_2fa else ("Password Only" if self.password else "No Encryption"),
                "wallet_gen_type": self.gen_type,
                "amount": self.amount,
                "version": "1.0"  
            }
            header_bytes = json.dumps(header, ensure_ascii=False).encode('utf-8')
            header_length = len(header_bytes)
            header_prefix = header_length.to_bytes(HEADER_LENGTH_SIZE, byteorder="big")
            wallet_data = json.dumps(wallets, indent=4, ensure_ascii=False).encode('utf-8')
            combined_plain = header_prefix + header_bytes + wallet_data

            if not self.password:
                final_data = salt + combined_plain
            else:
                factor = derive_factor_argon2(self.password, salt)
                master_key = derive_master_key([factor], salt)
                enc_key = derive_encryption_key(master_key, salt)
                data_with_hmac = add_integrity(combined_plain, enc_key, salt)
                encrypted = encrypt_with_aes(data_with_hmac, enc_key) if "AES-256" in self.algo_choice else encrypt_with_chacha(data_with_hmac, enc_key)
                final_data = salt + encrypted

            self.finished.emit(wallets, final_data, header["algorithm"], self.use_2fa)
            logger.info(f"Generated {total} wallets with {self.algo_choice}")
        except Exception as e:
            logger.error(f"Wallet generation failed: {str(e)}")
            self.finished.emit([], b'', self.algo_choice, self.use_2fa)

#########################################################
#                   GENERATE PAGE (UI)                  #
#########################################################

class GeneratePage(QWidget):
    """UI page for generating wallets with options for type, amount, and encryption."""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.totp_secret = None
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI layout for wallet generation."""
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        grid.setSpacing(10)

        self.type_label = QLabel("Generation Type:")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Private Key", "Seed Phrase"])
        grid.addWidget(self.type_label, 0, 0)
        grid.addWidget(self.type_combo, 0, 1)

        self.amount_label = QLabel("Number of Wallets:")
        self.amount_combo = QComboBox()
        self.amount_combo.addItems([str(i) for i in [10, 100, 1000, MAX_WALLETS]])
        self.custom_amount = QLineEdit()
        self.custom_amount.setPlaceholderText(f"Or enter custom (1-{MAX_WALLETS})")
        self.custom_amount.setValidator(QtGui.QIntValidator(1, MAX_WALLETS, self))
        grid.addWidget(self.amount_label, 1, 0)
        hbox_amt = QHBoxLayout()
        hbox_amt.addWidget(self.amount_combo)
        hbox_amt.addWidget(self.custom_amount)
        grid.addLayout(hbox_amt, 1, 1)

        self.export_label = QLabel("Export Format:")
        self.export_combo = QComboBox()
        self.export_combo.addItems(["JSON", "CSV", "TXT", "All Formats"])
        grid.addWidget(self.export_label, 2, 0)
        grid.addWidget(self.export_combo, 2, 1)

        self.auth_label = QLabel("Authentication Method:")
        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["No Encryption", "Password Only", "Password + 2FA"])
        grid.addWidget(self.auth_label, 3, 0)
        grid.addWidget(self.auth_combo, 3, 1)

        self.pwd_label = QLabel("Password:")
        self.pwd_field = QLineEdit()
        self.pwd_field.setEchoMode(QLineEdit.Password)
        self.pwd_strength = QLabel("")
        self.pwd_strength.setStyleSheet("color: gray;")
        grid.addWidget(self.pwd_label, 4, 0)
        pwd_box = QVBoxLayout()
        pwd_box.addWidget(self.pwd_field)
        pwd_box.addWidget(self.pwd_strength)
        grid.addLayout(pwd_box, 4, 1)

        self.auth_combo.currentTextChanged.connect(self.adjust_auth_fields)
        self.pwd_field.textChanged.connect(self.check_password_strength)

        self.pair_button = QPushButton("Pair 2FA")
        self.pair_button.setVisible(False)
        self.pair_button.clicked.connect(self.pair_2fa)
        grid.addWidget(self.pair_button, 5, 1)

        self.algo_label = QLabel("Encryption Algorithm:")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256 (Default)", "ChaCha20-Poly1305"])
        grid.addWidget(self.algo_label, 6, 0)
        grid.addWidget(self.algo_combo, 6, 1)

        self.generate_button = QPushButton("Generate Wallets")
        self.generate_button.setStyleSheet("font-weight: bold;")
        grid.addWidget(self.generate_button, 7, 0, 1, 2)
        self.generate_button.clicked.connect(self.generate_wallets)

        layout.addLayout(grid)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Private Key", "Seed Phrase"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self.copy_cell)
        self.table.setStyleSheet("QTableWidget::item { padding: 5px; }")
        layout.addWidget(self.table)

        self.output_label = QLabel("")
        self.output_label.setAlignment(Qt.AlignCenter)
        self.output_label.setStyleSheet("font-size: 32px; color: #FFFFFF;")
        layout.addWidget(self.output_label)

        self.setLayout(layout)

    def adjust_auth_fields(self, text: str) -> None:
        """Adjust visibility of password and 2FA fields based on authentication method."""
        self.pwd_label.setVisible(text != "No Encryption")
        self.pwd_field.setVisible(text != "No Encryption")
        self.pwd_strength.setVisible(text != "No Encryption")
        self.pair_button.setVisible(text == "Password + 2FA")

    def check_password_strength(self) -> None:
        """Check and display password strength using zxcvbn."""
        pwd = self.pwd_field.text().strip()
        if not pwd:
            self.pwd_strength.setText("")
            return
        result = zxcvbn(pwd)
        score = result['score']  # 0-4
        colors = ["red", "orange", "yellow", "lightgreen", "green"]
        self.pwd_strength.setText(f"Strength: {score}/4")
        self.pwd_strength.setStyleSheet(f"color: {colors[score]};")
        if score < 3:
            logger.warning(f"Weak password detected: score {score}, suggestions: {', '.join(result['feedback']['suggestions'])}")

    def pair_2fa(self) -> None:
        """Open dialog to pair 2FA with TOTP."""
        dlg = TwoFAPairingDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            self.totp_secret = dlg.totp_secret
            logger.info("2FA paired successfully")

    def generate_wallets(self) -> None:
        """Generate wallets based on user selections and handle the process asynchronously."""
        gen_type = self.type_combo.currentText()
        custom_amt = self.custom_amount.text().strip()
        try:
            amount = int(custom_amt) if custom_amt and 1 <= int(custom_amt) <= MAX_WALLETS else int(self.amount_combo.currentText())
        except ValueError:
            QMessageBox.critical(self, "Input Error", f"Invalid custom amount. Must be between 1 and {MAX_WALLETS}.")
            logger.error("Invalid custom amount entered")
            return
        export_format = self.export_combo.currentText()
        auth_method = self.auth_combo.currentText()

        password = ""
        use_2fa = False
        if auth_method == "Password Only":
            password = self.pwd_field.text().strip()
            if not password:
                QMessageBox.critical(self, "Input Error", "Please enter a password.")
                logger.warning("No password entered for Password Only mode")
                return
            if zxcvbn(password)['score'] < 3:
                if QMessageBox.question(self, "Weak Password", "Password strength is low. Continue anyway?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.No:
                    logger.warning("User rejected weak password")
                    return
        elif auth_method == "Password + 2FA":
            password = self.pwd_field.text().strip()
            if not password:
                QMessageBox.critical(self, "Input Error", "Please enter a password.")
                logger.warning("No password entered for Password + 2FA mode")
                return
            if zxcvbn(password)['score'] < 3:
                if QMessageBox.question(self, "Weak Password", "Password strength is low. Continue anyway?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.No:
                    logger.warning("User rejected weak password")
                    return
            if not self.totp_secret:
                QMessageBox.critical(self, "2FA Not Paired", "Please pair 2FA first.")
                logger.warning("2FA not paired for Password + 2FA mode")
                return
            use_2fa = True

        file_name, _ = QFileDialog.getSaveFileName(self, "Save Wallet File", f"wallets_{datetime.now().strftime('%Y%m%d_%H%M%S')}", "Encrypted Files (*.enc);;Wallet Files (*.wallet);;All Files (*)")
        if not file_name:
            logger.info("File save dialog canceled")
            return

        self.progress_dialog = QProgressDialog("Generating wallets...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.show()

        self.worker = WalletGenerationWorker(gen_type, amount, password, use_2fa, self.algo_combo.currentText())
        self.worker.progress.connect(self.progress_dialog.setValue)
        self.worker.finished.connect(lambda w, data, algo, u2fa: self.on_generation_finished(w, data, algo, u2fa, file_name, export_format))
        self.worker.finished.connect(self.progress_dialog.close)
        self.generate_button.setEnabled(False)
        self.worker.start()
        logger.info(f"Started wallet generation: {gen_type}, {amount} wallets, {auth_method}, algorithm: {self.algo_combo.currentText()}")

    def on_generation_finished(self, wallets: List[Dict], final_data: bytes, algo: str, use_2fa: bool, file_name: str, export_format: str) -> None:
        """Handle the completion of wallet generation and save results."""
        self.generate_button.setEnabled(True)

        if not file_name.endswith(('.enc', '.wallet')):
            file_name += '.enc' if self.pwd_field.isVisible() else '.wallet'
        try:
            with open(file_name, "wb") as f:
                f.write(final_data)
            logger.info(f"Wallets saved to {file_name}")
            QMessageBox.information(self, "Success", f"Wallets generated and saved to {file_name}")
        except Exception as e:
            logger.error(f"Failed to save file {file_name}: {str(e)}")
            QMessageBox.critical(self, "Save Error", f"Failed to save file: {str(e)}")
            return

        if not self.pwd_field.isVisible() and export_format != "Wallet":
            try:
                if export_format in ("JSON", "All Formats"):
                    json_path = f"{file_name.rsplit('.', 1)[0]}.json"
                    with open(json_path, "w", encoding='utf-8') as f:
                        json.dump(wallets, f, indent=4, ensure_ascii=False)
                    logger.info(f"Exported JSON to {json_path}")
                if export_format in ("CSV", "All Formats"):
                    csv_path = f"{file_name.rsplit('.', 1)[0]}.csv"
                    with open(csv_path, "w", encoding='utf-8') as f:
                        f.write(to_csv(wallets))
                    logger.info(f"Exported CSV to {csv_path}")
                if export_format in ("TXT", "All Formats"):
                    txt_path = f"{file_name.rsplit('.', 1)[0]}.txt"
                    with open(txt_path, "w", encoding='utf-8') as f:
                        f.write(json.dumps(wallets, indent=4, ensure_ascii=False))
                    logger.info(f"Exported TXT to {txt_path}")
            except Exception as e:
                logger.error(f"Failed to export additional formats: {str(e)}")
                QMessageBox.warning(self, "Export Warning", f"Failed to export additional formats: {str(e)}")

        self.output_label.setText(f"Wallets generated and saved to {file_name}")
        self.table.setRowCount(len(wallets))
        for i, w in enumerate(wallets):
            self.table.setItem(i, 0, QTableWidgetItem(w["address"]))
            self.table.setItem(i, 1, QTableWidgetItem(w["private_key"]))
            self.table.setItem(i, 2, QTableWidgetItem(w["seed_phrase"]))
        logger.debug(f"Displayed {len(wallets)} wallets in table")

    def copy_cell(self, row: int, column: int) -> None:
        """Copy the content of a table cell to the clipboard with feedback."""
        item = self.table.item(row, column)
        if item:
            text = item.text()
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", f"Copied: {text[:20]}{'...' if len(text) > 20 else ''}")
            logger.info(f"Copied cell content: {text[:20]}{'...' if len(text) > 20 else ''}")

#########################################################
#                   DECRYPT PAGE (UI)                   #
#########################################################

class DecryptPage(QWidget):
    """UI page for decrypting wallet files with options for method and password."""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI layout for wallet decryption."""
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        grid.setSpacing(10)

        self.method_label = QLabel("Decryption Method:")
        self.method_combo = QComboBox()
        self.method_combo.addItems(["No Encryption", "Password Only", "Password + 2FA"])
        grid.addWidget(self.method_label, 0, 0)
        grid.addWidget(self.method_combo, 0, 1)

        self.file_label = QLabel("Select Wallet File:")
        self.file_button = QPushButton("Browse...")
        self.file_button.setStyleSheet("background-color: #1E88E5; color: white;")
        self.file_button.clicked.connect(self.browse_file)
        self.selected_file = QLabel("")
        grid.addWidget(self.file_label, 1, 0)
        grid.addWidget(self.file_button, 1, 1)
        grid.addWidget(self.selected_file, 2, 0, 1, 2)

        self.pwd_label = QLabel("Password:")
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        grid.addWidget(self.pwd_label, 3, 0)
        grid.addWidget(self.pwd_input, 3, 1)

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setStyleSheet("font-weight: bold;")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        grid.addWidget(self.decrypt_button, 4, 0, 1, 2)

        layout.addLayout(grid)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Private Key", "Seed Phrase"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self.copy_cell)
        self.table.setStyleSheet("QTableWidget::item { padding: 5px; }")
        layout.addWidget(self.table)

        self.output_label = QLabel("")
        self.output_label.setAlignment(Qt.AlignCenter)
        self.output_label.setStyleSheet("font-size: 32px; color: #FFFFFF;")
        layout.addWidget(self.output_label)

        self.setLayout(layout)
        self.method_combo.currentTextChanged.connect(self.adjust_fields)
        self.adjust_fields(self.method_combo.currentText())

    def adjust_fields(self, text: str) -> None:
        """Adjust visibility of password field based on decryption method."""
        need_pwd = text != "No Encryption"
        self.pwd_label.setVisible(need_pwd)
        self.pwd_input.setVisible(need_pwd)

    def browse_file(self) -> None:
        """Open a file dialog to select a wallet file for decryption."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Wallet File", "", "Encrypted Files (*.enc);;Wallet Files (*.wallet);;All Files (*)"
        )
        if file_path:
            self.selected_file.setText(file_path)
            logger.info(f"Selected file for decryption: {file_path}")
            self.output_label.setText("")

    def decrypt_file(self) -> None:
        """Decrypt a wallet file based on the selected method and password."""
        file_path = self.selected_file.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Input Error", "Please select a valid file.")
            logger.warning("No valid file selected for decryption")
            return

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            logger.debug(f"Read file {file_path}, length: {len(file_data)}, content: {file_data.hex()[:50]}...")
        except Exception as e:
            QMessageBox.critical(self, "File Error", f"Failed to read file: {str(e)}")
            logger.error(f"Failed to read file {file_path}: {str(e)}")
            return

        if len(file_data) < SALT_SIZE:
            QMessageBox.critical(self, "File Error", "File too small or corrupted.")
            logger.error(f"File {file_path} too small, length: {len(file_data)}")
            return

        salt = file_data[:SALT_SIZE]
        data = file_data[SALT_SIZE:]
        method = self.method_combo.currentText()

        progress = QProgressDialog("Decrypting file...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.show()

        try:
            if method == "No Encryption":
                header_len = int.from_bytes(data[:HEADER_LENGTH_SIZE], byteorder="big")
                if len(data) < HEADER_LENGTH_SIZE + header_len + 1:  
                    raise ValueError("Insufficient data for unencrypted file")
                header_json = data[HEADER_LENGTH_SIZE:HEADER_LENGTH_SIZE + header_len].decode("utf-8", errors='strict')
                header = json.loads(header_json)
                wallets_data = data[HEADER_LENGTH_SIZE + header_len:]
                if not wallets_data:
                    raise ValueError("No wallet data found in unencrypted file")
                wallets = json.loads(wallets_data.decode("utf-8", errors='strict'))
                logger.info("Unencrypted file parsed successfully")
            else:
                password = self.pwd_input.text().strip()
                if not password:
                    raise ValidationError("Password is required for decryption")
                if zxcvbn(password)['score'] < 3 and method == "Password + 2FA":
                    if QMessageBox.question(self, "Weak Password", "Password strength is low. Continue anyway?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.No:
                        logger.warning("User rejected weak password for decryption")
                        return

                logger.debug(f"Deriving factor with password: *** and salt: {salt.hex()}")
                factor = derive_factor_argon2(password, salt)
                logger.debug(f"Derived factor: {factor.hex()[:10]}... (masked for security)")
                master_key = derive_master_key([factor], salt)
                logger.debug(f"Master key: {master_key.hex()[:10]}... (masked for security)")
                enc_key = derive_encryption_key(master_key, salt)
                logger.debug(f"Encryption key: {enc_key.hex()[:10]}... (masked for security)")

                def decrypt_and_validate(ciphertext: bytes, key: bytes) -> Tuple[Dict, List[Dict]]:
                    """Attempt decryption with both algorithms and validate the result."""
                    algorithms = ["AES-256", "ChaCha20-Poly1305"]
                    for algo in algorithms:
                        try:
                            decrypted = decrypt_with_aes(ciphertext, key) if algo == "AES-256" else decrypt_with_chacha(ciphertext, key)
                            plain = verify_integrity(decrypted, key, salt)
                            if len(plain) < HEADER_LENGTH_SIZE:
                                raise ValueError("Decrypted data too short")
                            header_len = int.from_bytes(plain[:HEADER_LENGTH_SIZE], byteorder="big")
                            if len(plain) < HEADER_LENGTH_SIZE + header_len:
                                raise ValueError("Insufficient data for header")
                            header_json = plain[HEADER_LENGTH_SIZE:HEADER_LENGTH_SIZE + header_len].decode("utf-8", errors='strict')
                            header = json.loads(header_json)
                            if header["algorithm"] != algo:
                                continue  
                            wallets_data = plain[HEADER_LENGTH_SIZE + header_len:]
                            if not wallets_data:
                                raise ValueError("No wallet data found after decryption")
                            wallets_str = wallets_data.decode("utf-8", errors='strict')
                            wallets = json.loads(wallets_str)
                            if not isinstance(wallets, list) or not all(isinstance(w, dict) and "address" in w for w in wallets):
                                raise ValueError("Invalid wallet data format")
                            progress.setValue(75)
                            return header, wallets
                        except (CryptoError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
                            logger.debug(f"Decryption with {algo} failed: {str(e)}, data: {ciphertext.hex()[:50]}...")
                    raise CryptoError("Unable to decrypt with either algorithm")

                header, wallets = decrypt_and_validate(data, enc_key)

                if header["auth_method"] == "Password + 2FA":
                    totp_secret, ok = QInputDialog.getText(self, "TOTP Secret", "Enter your TOTP secret:")
                    if not ok or not totp_secret:
                        raise ValidationError("TOTP secret required for 2FA")
                    code, ok = QInputDialog.getText(self, "2FA Verification", "Enter TOTP code:")
                    if not ok or not code or not pyotp.TOTP(totp_secret).verify(code, valid_window=1):
                        raise ValidationError("Invalid or expired TOTP code")
                    logger.info("2FA verification successful")

                logger.info("File decrypted successfully")
                progress.setValue(100)

            progress.close()
            self.table.setRowCount(len(wallets))
            for i, w in enumerate(wallets):
                self.table.setItem(i, 0, QTableWidgetItem(w.get("address", "")))
                self.table.setItem(i, 1, QTableWidgetItem(w.get("private_key", "")))
                self.table.setItem(i, 2, QTableWidgetItem(w.get("seed_phrase", "")))
            self.output_label.setText("File decrypted successfully!")
            QMessageBox.information(self, "Success", "File decrypted successfully!")

        except (CryptoError, ValidationError, UnicodeDecodeError, json.JSONDecodeError) as e:
            progress.close()
            error_msg = f"Decryption failed: {str(e)}"
            QMessageBox.critical(self, "Decryption Failed", error_msg)
            logger.error(f"{error_msg}, data: {data.hex()[:50]}...")
            return
        except Exception as e:
            progress.close()
            error_msg = f"Unexpected error during decryption: {str(e)}"
            QMessageBox.critical(self, "Decryption Failed", error_msg)
            logger.error(f"{error_msg}, data: {data.hex()[:50]}...")
            return

    def copy_cell(self, row: int, column: int) -> None:
        """Copy the content of a table cell to the clipboard with feedback."""
        item = self.table.item(row, column)
        if item:
            text = item.text()
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", f"Copied: {text[:20]}{'...' if len(text) > 20 else ''}")
            logger.info(f"Copied cell content: {text[:20]}{'...' if len(text) > 20 else ''}")

#########################################################
#               HELPER: CSV GENERATION                  #
#########################################################

def to_csv(wallets: List[Dict]) -> str:
    """Convert wallet data to CSV format."""
    if not wallets or not isinstance(wallets, list):
        raise ValueError("Invalid wallets data for CSV conversion")
    lines = ["address,private_key,seed_phrase"]
    for w in wallets:
        if not isinstance(w, dict) or not all(k in w for k in ["address", "private_key", "seed_phrase"]):
            raise ValueError("Invalid wallet format in CSV conversion")
        lines.append(f"{w['address']},{w['private_key']},{w['seed_phrase']}")
    return "\n".join(lines)

#########################################################
#                     MAIN WINDOW                       #
#########################################################

class MainWindow(QMainWindow):
    """Main application window with navigation and wallet generation/decryption pages."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Offline Wallet Generator v1.0")
        self.setMinimumSize(900, 600)
        self.central = QStackedWidget()
        self.setCentralWidget(self.central)
        self.gen_page = GeneratePage(self)
        self.dec_page = DecryptPage(self)
        self.central.addWidget(self.gen_page)
        self.central.addWidget(self.dec_page)
        self.current_font_size = 10
        self.create_menu()
        self.create_footer()
        self.create_status_bar()
        logger.info("Main window initialized")

    def create_menu(self) -> None:
        """Create the menu bar with view and navigation options."""
        menubar = self.menuBar()
        view_menu = menubar.addMenu("View")
        zoom_in_action = view_menu.addAction("Zoom In")
        zoom_out_action = view_menu.addAction("Zoom Out")
        zoom_in_action.triggered.connect(lambda: self.change_font_size(1))
        zoom_out_action.triggered.connect(lambda: self.change_font_size(-1))
        nav_menu = menubar.addMenu("Navigation")
        gen_action = nav_menu.addAction("Generate Wallets")
        dec_action = nav_menu.addAction("Decrypt Wallets")
        gen_action.triggered.connect(lambda: self.central.setCurrentWidget(self.gen_page))
        dec_action.triggered.connect(lambda: self.central.setCurrentWidget(self.dec_page))
        help_menu = menubar.addMenu("Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)

    def create_footer(self) -> None:
        """Create the footer with credits and donation link."""
        footer = QWidget(self)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(10, 0, 10, 10)
        credit = QLabel('<a href="https://x.com/sunshinevndetta">Created by SunshineVendetta</a>')
        credit.setOpenExternalLinks(True)
        credit.setStyleSheet("color: #FFFFFF;")
        donation = QLabel('<a href="#">Donate: 0x3eCa5f038A7f32367d03A0385534ffC918E2342b</a>')
        donation.setOpenExternalLinks(False)
        donation.linkActivated.connect(self.copy_donation)
        donation.setStyleSheet("color: #FFFFFF;")
        footer_layout.addWidget(credit)
        footer_layout.addStretch()
        footer_layout.addWidget(donation)
        self.statusBar().addPermanentWidget(footer)

    def create_status_bar(self) -> None:
        """Create a status bar for operation feedback."""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready", 5000)

    def change_font_size(self, delta: int) -> None:
        """Adjust the font size of the application for better readability."""
        self.current_font_size = max(8, min(16, self.current_font_size + delta))  
        font = QFont()
        font.setPointSize(self.current_font_size)
        self.setFont(font)
        logger.debug(f"Font size changed to {self.current_font_size}")

    def copy_donation(self) -> None:
        """Copy the donation address to the clipboard with feedback."""
        donation_addr = "0x3eCa5f038A7f32367d03A0385534ffC918E2342b"
        QApplication.clipboard().setText(donation_addr)
        self.statusBar().showMessage("Donation address copied to clipboard", 5000)
        QMessageBox.information(self, "Donation", f"Donation address copied: {donation_addr}")
        logger.info("Donation address copied to clipboard")

    def show_about(self) -> None:
        """Display an about dialog with application information."""
        about_text = (
            "Offline Wallet Generator v1.0\n"
            "Created by SunshineVendetta\n"
            "A secure tool for generating and managing offline cryptocurrency wallets.\n"
            "© 2025 All rights reserved."
        )
        QMessageBox.information(self, "About Offline Wallet Generator", about_text)
        logger.info("About dialog displayed")

#########################################################
#                         MAIN                          #
#########################################################

def main() -> None:
    """Main entry point for the application with styling and error handling."""
    dark_stylesheet = """
QMainWindow { background-color: #121212; }
QWidget { background-color: #1E1E1E; }
QLabel { color: #FFFFFF; font-size: 34px; }
QLineEdit, QComboBox, QTableWidget { background-color: #252525; color: #FFFFFF; border: 1px solid #444444; border-radius: 5px; padding: 6px; }
QPushButton { background-color: #0078D4; color: #FFFFFF; border: 1px solid #005A9E; border-radius: 5px; padding: 6px; font-weight: bold; }
QPushButton:hover { background-color: #0098FF; }
QTableWidget::item { padding: 8px; }
QHeaderView::section { background-color: #292929; color: #FFFFFF; padding: 6px; border: 1px solid #444444; font-weight: bold; }
QMenuBar { background-color: #2A2A2A; color: #FFFFFF; font-size: 34px; border-bottom: 1px solid #444444; }
QMenuBar::item { background-color: transparent; padding: 6px; }
QMenuBar::item:selected { background-color: #404040; }
QMenu { background-color: #2E2E2E; border: 1px solid #444444; }
QMenu::item { padding: 6px 10px; color: #FFFFFF; }
QMenu::item:selected { background-color: #505050; }
QStatusBar { background-color: #1E1E1E; color: #FFFFFF; border-top: 1px solid #444444; font-size: 32px; }
QProgressDialog { background-color: #292929; color: #FFFFFF; border-radius: 5px; }
QMessageBox { background-color: #292929; color: #FFFFFF; }
QScrollBar:vertical { background: #2A2A2A; width: 12px; margin: 0px; border-radius: 6px; }
QScrollBar::handle:vertical { background: #5A5A5A; min-height: 20px; border-radius: 6px; }
QScrollBar::handle:vertical:hover { background: #7A7A7A; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { background: none; }
"""

    app = QApplication(sys.argv)
    app.setStyleSheet(dark_stylesheet)
    try:
        main_win = MainWindow()
        main_win.show()
        logger.info("Application started successfully")
        sys.exit(app.exec_())
    except Exception as e:
        logger.critical(f"Application failed to start: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

# Unit Tests
import unittest

class TestWalletGen(unittest.TestCase):
    """Unit tests for wallet generation and cryptographic functions."""
    def setUp(self):
        self.password = "TestPassword123!@#"
        self.salt = dynamic_salt()
        self.data = b"Test data for encryption"

    def test_key_derivation(self):
        """Test Argon2 and HKDF key derivation."""
        factor = derive_factor_argon2(self.password, self.salt)
        self.assertEqual(len(factor), KEY_LENGTH)
        master_key = derive_master_key([factor], self.salt)
        self.assertEqual(len(master_key), KEY_LENGTH)
        enc_key = derive_encryption_key(master_key, self.salt)
        self.assertEqual(len(enc_key), KEY_LENGTH)
        logger.debug("Key derivation tests passed")

    def test_aes_encryption_decryption(self):
        """Test AES-256 encryption and decryption cycle."""
        factor = derive_factor_argon2(self.password, self.salt)
        master_key = derive_master_key([factor], self.salt)
        enc_key = derive_encryption_key(master_key, self.salt)
        encrypted = encrypt_with_aes(self.data, enc_key)
        decrypted = decrypt_with_aes(encrypted, enc_key)
        self.assertEqual(self.data, decrypted)
        logger.debug("AES encryption/decryption tests passed")

    def test_chacha_encryption_decryption(self):
        """Test ChaCha20-Poly1305 encryption and decryption cycle."""
        factor = derive_factor_argon2(self.password, self.salt)
        master_key = derive_master_key([factor], self.salt)
        enc_key = derive_encryption_key(master_key, self.salt)
        encrypted = encrypt_with_chacha(self.data, enc_key)
        decrypted = decrypt_with_chacha(encrypted, enc_key)
        self.assertEqual(self.data, decrypted)
        logger.debug("ChaCha20 encryption/decryption tests passed")

    def test_integrity(self):
        """Test HMAC integrity addition and verification."""
        factor = derive_factor_argon2(self.password, self.salt)
        master_key = derive_master_key([factor], self.salt)
        enc_key = derive_encryption_key(master_key, self.salt)
        data_with_hmac = add_integrity(self.data, enc_key, self.salt)
        verified_data = verify_integrity(data_with_hmac, enc_key, self.salt)
        self.assertEqual(self.data, verified_data)
        with self.assertRaises(CryptoError):
            verify_integrity(data_with_hmac[:-1], enc_key, self.salt)  # Tampered data
        logger.debug("Integrity tests passed")

    def test_wallet_generation(self):
        """Test wallet generation with minimal data."""
        worker = WalletGenerationWorker("Private Key", 1, "", False, "AES-256 (Default)")
        worker.run()
        logger.debug("Wallet generation test passed")

if __name__ == '__main__':
    unittest.main(argv=[''], exit=False)
