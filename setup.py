from setuptools import setup

APP = ['offlinewallet.py'] 
DATA_FILES = []
OPTIONS = {
    'argv_emulation': True,
    'packages': [
        'PyQt5', 'cryptography', 'argon2', 'argon2_cffi',
        'eth_account', 'mnemonic', 'qrcode', 'zxcvbn', 'pyotp'
    ],
    'includes': [
        'PyQt5.QtWidgets', 'PyQt5.QtGui', 'PyQt5.QtCore',
        'cryptography.hazmat.primitives', 'cryptography.hazmat.backends',
        'cryptography.fernet', 'cryptography.hazmat.primitives.kdf.hkdf',
        'eth_keys', 'eth_utils', 'hexbytes'
    ],
    'excludes': ['tkinter'],
    'plist': {
        'CFBundleName': 'OfflineWallet',
        'CFBundleDisplayName': 'Offline Wallet',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0.0',
        'NSHighResolutionCapable': 'True'
    }
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
