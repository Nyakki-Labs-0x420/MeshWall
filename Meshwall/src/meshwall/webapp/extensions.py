import os
import base64
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from meshwall.models import Base
from meshwall.db import engine, init_db

db = SQLAlchemy(model_class=Base)

FIXED_SALT = bytes.fromhex(
    os.environ.get('MESHWALL_SALT',
                   '[PLACE-UR-SALT-HERE-XP]')
)

class SecureStorage:
    def __init__(self, passphrase: str):
        self.key = hash_secret_raw(
            secret=passphrase.encode(),
            salt=FIXED_SALT,
            time_cost=4,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, ciphertext: str) -> str:
        raw = base64.b64decode(ciphertext)
        nonce, ct = raw[:12], raw[12:]
        return self.aesgcm.decrypt(nonce, ct, None).decode()

def init_extensions(app):
    db.init_app(app)
    # Ensure all tables exist 
    init_db()
    passphrase = os.environ.get('MESHWALL_ENCRYPTION_KEY', 'meshwall-default')
    app.config['encryptor'] = SecureStorage(passphrase)