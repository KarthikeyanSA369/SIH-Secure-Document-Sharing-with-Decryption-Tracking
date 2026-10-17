import os
import json
from pathlib import Path
from typing import Optional, Dict

class KeyStore:
    """
    Secure server-side keystore for post-quantum private keys.
    Private keys are never sent over the network or stored in plaintext in the database.
    """
    def __init__(self, keystore_dir: str = "../storage/keystore"):
        self.keystore_dir = Path(keystore_dir)
        self.keystore_dir.mkdir(parents=True, exist_ok=True)
        self._store_file = self.keystore_dir / "keys.json"
        self._ensure_store()

    def _ensure_store(self):
        if not self._store_file.exists():
            with open(self._store_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def _read_all(self) -> Dict[str, dict]:
        try:
            with open(self._store_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_all(self, data: Dict[str, dict]):
        with open(self._store_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_user_keys(self, user_id: str, ml_kem_sk: str, ml_dsa_sk: Optional[str] = None):
        """Save a user's post-quantum private keys in the secure keystore."""
        data = self._read_all()
        data[user_id] = {
            "ml_kem_sk": ml_kem_sk,
            "ml_dsa_sk": ml_dsa_sk
        }
        self._write_all(data)

    def get_user_kem_sk(self, user_id: str) -> Optional[str]:
        """Retrieve a user's ML-KEM-768 secret key."""
        data = self._read_all()
        return data.get(user_id, {}).get("ml_kem_sk")

    def get_user_dsa_sk(self, user_id: str) -> Optional[str]:
        """Retrieve a user's ML-DSA-65 secret key."""
        data = self._read_all()
        return data.get(user_id, {}).get("ml_dsa_sk")

    def get_server_signing_key(self) -> Optional[str]:
        """Retrieve the system server signing ML-DSA-65 secret key."""
        data = self._read_all()
        return data.get("server_system", {}).get("ml_dsa_sk")

    def save_server_signing_key(self, ml_dsa_sk: str, ml_dsa_pk: str):
        """Save the system server ML-DSA-65 keypair."""
        data = self._read_all()
        data["server_system"] = {
            "ml_dsa_sk": ml_dsa_sk,
            "ml_dsa_pk": ml_dsa_pk
        }
        self._write_all(data)
