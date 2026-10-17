import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

class Settings:
    # Database
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "karthi1")
    DB_NAME: str = os.getenv("DB_NAME", "secureshare")

    # JWT Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "secureshare_pqc_super_secret_jwt_key_2026_x8f92a1")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

    # File Storage Paths
    STORAGE_PATH: Path = BASE_DIR / os.getenv("STORAGE_PATH", "../storage/encrypted")
    KEYSTORE_PATH: Path = BASE_DIR / os.getenv("KEYSTORE_PATH", "../storage/keystore")

    @property
    def database_url(self) -> str:
        # Standard MySQL connection URL with pymysql driver
        return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset=utf8mb4"

settings = Settings()

# Ensure directories exist
settings.STORAGE_PATH.mkdir(parents=True, exist_ok=True)
settings.KEYSTORE_PATH.mkdir(parents=True, exist_ok=True)
