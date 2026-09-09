import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./database/security.db"
    
    JWT_SECRET: str = "super-secret-cns-project-jwt-key-change-in-production-2026"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 120
    
    RSA_PRIVATE_KEY_PATH: str = os.path.join("uploads", "keys", "rsa_private.pem")
    RSA_PUBLIC_KEY_PATH: str = os.path.join("uploads", "keys", "rsa_public.pem")
    
    MAX_UPLOAD_SIZE_MB: int = 50
    STORAGE_ENCRYPTED_DIR: str = os.path.join("uploads", "encrypted_files")
    STORAGE_DECRYPTED_DIR: str = os.path.join("uploads", "decrypted_files")
    
    CORS_ORIGINS: str = "http://localhost:8000,http://127.0.0.1:8000,http://localhost:8080"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
