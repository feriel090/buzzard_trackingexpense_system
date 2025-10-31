import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'buzzard.db'
UPLOAD_FOLDER = BASE_DIR / 'uploads'
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','pdf'}
SECRET_KEY = os.environ.get('BUZZARD_SECRET', 'change-me-in-production')
MAX_CONTENT_LENGTH = 8 * 1024 * 1024
# Email (optional) - set environment variables in production
SMTP_HOST = os.environ.get('SMTP_HOST')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587) or 587)
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')
