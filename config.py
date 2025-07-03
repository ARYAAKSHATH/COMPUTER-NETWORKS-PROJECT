# Simple config for chat app
import os

# Server settings
HOST = os.getenv('HOST', 'localhost')
PORT = int(os.getenv('PORT', 9999))
MAX_CLIENTS = int(os.getenv('MAX_CLIENTS', 20))

# Database
DB_FILE = os.getenv('DB_FILE', 'chat.db')

# File limits
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = ['.txt', '.jpg', '.png', '.pdf', '.doc']

# Security
MIN_PASSWORD_LEN = 4
SESSION_TIMEOUT = 3600  # 1 hour

def check_config():
    """Basic config validation"""
    if PORT < 1024 or PORT > 65535:
        raise ValueError("Port must be between 1024-65535")
    
    if MAX_FILE_SIZE < 1024:
        raise ValueError("File size too small")
    
    return True

if __name__ == "__main__":
    try:
        check_config()
        print("Config OK")
    except ValueError as e:
        print(f"Config error: {e}")