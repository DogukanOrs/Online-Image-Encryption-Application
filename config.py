"""
Configuration for the Online Image Encryption Application (IEA).
All settings in one place.
"""

# Server settings
SERVER_HOST = "0.0.0.0"       # Listen on all interfaces
SERVER_PORT = 9999            # TCP port
BUFFER_SIZE = 65536           # Max message chunk size

# RSA settings
RSA_KEY_BITS = 512            # RSA key size in bits
KEY_ROTATION_INTERVAL = 300   # Seconds between RSA key rotation (5 minutes)

# Database
DB_PATH = "iea_database.db"

# File storage
UPLOAD_FOLDER = "encrypted_images"

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
