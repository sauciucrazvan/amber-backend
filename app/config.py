# Server related configurations
SERVER_ADDRESS="127.0.0.1"
SERVER_PORT=8000
ALLOWED_CORS_ORIGINS=["http://localhost:3000",
                      "http://localhost:5173"]

# Rate limiting configuration
RL_GENERAL = "100/minute"
RL_CRUD = "50/minute"
RL_STOCK = "30/minute"
RL_BULK = "10/minute"
RL_READ = "150/minute"
RL_WRITE = "20/minute"

# Authentication
SECRET_KEY = "f8f214371a432c553d62c0e5348b9c77b58024a33526634da9fa68aa6601f75a" # openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30