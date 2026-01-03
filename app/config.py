# Server related configurations
SERVER_ADDRESS="127.0.0.1"
SERVER_PORT=8000
ALLOWED_CORS_ORIGINS=["http://localhost:3000", "http://example.com"]

# Rate limiting configuration
RL_GENERAL = "100/minute"
RL_CRUD = "50/minute"
RL_STOCK = "30/minute"
RL_BULK = "10/minute"
RL_READ = "150/minute"
RL_WRITE = "20/minute"

# Authentication
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30