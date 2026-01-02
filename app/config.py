# Server related configurations
server_address="127.0.0.1"
server_port=8000
allowed_cors_origins=["http://localhost:3000", "http://example.com"]

# Rate limiting configuration
rl_general = "100/minute"
rl_crud = "50/minute"
rl_stock = "30/minute"
rl_bulk = "10/minute"
rl_read = "150/minute"
rl_write = "20/minute"