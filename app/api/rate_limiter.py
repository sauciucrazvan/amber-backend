from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi import FastAPI
from app import config as conf

limiter = Limiter(key_func=get_remote_address)

def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler) # type: ignore
    app.add_middleware(SlowAPIMiddleware)

def rate_limit_strict():
    return limiter.limit("5/minute")

def rate_limit_moderate():
    return limiter.limit("30/minute")

def rate_limit_relaxed():
    return limiter.limit("100/minute")

class RateLimitConfig:
    GENERAL = conf.RL_GENERAL
    CRUD = conf.RL_CRUD
    STOCK = conf.RL_STOCK
    BULK = conf.RL_BULK
    READ = conf.RL_READ
    WRITE = conf.RL_WRITE