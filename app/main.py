from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware

from app.api.rate_limiter import setup_rate_limiting
from app.api.routes import test
from app import config as conf

def create_app() -> FastAPI:
    application = FastAPI(title="FastAPI Application", version="1.0.0")
    setup_rate_limiting(application)

    api_router = APIRouter(prefix="/api")
    api_router.include_router(test.router)
    application.include_router(api_router)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=conf.allowed_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return application


app = create_app()

def runApp():
    import uvicorn

    uvicorn.run(app, host=conf.server_address, port=conf.server_port)

def getApp():
    return app