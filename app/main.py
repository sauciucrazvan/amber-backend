import logging

from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware

from app.api.rate_limiter import setup_rate_limiting
from app.api.routes import test
from app import config as conf
from app.api.routes.auth import auth
from app.database import session


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)

logging.getLogger().setLevel(logging.INFO)

def create_app() -> FastAPI:
    application = FastAPI(title="Amber Backend", version="1.0.0")
    setup_rate_limiting(application)

    @application.on_event("startup")
    def _startup() -> None:
        session.initConnection()

    api_router = APIRouter(prefix="/api")
    api_router.include_router(test.router)
    api_router.include_router(auth.router)
    application.include_router(api_router)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=conf.ALLOWED_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return application


app = create_app()

def runApp():
    import uvicorn

    uvicorn.run(app, host=conf.SERVER_ADDRESS, port=conf.SERVER_PORT)

def getApp():
    return app