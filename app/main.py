import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware

from app.api.rate_limiter import setup_rate_limiting
from app import config as conf
from app.api.features import account, contacts, auth, chats, calls
from app.database import session
from app.ws import connection_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)

logging.getLogger().setLevel(logging.INFO)

def create_app(*, init_db: bool = True, enable_rate_limiting: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if init_db:
            session.initConnection()
        yield

    application = FastAPI(title="Amber Backend", version="1.0.0", lifespan=lifespan)
    if enable_rate_limiting:
        setup_rate_limiting(application)

    api_router = APIRouter(prefix="/api")
    
    api_router.include_router(auth.router)
    api_router.include_router(account.router)
    api_router.include_router(contacts.router)
    api_router.include_router(chats.router)
    api_router.include_router(calls.router)

    application.include_router(api_router)
    application.include_router(connection_manager.router)

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

    uvicorn.run(app, host=conf.SERVER_ADDRESS, port=conf.SERVER_PORT, ws="wsproto")

def getApp():
    return app