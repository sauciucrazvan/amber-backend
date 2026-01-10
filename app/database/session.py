from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.engine.url import make_url
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from collections.abc import Generator

import logging
import os
import time

connection = None
session = None
base = declarative_base()

logger = logging.getLogger(__name__)

def _redact_db_url(db_url: str) -> str:
    try:
        url = make_url(db_url)
        if url.password is not None:
            url = url.set(password="***")
        return str(url)
    except Exception:
        return "<unparseable db url>"

def initConnection() -> None:
    global connection, base, session
    
    os.chdir(os.path.dirname(__file__))

    db_url = os.getenv("DATABASE_URL", "postgresql://postgres@localhost/amber-db")
    logger.info("Initializing database connection")
    logger.info("Database URL: %s", _redact_db_url(db_url))

    from app.database import models as _models

    engine = create_engine(
        db_url,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=120,
    )

    connect_retries = int(os.getenv("DB_CONNECT_RETRIES", "30"))
    connect_delay_s = float(os.getenv("DB_CONNECT_DELAY_SECONDS", "1"))

    last_error: Exception | None = None
    for attempt in range(1, connect_retries + 1):
        try:
            connection = engine.connect()
            session = sessionmaker(bind=engine)
            base.metadata.create_all(engine)
            logger.info("Successfully initialized database")
            return
        except Exception as exc:
            last_error = exc
            if attempt < connect_retries:
                logger.warning(
                    "Database not ready (attempt %s/%s). Retrying in %ss",
                    attempt,
                    connect_retries,
                    connect_delay_s,
                )
                time.sleep(connect_delay_s)
            else:
                logger.exception("Failed to initialize database after retries")
                raise

def getConnection() -> Connection:
    global connection

    if connection is None:
        raise Exception("Connection not initialized. Call initConnection() first.")

    return connection

def getBase():
    global base

    if base is None:
        raise Exception("Base not initialized. Call initConnection() first.")

    return base

def getSession():
    global session

    if session is None:
        raise Exception("Session not initialized. Call initConnection() first.")
    
    return session()


def get_db() -> Generator[Session, None, None]:
    db = getSession()
    try:
        yield db
    finally:
        db.close()