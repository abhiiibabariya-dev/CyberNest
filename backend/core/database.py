"""Database setup."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from core.config import settings

SYNC_DB_URL = (
    settings.DATABASE_URL
    .replace("sqlite+aiosqlite", "sqlite")
    .replace("sqlite+pysqlite", "sqlite")
)
engine = create_engine(
    SYNC_DB_URL, echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in SYNC_DB_URL else {},
)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

async def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
