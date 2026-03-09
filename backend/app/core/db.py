from __future__ import annotations
import os
from sqlmodel import SQLModel, create_engine, Session

def database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./pgas.db")

DATABASE_URL = database_url()
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)

def init_db() -> None:
    SQLModel.metadata.create_all(engine)

def get_session() -> Session:
    return Session(engine)
