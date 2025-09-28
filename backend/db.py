from sqlmodel import create_engine, SQLModel, Session
import pathlib

DB_PATH = (pathlib.Path(__file__).resolve().parent / ".." / "backend.db").resolve()
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)

def init_db():
    from . import models
    SQLModel.metadata.create_all(engine)

def get_session():
    return Session(engine)
