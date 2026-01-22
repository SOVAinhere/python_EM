from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database import engine, SessionLocal
from models import Base, User

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok"}


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)
