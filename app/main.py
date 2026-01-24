from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from app.database_utils import get_db
from app.models import User
from app.current_user import get_current_user
from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


# --- Pydantic-схемы ---
class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., example="Иванов Иван Иванович")


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    password_repeat: str = Field(..., min_length=8)

    @validator('password_repeat')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Пароли не совпадают')
        return v


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


class UserOut(UserBase):
    id: int
    is_active: bool
    role: str

    class Config:
        orm_mode = True


# --- Приложение ---
app = FastAPI()

# --- Хэширование паролей ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# --- JWT ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Mock права ---
ROLES_PERMISSIONS = {
    "admin": ["all_access", "edit_rules"],
    "user": ["view_own_profile"]
}


def check_permission(required_permission: str):
    def permission_checker(current_user: User = Depends(get_current_user)):
        user_permissions = ROLES_PERMISSIONS.get(current_user.role, [])
        if "all_access" in user_permissions:
            return True
        if required_permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="У вас нет прав для этого действия"
            )
        return True

    return Depends(permission_checker)


# --- Эндпоинты ---

@app.post("/signup", response_model=UserOut)
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email уже зарегистрирован")

    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        password_hash=hash_password(user_data.password),
        role="user",  # роль по умолчанию
        is_active=True
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверные учетные данные или аккаунт неактивен")

    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.patch("/me", response_model=UserOut)
def update_profile(data: UserUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if data.full_name:
        current_user.full_name = data.full_name
    if data.email:
        current_user.email = data.email
    db.commit()
    db.refresh(current_user)
    return current_user


@app.delete("/me")
def delete_account(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.is_active = False
    db.commit()
    return {"detail": "Аккаунт деактивирован"}


@app.post("/logout")
def logout():
    return {"detail": "Успешный выход"}


@app.get("/admin/rules", dependencies=[check_permission("edit_rules")])
def get_access_rules():
    return {"rules": ROLES_PERMISSIONS}


@app.get("/business-data")
def get_mock_business_objects(current_user: User = Depends(get_current_user)):
    return [
        {"id": 1, "name": "Секретный отчет", "owner_id": current_user.id},
        {"id": 2, "name": "Публичный документ", "owner_id": 999}
    ]
