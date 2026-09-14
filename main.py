import os
import uuid
import enum
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt, JWTError
from passlib.context import CryptContext

DATABASE_URL = os.environ["DATABASE_URL"]
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    WAREHOUSE = "omborchi"
    OPERATOR = "operator"
    SALES = "sotuvchi"
    ACCOUNTANT = "buxgalter"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(150), nullable=False)
    username = Column(String(50), unique=True, nullable=False, index=True)
    phone = Column(String(20), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole, name="user_role"), nullable=False, default=UserRole.OPERATOR)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)class UserCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=150)
    username: str = Field(..., min_length=3, max_length=50)
    phone: str | None = None
    password: str = Field(..., min_length=6, max_length=100)
    role: UserRole = UserRole.OPERATOR


class UserOut(BaseModel):
    id: uuid.UUID
    full_name: str
    username: str
    phone: str | None
    role: UserRole
    is_active: bool

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(p: str, hashed: str) -> bool:
    return pwd_context.verify(p, hashed)


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": subject, "role": role, "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    exc = HTTPException(status_code=401, detail="Token yaroqsiz yoki muddati tugagan")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise exc
    except JWTError:
        raise exc
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if user is None or not user.is_active:
        raise exc
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Faqat admin bu amalni bajara oladi")
    return current_user


app = FastAPI(title="MetalCRM")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "app": "MetalCRM"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}@app.post("/api/auth/bootstrap-admin", response_model=UserOut, status_code=201, tags=["Auth"])
def bootstrap_admin(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.role == UserRole.ADMIN).first():
        raise HTTPException(status_code=403, detail="Admin allaqachon mavjud")
    user = User(
        full_name=payload.full_name,
        username=payload.username,
        phone=payload.phone,
        hashed_password=hash_password(payload.password),
        role=UserRole.ADMIN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/auth/register", response_model=UserOut, status_code=201, tags=["Auth"])
def register(payload: UserCreate, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Bu username band")
    user = User(
        full_name=payload.full_name,
        username=payload.username,
        phone=payload.phone,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/auth/login", response_model=Token, tags=["Auth"])
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Username yoki parol noto'g'ri")
    if not user.is_active:
        raise HTTPException(statu
