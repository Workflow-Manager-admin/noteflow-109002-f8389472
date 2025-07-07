from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr, ValidationError
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from datetime import datetime, timedelta
import os

# === Environment & Secrets ===
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day token
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./notes_app.db")  # Use SQLite by default

# === Database setup ===
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# === Models ===

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(256), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    notes = relationship("Note", back_populates="owner", cascade="all, delete")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="notes")

# Create tables if not existing
Base.metadata.create_all(bind=engine)

# === Auth utilities ===

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === Schemas ===

class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Type of token, always 'bearer'")

class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User email address")

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="User password")

class UserOut(UserBase):
    id: int

    class Config:
        orm_mode = True

class NoteBase(BaseModel):
    title: str = Field(..., description="Note title")
    content: Optional[str] = Field("", description="Note content")

class NoteCreate(NoteBase):
    pass

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Note title (optional)")
    content: Optional[str] = Field(None, description="Note content (optional)")

class NoteOut(NoteBase):
    id: int
    created_at: datetime
    updated_at: datetime
    owner_id: int

    class Config:
        orm_mode = True

# === FastAPI App ===
app = FastAPI(
    title="Notes Backend API",
    description="A Notes API backend with user authentication and CRUD endpoints.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "Authentication: Register/Login"},
        {"name": "notes", "description": "Notes CRUD Operations"},
    ],
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Adjust for production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Helper functions for user management ===

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

async def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# === ROUTES ===

# HEALTH CHECK
# PUBLIC_INTERFACE
@app.get("/", tags=["health"], summary="Health Check")
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}

# AUTH

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserOut, tags=["auth"], summary="Register a new user")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with email and password."""
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(email=user.email, hashed_password=get_password_hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=Token, tags=["auth"], summary="User login to obtain JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login user and return access JWT token."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

# NOTES

# PUBLIC_INTERFACE
@app.get("/notes", response_model=List[NoteOut], tags=["notes"], summary="Get all notes for current user")
def get_notes(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get all notes belonging to the current user."""
    return db.query(Note).filter(Note.owner_id == current_user.id).order_by(Note.created_at.desc()).all()

# PUBLIC_INTERFACE
@app.post("/notes", response_model=NoteOut, tags=["notes"], summary="Create a new note")
def create_note(note: NoteCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new note for the current user."""
    db_note = Note(title=note.title, content=note.content, owner_id=current_user.id)
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note

# PUBLIC_INTERFACE
@app.get("/notes/{note_id}", response_model=NoteOut, tags=["notes"], summary="Get a note by ID")
def get_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get a single note by its ID (must belong to the current user)."""
    db_note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    return db_note

# PUBLIC_INTERFACE
@app.put("/notes/{note_id}", response_model=NoteOut, tags=["notes"], summary="Update a note by ID")
def update_note(
    note_id: int,
    note_in: NoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a note (title/content) by its ID (must belong to the current user)."""
    db_note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    if note_in.title is not None:
        db_note.title = note_in.title
    if note_in.content is not None:
        db_note.content = note_in.content
    db.commit()
    db.refresh(db_note)
    return db_note

# PUBLIC_INTERFACE
@app.delete("/notes/{note_id}", status_code=204, tags=["notes"], summary="Delete a note by ID")
def delete_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a note by its ID (must belong to the current user)."""
    db_note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(db_note)
    db.commit()
    return None

# PUBLIC_INTERFACE
@app.get("/auth/me", response_model=UserOut, tags=["auth"], summary="Get current user info")
def read_users_me(current_user: User = Depends(get_current_user)):
    """Get the details of the currently authenticated user."""
    return UserOut.from_orm(current_user)

# PUBLIC_INTERFACE
@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_json():
    """Serves OpenAPI JSON for tooling and frontend integration."""
    return get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
        description=app.description,
    )

# === Error handlers ===

@app.exception_handler(ValidationError)
async def validation_exception_handler(request, exc):
    return HTTPException(
        status_code=422,
        detail={"errors": exc.errors(), "body": exc.body},
    )

# === Swagger README Route (API usage hint for websocket–not used here but good practice) ===

@app.get("/docs/help", tags=["health"], summary="API usage help and notes.")
def docs_help():
    """API usage help text for clients."""
    return {
        "api": "This API provides authentication and notes management endpoints. Register/login, then use the Bearer token for /notes endpoints.",
        "authentication": "Send Authorization: Bearer <token> with each notes request.",
        "token_hint": "Token is acquired from /auth/login (username=email, password)",
        "frontend": "See README or frontend implementation for integration instructions.",
    }
