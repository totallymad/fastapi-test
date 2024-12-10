# from fastapi import FastAPI, HTTPException, Depends
# from pydantic import BaseModel
# from sqlalchemy import create_engine, Column, Integer, String
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker, Session
# from sqlalchemy.exc import IntegrityError
# from typing import Annotated
# from fastapi import Depends, FastAPI
# from fastapi.security import OAuth2PasswordBearer

from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import bcrypt

# Создание объекта FastAPI
app = FastAPI()

# Определяем схему для авторизации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Настройка базы данных MySQL
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://isp_p_test4:12345@77.91.86.135/isp_p_test4"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Определение модели SQLAlchemy для пользователя
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    full_name = Column(String(100), nullable=True)
    hashed_password = Column(String(100))
    disabled = Column(Boolean, default=False)


# Создание таблиц в базе данных
Base.metadata.create_all(bind=engine)


# Определение Pydantic модели для пользователя
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    password: str


# Добавляем для обновления пользователя.
class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    full_name: str | None = None
    password: str | None = None
    disabled: bool | None = None


# Код для получения данных из БД
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str | None = None
    disabled: bool | None = None

    class Config:
        from_attributes = True


# Код для зашифрованного пароля
class UserInDB(UserResponse):
    hashed_password: str


# Зависимость для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# def get_users(db: Session = Depends(get_db)):
#     users = db.query(User).all()
#     if not users:
#         raise HTTPException(status_code=404, detail="Users not found")
#     return users


# Маршрут для получения пользователя по ID
# @app.get("/users/", response_model=list[UserResponse])
# def read_users(db: Session = Depends(get_db)):
#     users = db.query(User).all()
#     if not users:
#         raise HTTPException(status_code=404, detail="Пользователи не найдены")
#     return users


@app.get("/users/", response_model=list[UserResponse])
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    if not users:
        raise HTTPException(status_code=404, detail="Users not found")
    return users


def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Маршрут для создания нового пользователя
# @app.post("/users/", response_model=UserResponse)
# def create_user(user: UserCreate, db: Session = Depends(get_db)):
#     db_user = User(name=user.name, email=user.email)
#     try:
#         db.add(db_user)
#         db.commit()
#         db.refresh(db_user)
#         return db_user
#     except IntegrityError:
#         db.rollback()
#         raise HTTPException(status_code=400, detail="Email already registered")


# Маршрут для удаления пользователя по ID
@app.delete("/users/{user_id}", response_model=UserResponse)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return user


# Маршрут для обновления пользователя
@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user_update.username:
        user.username = user_update.username
    if user_update.email:
        user.email = user_update.email
    if user_update.full_name:
        user.full_name = user_update.full_name
    if user_update.password:
        user.hashed_password = fake_hash_password(user_update.password)
    if user_update.disabled is not None:
        user.disabled = user_update.disabled
    try:
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Username or Email already registered"
        )


@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}


def fake_decode_token(token):
    return User(
        username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
    )


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)
):
    user = fake_decode_token(token, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# @app.get("/users/me")
# async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
#     return current_user


@app.get("/users/me", response_model=UserResponse)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_password.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def fake_hash_password(password: str):
    return "fakehashed" + password


def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def fake_decode_token(token: str, db: Session):
    user = get_user_by_username(db, token)
    return user


@app.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return {"access_token": user.username, "token_type": "bearer"}


@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user_update.username:
        user.username = user_update.username
    if user_update.email:
        user.email = user_update.email
    if user_update.full_name:
        user.full_name = user_update.full_name
    if user_update.password:
        user.hashed_password = fake_hash_password(user_update.password)
    if user_update.disabled is not None:
        user.disabled = user_update.disabled
    try:
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Username or Email already registered"
        )


@app.post("/register/", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
    )
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Username or Email already registered"
        )
