from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated
from dataclasses import dataclass
import bcrypt

import reflex as rx
import jwt
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.middleware.cors import CORSMiddleware
import httpx
from starlette.middleware import Middleware

SECRET_KEY = "d1476829cf5d3ea5326220b34a3d6ab78031d28f6b75d2575d9177f4e21a7fa4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# https://github.com/pyca/bcrypt/issues/684#issuecomment-2430047176
@dataclass
class SolveBugBcryptWarning:
    __version__: str = getattr(bcrypt, "__version__")


# Password hashing
setattr(bcrypt, "__about__", SolveBugBcryptWarning())
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Authentication Models
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


# User Models
class UserBase(SQLModel):
    username: str = Field(unique=True, index=True)
    email: str | None = Field(default=None)
    full_name: str | None = Field(default=None)
    disabled: bool = Field(default=False)


class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str


class UserCreate(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    password: str


class UserPublic(BaseModel):
    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool


class UserUpdate(BaseModel):
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    password: str | None = None


# Database setup
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def add_cors_middleware(fastapi_app):
    return CORSMiddleware(
        app=fastapi_app,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


def add_logging_middleware(app):
    async def middleware(scope, receive, send):
        path = scope["path"]
        print("Request:", path)
        await app(scope, receive, send)

    return middleware


# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_by_username(session: Session, username: str):
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    return user


def authenticate_user(session: Session, username: str, password: str):
    user = get_user_by_username(session, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user_by_username(session, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


CurrentUser = Annotated[User, Depends(get_current_active_user)]


# App initialization
@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    create_db_and_tables()
    yield
    print("shutting down")


fastapi_app = FastAPI(lifespan=lifespan)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


# Authentication endpoints
@fastapi_app.post("/register", response_model=UserPublic)
def register(user: UserCreate, session: SessionDep):
    # Check if user already exists
    db_user = get_user_by_username(session, user.username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@fastapi_app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep
) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@fastapi_app.get("/users/me/", response_model=UserPublic)
async def read_current_user(current_user: CurrentUser):
    return current_user


# User management endpoints (protected)
@fastapi_app.post("/users/", response_model=UserPublic)
def create_user(user: UserCreate, session: SessionDep, current_user: CurrentUser):
    # Check if user already exists
    db_user = get_user_by_username(session, user.username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@fastapi_app.get("/users/", response_model=list[UserPublic])
def read_users(
    session: SessionDep,
    current_user: CurrentUser,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    users = session.exec(select(User).offset(offset).limit(limit)).all()
    return users


@fastapi_app.get("/users/{user_id}", response_model=UserPublic)
def read_user(user_id: int, session: SessionDep, current_user: CurrentUser):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@fastapi_app.patch("/users/{user_id}", response_model=UserPublic)
def update_user(
    user_id: int,
    user_update: UserUpdate,
    session: SessionDep,
    current_user: CurrentUser,
):
    user_db = session.get(User, user_id)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    # Handle password update separately
    user_data = user_update.model_dump(exclude_unset=True, exclude={"password"})

    # Update password if provided
    if user_update.password is not None:
        user_data["hashed_password"] = get_password_hash(user_update.password)

    # Update user fields
    user_db.sqlmodel_update(user_data)
    session.add(user_db)
    session.commit()
    session.refresh(user_db)
    return user_db


@fastapi_app.delete("/users/{user_id}")
def delete_user(user_id: int, session: SessionDep, current_user: CurrentUser):
    # Prevent users from deleting themselves
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"ok": True}


# Public endpoint (no authentication required)
@fastapi_app.get("/")
def root():
    return {"message": "User Management API with Authentication"}


#############################################################
#############################################################


class State(rx.State):
    """The app state."""


class FormState(rx.State):

    @rx.event
    async def handle_login(self, form_data: dict):
        async with httpx.AsyncClient() as client:
            response = await client.post("http://127.0.0.1:8001/token", data=form_data)
            # response.raise_for_status()
            if response.status_code == 200:
                return rx.redirect("http://localhost:3001/")

    @rx.event
    async def handle_signup(self, form_data: dict):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://127.0.0.1:8001/register", json=form_data
            )
            # response.raise_for_status()
            print(response.json())
            if response.status_code == 200:
                return rx.redirect("http://localhost:3001/login")


def index() -> rx.Component:
    # Welcome Page (Index)
    return rx.container(
        rx.color_mode.button(position="top-right"),
        rx.center(
            rx.vstack(
                rx.heading("Welcome to Reflex!", size="9"),
                rx.link("login page", href="/login"),
                rx.link("signup pagae", href="/signup"),
                spacing="5",
                justify="center",
                min_height="85vh",
            ),
        ),
    )


def login() -> rx.Component:
    return rx.container(
        rx.center(
            rx.form(
                rx.vstack(
                    rx.heading("Login"),
                    rx.input(placeholder="username", name="username"),
                    rx.input(placeholder="password", name="password", type="password"),
                    rx.button("Login", type="submit"),
                    rx.link("go back home", href="/"),
                ),
                on_submit=FormState.handle_login,
                width="50%",
                display="content",
            ),
            box_sizing="content-box",
            max_inline_size="var(--measure)",
            margin_inline="auto",
            display="flex",
            flex_direction="column",
            align_items="center",
            justify="center",
            min_height="85vh",
        ),
    )


def signup() -> rx.Component:
    return rx.container(
        rx.center(
            rx.form(
                rx.vstack(
                    rx.heading("Sign Up"),
                    rx.input(placeholder="username", name="username"),
                    rx.input(placeholder="password", name="password", type="password"),
                    # rx.input(placeholder="email", name="email"),
                    # rx.input(placeholder="full name", name="full_name"),
                    # rx.input(placeholder="password again", name="password_again"),
                    rx.button("Sign up", type="submit"),
                    rx.link("go back home", href="/"),
                ),
                on_submit=FormState.handle_signup,
                width="50%",
                display="content",
            ),
            box_sizing="content-box",
            max_inline_size="var(--measure)",
            margin_inline="auto",
            display="flex",
            flex_direction="column",
            align_items="center",
            justify="center",
            min_height="85vh",
        ),
    )


app = rx.App(api_transformer=[fastapi_app, add_cors_middleware, add_logging_middleware])
app.add_page(index, route="/")
app.add_page(login, route="/login")
app.add_page(signup, route="/signup")
