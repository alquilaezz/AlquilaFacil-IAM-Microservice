from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import Base, engine
from .routers import auth, users

Base.metadata.create_all(bind=engine)

app = FastAPI(title="IAM Service")

# Dominios que pueden llamar a tu API
origins = [
    "http://localhost:5173",                # para desarrollo local
    "https://alquilaezz.netlify.app",       # tu front en producción
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,          # o ["*"] si quieres permitir todos (no recomendado para prod)
    allow_credentials=True,
    allow_methods=["*"],            # GET, POST, PUT, DELETE, etc.
    allow_headers=["*"],            # "Content-Type", "Authorization", etc.
)

app.include_router(auth.router)
app.include_router(users.router)
