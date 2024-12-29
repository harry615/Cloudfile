from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlmodel import Field, Session, SQLModel, select

from database import engine, create_db_and_tables
from routes import router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    await create_db_and_tables()
    yield
    # Shutdown logic would go here, if needed

app = FastAPI(lifespan=lifespan)

app.include_router(router)
