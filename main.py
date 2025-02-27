from fastapi import Depends, FastAPI, HTTPException, Query
from database import engine, create_db_and_tables
from routes import router
from dotenv import load_dotenv
import os

load_dotenv() # Load env file
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(router)
