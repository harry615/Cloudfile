import os
from sqlmodel import SQLModel, create_engine
from models import User, FileRecord , SharedFile # Added imports for schema creation

# Azure Database connection string 
DATABASE_URL = os.environ.get("DATABASE_URL")

# Create the engine
engine = create_engine(DATABASE_URL, echo=True)

def create_db_and_tables():
    # Drop all tables first (development only) remember to remove later 
    SQLModel.metadata.drop_all(engine)
    # Then recreate them
    SQLModel.metadata.create_all(engine)

