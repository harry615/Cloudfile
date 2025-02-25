# routes.py
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, File, UploadFile
from sqlmodel import Session, select
from azure.storage.blob import BlobServiceClient
import os
from database import engine
from models import User, UserCreate, UserPublic, UserUpdate, FileRecord
from fastapi.responses import StreamingResponse
import io

AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING") 
AZURE_CONTAINER_NAME = "harry61551"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]
router = APIRouter()

# Upload File Endpoint
@router.post("/users/{user_id}/upload/", response_model=FileRecord)
async def upload_user_file(user_id: int, session: SessionDep, file: UploadFile = File(...)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=file.filename)
        blob_client.upload_blob(file.file, overwrite=True)
        file_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{file.filename}"
        file_record = FileRecord(filename=file.filename, file_url=file_url, user_id=user_id)
        session.add(file_record)
        session.commit()
        session.refresh(file_record)
        return file_record
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

# List Files for a User
@router.get("/users/{user_id}/files/", response_model=list[FileRecord])
async def list_user_files(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    files = session.exec(select(FileRecord).where(FileRecord.user_id == user_id)).all()
    return files

# Download File for a User
@router.get("/users/{user_id}/files/{filename}")
async def download_user_file(user_id: int, session: SessionDep, filename: str):
    file_record = session.exec(select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found for this user")
    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
        blob_data = blob_client.download_blob().readall()
        return StreamingResponse(
            io.BytesIO(blob_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")

# Delete File for a User
@router.delete("/users/{user_id}/files/{filename}")
async def delete_user_file(user_id: int, session: SessionDep, filename: str):
    file_record = session.exec(select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found for this user")
    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
        blob_client.delete_blob()
        session.delete(file_record)
        session.commit()
        return {"message": f"File {filename} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")

# User CRUD Routes
@router.post("/users/", response_model=UserPublic)
def create_user(user: UserCreate, session: SessionDep):
    db_user = User.from_orm(user)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@router.get("/users/", response_model=list[UserPublic])
def read_users(session: SessionDep, offset: int = 0, limit: Annotated[int, Query(le=100)] = 100):
    users = session.exec(select(User).offset(offset).limit(limit)).all()
    return users

@router.get("/users/{user_id}", response_model=UserPublic)
def read_user(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.patch("/users/{user_id}", response_model=UserPublic)
def update_user(user_id: int, user: UserUpdate, session: SessionDep):
    user_db = session.get(User, user_id)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    user_data = user.model_dump(exclude_unset=True)
    user_db.sqlmodel_update(user_data)
    session.add(user_db)
    session.commit()
    session.refresh(user_db)
    return user_db

@router.delete("/users/{user_id}")
def delete_user(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"ok": True}