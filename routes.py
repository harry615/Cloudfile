from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, File, UploadFile, Header
from sqlmodel import Session, select
import os, io
from fastapi.responses import StreamingResponse
from database import engine
from models import User, UserPublic, FileRecord, SharedFile , UserSignup , LoginRequest, DownloadFileResponse ,ShareRequest, SharedDownloadResponse
from datetime import datetime, timedelta
from azure.storage.blob import generate_blob_sas, BlobSasPermissions, BlobServiceClient
from urllib.parse import unquote
import base64
import logging
from fastapi import Form

logging.basicConfig(level=logging.INFO)

router = APIRouter()

# Azure Blob Storage configuration
AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
AZURE_ACCOUNT_KEY = os.environ.get("AZURE_ACCOUNT_KEY")
if not AZURE_ACCOUNT_KEY:
    raise Exception("AZURE_ACCOUNT_KEY is not set or empty!")

AZURE_CONTAINER_NAME = "harry61551"
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)

# Dependency for DB session
def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]


#SAS URL helper function 
def generate_file_share_link(blob_name: str, expiry_minutes: int = 60) -> str:
    
    sas_token = generate_blob_sas(
        account_name=blob_service_client.account_name,
        container_name=AZURE_CONTAINER_NAME,
        blob_name=blob_name,
        account_key=AZURE_ACCOUNT_KEY,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(minutes=expiry_minutes)
    )
    blob_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{blob_name}"
    share_link = f"{blob_url}?{sas_token}"
    return share_link

# ------------------------------------------------------------------
# User Signup and Login Endpoints (unchanged)
# ------------------------------------------------------------------

@router.post("/users/signup", response_model=UserPublic)
def signup_user(user: UserSignup, session: SessionDep):
    db_user = User(
        name=user.name,
        age=user.age,
        secret_name=user.name,  # Using name for login.
        password_hash= user.password,  # Placeholder hash.
        salt=base64.b64decode(user.salt),
        public_key=base64.b64decode(user.public_key) if not user.public_key.startswith("-----BEGIN") else user.public_key.encode(),
        encrypted_private_key=base64.b64decode(user.encrypted_private_key),
        iv=base64.b64decode(user.iv)
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)


    logging.info(f"Salt (base64): {base64.b64encode(db_user.salt).decode('utf-8')}")
    logging.info(f"IV (base64): {base64.b64encode(db_user.iv).decode('utf-8')}")
    logging.info(f"Public Key (base64): {base64.b64encode(db_user.public_key).decode('utf-8')}")

    return UserPublic.from_orm(db_user)

@router.post("/users/login", response_model=UserPublic)
def login_user(login_data: LoginRequest, session: SessionDep):
    user = session.exec(select(User).where(User.name == login_data.name)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.password_hash != login_data.password:
        raise HTTPException(status_code=401, detail="Incorrect password")
    return UserPublic.from_orm(user)

# ------------------------------------------------------------------
# File Operations Endpoints
# ------------------------------------------------------------------
@router.get("/users/{user_id}/files/", response_model=list[FileRecord])
async def list_user_files(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    owned_files = session.exec(select(FileRecord).where(FileRecord.user_id == user_id)).all()
    shared_files = session.exec(
        select(FileRecord)
        .join(SharedFile)
        .where(SharedFile.user_id == user_id)
    ).all()
    
    seen_ids = set()
    all_files = []
    for file in owned_files + shared_files:
        if file.id not in seen_ids:
            seen_ids.add(file.id)
            all_files.append(file)
    return all_files

# Upload endpoint – accepts encrypted file and encryption metadata from the client.
@router.post("/users/{user_id}/upload/", response_model=FileRecord)
async def upload_user_file(
    user_id: int,
    session: SessionDep,
    file: UploadFile = File(...),
    encrypted_file_key: str = Form(...),
    file_key_iv: str = Form(...),
    file_data_iv: str = Form(...)
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        file_data = await file.read()
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=file.filename)
        blob_client.upload_blob(file_data, overwrite=True)
        file_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{file.filename}"
        
        # Save a FileRecord with encryption metadata.
        file_record = FileRecord(
            filename=file.filename,
            file_url=file_url,
            user_id=user_id,
            encrypted_file_key=encrypted_file_key,
            file_key_iv=file_key_iv,
            file_data_iv=file_data_iv
        )
        logging.info("Received headers Upload backend:")
        logging.info(f"X-Encrypted-File-Key: {encrypted_file_key}")
        logging.info(f"X-File-Key-IV: {file_key_iv}")
        logging.info(f"X-File-Data-IV: {file_data_iv}")

        session.add(file_record)
        session.commit()
        session.refresh(file_record)
        return file_record
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

# Download endpoint – retrieves the encrypted file and returns the stored encryption metadata in response headers.
@router.get("/users/{user_id}/files/{filename}/download", response_model=DownloadFileResponse)
async def download_user_file(user_id: int, session: SessionDep, filename: str):
    file_record = session.exec(
        select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)
    ).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
        encrypted_data = blob_client.download_blob().readall()
        """headers = {
            "Content-Disposition": f"attachment; filename={filename}",
            "X-Encrypted-File-Key": file_record.encrypted_file_key,
            "X-File-Key-IV": file_record.file_key_iv,
            "X-File-Data-IV": file_record.file_data_iv,
        }
        logging.info("Received headers Backend :")
        logging.info(f"X-Encrypted-File-Key: {file_record.encrypted_file_key}")
        logging.info(f"X-File-Key-IV: {file_record.file_key_iv}")
        logging.info(f"X-File-Data-IV: {file_record.file_data_iv}")

        return StreamingResponse(io.BytesIO(encrypted_data), media_type="application/octet-stream", headers=headers)"
        """
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Return all the metadata in the response body as JSON.
        return DownloadFileResponse(
            file_data=encrypted_data_b64,
            encrypted_file_key=file_record.encrypted_file_key,
            file_key_iv=file_record.file_key_iv,
            file_data_iv=file_record.file_data_iv,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")
@router.get("/shared-files/{recipient_id}/{filename}/download", response_model=SharedDownloadResponse)
async def download_shared_file(recipient_id: int, filename: str, session: SessionDep):
    # Look up the shared file record (join SharedFile and FileRecord)
    shared_record = session.exec(
        select(SharedFile)
        .join(FileRecord)
        .where(SharedFile.user_id == recipient_id, FileRecord.filename == filename)
    ).first()
    if not shared_record:
        raise HTTPException(status_code=404, detail="Shared file not found")
    file_record = session.get(FileRecord, shared_record.file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="File record not found")
    
    try:
        # Retrieve the encrypted file data from Azure.
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
        encrypted_data = blob_client.download_blob().readall()
        # Return a JSON response with the Base64-encoded file data and metadata.
        return SharedDownloadResponse(
            file_data=base64.b64encode(encrypted_data).decode("utf-8"),
            encrypted_file_key=shared_record.encrypted_file_key,
            file_data_iv=file_record.file_data_iv,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Shared file download failed: {str(e)}")
    
# Delete endpoint – deletes the file record and its blob.
@router.delete("/users/{user_id}/files/{filename}")
async def delete_user_file(user_id: int, session: SessionDep, filename: str):
    file_record = session.exec(
        select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)
    ).first()
    if not file_record:
        shared_file = session.exec(select(SharedFile).join(FileRecord)
        .where(SharedFile.user_id == user_id, FileRecord.filename == filename)
    ).first()
        session.delete(shared_file)
        session.commit()
        return {"message": f"File {filename} removed from your shared files"}
    if not shared_file:
        raise HTTPException(status_code=404, detail="File not found")
    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
        try:
            blob_client.delete_blob()
        except Exception as blob_error:
            print(f"Warning: blob deletion failed for {filename}: {blob_error}")

        # Delete any shared file entries referencing this file record.
        shared_files = session.exec(
            select(SharedFile).where(SharedFile.file_id == file_record.id)
        ).all()
        for shared in shared_files:
            session.delete(shared)

        session.flush()

        session.delete(file_record)
        session.commit()
        return {"message": f"File {filename} deleted successfully"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")


@router.post("/users/{user_id}/share/{filename}")
async def share_file(user_id: int, filename: str, recipient_id: int,share_req: ShareRequest, session: SessionDep):
    file_record = session.exec(
        select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)
    ).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found or not owned by this user")
    
    recipient = session.get(User, recipient_id)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Create a SharedFile record without encryption details.
    shared = SharedFile(
        file_id=file_record.id,
        user_id=recipient_id,
        encrypted_file_key=share_req.shared_file_key
    )
    session.add(shared)
    session.commit()
    
    return {"message": f"File {filename} shared successfully"}

@router.get("/users/{user_id}/files/{filename}/shareLink")
async def get_file_share_link(user_id: int, filename: str,session: SessionDep, expiry: int = 60):
    # Verify that the file exists and that the user is allowed to share it.
    filename = unquote(filename)
    file_record = session.exec(
        select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)
    ).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        share_link = generate_file_share_link(filename, expiry_minutes=expiry)
        return {"share_link": share_link, "expiry_minutes": expiry}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not generate share link: {str(e)}")
# ------------------------------------------------------------------
# Additional User Endpoints
# ------------------------------------------------------------------

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

@router.get("/users/by-name/{username}", response_model=UserPublic)
def get_user_by_name(username: str, session: SessionDep):
    user = session.exec(select(User).where(User.name == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserPublic.from_orm(user)

@router.patch("/users/{user_id}", response_model=UserPublic)
def update_user(user_id: int, user: UserPublic, session: SessionDep):
    user_db = session.get(User, user_id)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    user_data = user.dict(exclude_unset=True)
    for key, value in user_data.items():
        setattr(user_db, key, value)
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
