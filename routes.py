# routes.py
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, File, UploadFile
from sqlmodel import Session, select
from azure.storage.blob import BlobServiceClient
import os
from database import engine
from models import User, UserCreate, UserPublic, UserUpdate, FileRecord, SharedFile
from fastapi.responses import StreamingResponse
from crypto_utils import derive_key, generate_key_pair, serialize_public_key, serialize_private_key, load_public_key, load_private_key, encrypt_file_key, decrypt_file_key, encrypt_file, decrypt_file
from cryptography.fernet import Fernet
import io

AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = "harry61551"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]
router = APIRouter()

# Create User with Key Pair
@router.post("/users/", response_model=UserPublic)
def create_user(user: UserCreate, session: SessionDep):
    # Create User object without from_orm, manually set fields
    db_user = User(
        name=user.name,
        age=user.age,
        secret_name=user.secret_name,
        password_hash="hashed_" + user.secret_name  # Placeholder
    )
    db_user.salt = os.urandom(16)
    private_key, public_key = generate_key_pair()
    db_user.public_key = serialize_public_key(public_key)
    kek = derive_key("testpassword", db_user.salt)  # Simulate password
    cipher = Fernet(kek)
    db_user.encrypted_private_key = cipher.encrypt(serialize_private_key(private_key))
    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

# Upload Encrypted File
@router.post("/users/{user_id}/upload/", response_model=FileRecord)
async def upload_user_file(user_id: int, session: SessionDep, file: UploadFile = File(...)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        # Simulate client-side encryption
        file_data = await file.read()
        file_key = Fernet.generate_key()
        encrypted_data = encrypt_file(file_data, file_key)

        # Encrypt file_key with uploader's KEK
        kek = derive_key("testpassword", user.salt)
        kek_cipher = Fernet(kek)
        encrypted_file_key = kek_cipher.encrypt(file_key)

        # Upload to Azure
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=file.filename)
        blob_client.upload_blob(encrypted_data, overwrite=True)
        file_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{file.filename}"
        
        file_record = FileRecord(
            filename=file.filename,
            file_url=file_url,
            user_id=user_id,
            encrypted_file_key=encrypted_file_key
        )
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
    
    # Files owned by the user
    owned_files = session.exec(select(FileRecord).where(FileRecord.user_id == user_id)).all()
    
    # Files shared with the user
    shared_files = session.exec(
        select(FileRecord)
        .join(SharedFile)
        .where(SharedFile.user_id == user_id)
    ).all()
    
    # Combine and deduplicate by id
    seen_ids = set()
    all_files = []
    for file in owned_files + shared_files:
        if file.id not in seen_ids:
            seen_ids.add(file.id)
            all_files.append(file)
    return all_files

#Download File
@router.get("/users/{user_id}/files/{filename}")
async def download_user_file(user_id: int, session: SessionDep, filename: str):
    file_record = session.exec(select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)).first()
    shared_record = None
    if not file_record:
        shared_record = session.exec(select(SharedFile).join(FileRecord).where(SharedFile.user_id == user_id, FileRecord.filename == filename)).first()
        if not shared_record:
            raise HTTPException(status_code=404, detail="File not found for this user")
        file_record = session.get(FileRecord, shared_record.file_id)

    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
        encrypted_data = blob_client.download_blob().readall()

        # Get the user (owner or recipient)
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Decrypt the symmetric file key
        kek = derive_key("testpassword", user.salt)
        cipher = Fernet(kek)

        if file_record.user_id == user_id:  # Owner
            file_key = cipher.decrypt(file_record.encrypted_file_key)
        else:  # Shared recipient
            private_key = load_private_key(cipher.decrypt(user.encrypted_private_key))
            file_key = decrypt_file_key(shared_record.encrypted_file_key, private_key)

        # Decrypt the file
        decrypted_data = decrypt_file(encrypted_data, file_key)

        return StreamingResponse(
            io.BytesIO(decrypted_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")

# Delete File for a User
@router.delete("/users/{user_id}/files/{filename}")
async def delete_user_file(user_id: int, session: SessionDep, filename: str):
    # Check if user owns the file
    file_record = session.exec(select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)).first()
    
    if file_record:  # User is the owner
        try:
            # Delete all shared instances first
            shared_files = session.exec(select(SharedFile).where(SharedFile.file_id == file_record.id)).all()
            for shared_file in shared_files:
                session.delete(shared_file)
            
            # Delete the blob from Azure
            blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=filename)
            blob_client.delete_blob()
            
            # Delete the FileRecord
            session.delete(file_record)
            session.commit()
            return {"message": f"File {filename} and all shares deleted successfully"}
        except Exception as e:
            session.rollback()
            raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")
    
    else:  # User is a recipient, delete shared access
        shared_record = session.exec(
            select(SharedFile)
            .join(FileRecord)
            .where(SharedFile.user_id == user_id, FileRecord.filename == filename)
        ).first()
        if not shared_record:
            raise HTTPException(status_code=404, detail="File not found for this user")
        try:
            session.delete(shared_record)
            session.commit()
            return {"message": f"Shared access to {filename} removed successfully"}
        except Exception as e:
            session.rollback()
            raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")

@router.post("/users/{user_id}/share/{filename}")
async def share_file(user_id: int, filename: str, recipient_id: int, session: SessionDep):
    file_record = session.exec(select(FileRecord).where(FileRecord.user_id == user_id, FileRecord.filename == filename)).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found or not owned by this user")
    
    user = session.get(User, user_id)
    recipient = session.get(User, recipient_id)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Decrypt file_key with uploader's KEK
    kek = derive_key("testpassword", user.salt)
    cipher = Fernet(kek)
    file_key = cipher.decrypt(file_record.encrypted_file_key)

    # Encrypt file_key with recipient's public key
    recipient_public_key = load_public_key(recipient.public_key)
    shared_file_key = encrypt_file_key(file_key, recipient_public_key)

    # Store shared key
    shared = SharedFile(file_id=file_record.id, user_id=recipient_id, encrypted_file_key=shared_file_key)
    session.add(shared)
    session.commit()
    return {"message": f"File {filename} shared successfully"}

# User CRUD Routes

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