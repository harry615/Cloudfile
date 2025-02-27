# models.py
from sqlmodel import SQLModel, Field

class UserBase(SQLModel):
    name: str = Field(index=True)
    age: int | None = Field(default=None, index=True)

class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    secret_name: str
    password_hash: str  # Placeholder for hashed password
    salt: bytes  # For key derivation
    public_key: bytes  # RSA public key
    encrypted_private_key: bytes  # RSA private key encrypted with KEK

class UserPublic(UserBase):
    id: int

class UserCreate(UserBase):
    secret_name: str

class UserUpdate(UserBase):
    name: str | None = None
    age: int | None = None
    secret_name: str | None = None

class FileRecord(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    filename: str
    file_url: str
    user_id: int = Field(foreign_key="user.id")
    encrypted_file_key: bytes  # Symmetric key encrypted with uploader's KEK

class SharedFile(SQLModel, table=True):
    id: int = Field(primary_key=True)
    file_id: int = Field(foreign_key="filerecord.id")
    user_id: int = Field(foreign_key="user.id")
    encrypted_file_key: bytes  # Symmetric key encrypted with recipient's public key
    