import base64
from sqlalchemy import Column, LargeBinary, String
from sqlmodel import SQLModel, Field
from pydantic import validator


class UserBase(SQLModel):
    name: str = Field(index=True)
    age: int | None = Field(default=None, index=True)

class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    secret_name: str
    password_hash: str  # Placeholder for hashed password
    salt: bytes = Field(sa_column=Column(LargeBinary))
    public_key: bytes = Field(sa_column=Column(LargeBinary))
    encrypted_private_key: bytes = Field(sa_column=Column(LargeBinary))

class UserPublic(UserBase):
    id: int
    salt: str

    @validator('salt', pre=True, always=True)
    def encode_salt(cls, v):
        if isinstance(v, bytes):
            return base64.b64encode(v).decode("utf-8")
        return v
    
    @classmethod
    def from_orm(cls, user: User):
        # Copy the __dict__ of the user
        data = user.__dict__.copy()
        # Convert the salt field from bytes to a Base64 string if necessary.
        if "salt" in data and isinstance(data["salt"], bytes):
            data["salt"] = base64.b64encode(data["salt"]).decode("utf-8")
        # You can also convert other binary fields if needed.
        return cls(**data)

class UserSignup(UserBase):
    name: str
    age: int | None = None
    password: str

class LoginRequest(UserBase):
    name: str
    password: str

class UserCreate(UserBase):
    secret_name: str

class UserUpdate(UserBase):
    name: str | None = None
    age: int | None = None
    secret_name: str | None = None

class FileRecord(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    filename: str
    file_url: str
    user_id: int = Field(foreign_key="user.id")
    encrypted_file_key: str = Field(sa_column=Column(String(512)))
    file_key_iv: str = Field(sa_column=Column(String(128)), default="")
    file_data_iv: str = Field(sa_column=Column(String(128)), default="")
class SharedFile(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    file_id: int = Field(foreign_key="filerecord.id")
    user_id: int = Field(foreign_key="user.id")
    encrypted_file_key: str = Field(sa_column=Column(String(512)))