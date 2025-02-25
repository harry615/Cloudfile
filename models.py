# models.py
from sqlmodel import SQLModel, Field

class UserBase(SQLModel):
    name: str = Field(index=True)
    age: int | None = Field(default=None, index=True)

class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    secret_name: str

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