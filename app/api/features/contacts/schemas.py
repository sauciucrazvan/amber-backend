from pydantic import BaseModel


class RemoveContact(BaseModel):
    username: str


class BlockUser(BaseModel):
    username: str


class UnblockUser(BaseModel):
    username: str


class RequestContact(BaseModel):
    username: str


class AcceptContactRequest(BaseModel):
    username: str


class DeclineContactRequest(BaseModel):
    username: str
