from fastapi import UploadFile
from pydantic import BaseModel


class SendMessageData(BaseModel):
    text: str


class UpdateReadCursorData(BaseModel):
    upto_seq: int


class ReplyMessageData(BaseModel):
    message_id: str
    text: str


class DeleteMessageData(BaseModel):
    message_id: str


class EditMessageData(BaseModel):
    text: str
    message_id: str


class ReactData(BaseModel):
    emoji: str
