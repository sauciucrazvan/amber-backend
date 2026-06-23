from pydantic import BaseModel


class ModifyPassword(BaseModel):
    current_password: str
    new_password: str
    new_password_confirmation: str


class ModifyFullname(BaseModel):
    new_full_name: str


class EmailChangeRequest(BaseModel):
    new_email: str
    password: str


class EmailChangeConfirm(BaseModel):
    code: str


class EmailChangeVerify(BaseModel):
    code: str


class DeleteAccount(BaseModel):
    password: str


class RecoveryRequest(BaseModel):
    username: str


class ResetRequest(BaseModel):
    username: str
    code: str
    new_password: str
    new_password_confirmation: str


class ModifyBio(BaseModel):
    new_bio: str

class PrivacySetting(BaseModel):
    setting: str
    value: bool