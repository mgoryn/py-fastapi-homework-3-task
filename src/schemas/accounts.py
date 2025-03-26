from pydantic import BaseModel, field_validator

from database.validators.accounts import validate_password_strength, validate_email


class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)

    @field_validator("email")
    def validate_email(cls, value):
        return validate_email(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str

    @field_validator("email")
    def validate_email(cls, value):
        return validate_email(value)


class PasswordResetRequestSchema(BaseModel):
    email: str

    @field_validator("email")
    def validate_email(cls, value):
        return validate_email(value)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)

    @field_validator("email")
    def validate_email(cls, value):
        return validate_email(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str