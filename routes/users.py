from email.message import EmailMessage
from enum import Enum
import smtplib
from fastapi import APIRouter, Form, status, HTTPException, Depends
from typing import Annotated
from pydantic import EmailStr
from db import users_collection
import bcrypt
import jwt
import os
from utils import replace_mongo_id
from dependencies.authn import authenticated_user


class UserRole(str, Enum):
    VENDOR = "vendor"
    CUSTOMER = "customer"


# Create users router
users_router = APIRouter(tags=["Users"])


# Define endpoints
@users_router.post("/users/register")
def register_user(
    username: Annotated[str, Form()],
    email: Annotated[EmailStr, Form()],
    password: Annotated[str, Form(min_length=8)],
    role: Annotated[UserRole, Form()] = UserRole.CUSTOMER,
):
    # Ensure user does not exist
    user_count = users_collection.count_documents(filter={"email": email})
    if user_count > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "User already exist!")
    # Hash user password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    # Save user into database
    users_collection.insert_one(
        {
            "username": username,
            "email": email,
            "password": hashed_password,
            "role": role,
        }
    )
    # Return response
    return {"message": "User registered successfully!"}


@users_router.post("/users/login")
def login_user(
    email: Annotated[EmailStr, Form()],
    password: Annotated[str, Form(min_length=8)],
):
    # Ensure user exist
    user = users_collection.find_one(filter={"email": email})
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User does not exist!")
    # Compare their password
    correct_password = bcrypt.checkpw(password.encode(), user["password"])
    if not correct_password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials!")
    # Generate for them an access token
    encoded_jwt = jwt.encode(
        {"id": str(user["_id"])}, os.getenv("JWT_SECRET_KEY"), "HS256"
    )
    # Prepare user info to return
    user_info = replace_mongo_id(user)
    del user_info["password"]
    # Return reponse
    return {
        "message": "User logged in successfully!",
        "access_token": encoded_jwt,
        "user": user_info,
    }


@users_router.post("/users/forgot_password")
def send_reset_password_email(email: Annotated[EmailStr, Form()]):
    # Ensure user exist
    user = users_collection.find_one(filter={"email": email})
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User does not exist!")
    # Create the email message-This send a password-reset email.
    msg = EmailMessage()
    from_addr = os.getenv("SMTP_FROM") or os.getenv("SMTP_USERNAME") or "noreply@example.com"
    msg["From"] = from_addr
    msg["To"] = user["email"]
    msg["Subject"] = "[Important] Password Reset"
    msg.set_content(
        f"Dear {user['username']},\nWe are sorry to know that you have forgotten your password.\nPlease follow the steps below to change your password!"
    )
    # Send password reset email
    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        with smtplib.SMTP(os.getenv("SMTP_HOST"), smtp_port) as server:
            server.starttls()
            server.login(os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASSWORD"))
            server.send_message(msg=msg)
        # Return reponse
        return {"message": "Password reset email sent successfully!"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_417_EXPECTATION_FAILED, detail=str(e)
        )


@users_router.get("/users/me")
def user_info(user: Annotated[dict, Depends(authenticated_user)]):
    # Prepare user info to return
    del user["password"]
    # Return reponse
    return user
