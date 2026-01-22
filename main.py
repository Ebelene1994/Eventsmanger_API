from fastapi import FastAPI
import cloudinary
import os
from dotenv import load_dotenv
from routes.events import events_router
from routes.users import users_router
from routes.genai import genai_router

load_dotenv()

# Configure cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
)


app = FastAPI()


@app.get("/")
def get_home():
    return {"message": "You are on the home page"}


# Include routers
app.include_router(events_router)
app.include_router(users_router)
app.include_router(genai_router)
