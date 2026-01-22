from fastapi import Depends, Form, File, HTTPException, status, APIRouter
from db import events_collection
from bson.objectid import ObjectId
from utils import replace_mongo_id, genai_client
from google.genai import types
from typing import Annotated
import cloudinary
import cloudinary.uploader
from datetime import date, time
from dependencies.authn import is_authenticated
from dependencies.authz import has_roles

# Create events router
events_router = APIRouter(tags=["Events"])


# Events endpoints
@events_router.get("/events")
def get_events(query="", limit=10, skip=0):
    # Get all events from database
    events = events_collection.find(
        filter={
            "$or": [
                {"title": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}},
                {"venue": {"$regex": query, "$options": "i"}},
            ]
        },
        limit=int(limit),
        skip=int(skip),
    ).to_list()
    # Return response
    return {"data": list(map(replace_mongo_id, events))}


@events_router.post("/events", dependencies=[Depends(has_roles(["vendor", "admin"]))])
def post_event(
    title: Annotated[str, Form()],
    venue: Annotated[str, Form()],
    start_time: Annotated[time, Form()],
    end_time: Annotated[time, Form()],
    start_date: Annotated[date, Form()],
    end_date: Annotated[date, Form()],
    description: Annotated[str, Form()],
    user_id: Annotated[str, Depends(is_authenticated)],
    image: Annotated[bytes, File()] = None,
):
    # Handle when no image uploaded
    if not image:
        # Generate AI image
        response = genai_client.models.generate_images(
            model="imagen-4.0-generate-001",
            prompt=title,
            config=types.GenerateImagesConfig(number_of_images=1),
        )
        image = response.generated_images[0].image.image_bytes
    # Upload image to cloudinary to get a url
    upload_result = cloudinary.uploader.upload(image)
    # Insert event into database
    events_collection.insert_one(
        {
            "title": title,
            "venue": venue,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "image": upload_result["secure_url"],
            "description": description,
            "owner": user_id,
        }
    )
    # Return response
    return {"message": "Event added successfully"}


@events_router.get("/events/{event_id}")
def get_event_by_id(event_id):
    # Check if event id is valid
    if not ObjectId.is_valid(event_id):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid mongo id received!"
        )
    # Get event from database by id
    event = events_collection.find_one({"_id": ObjectId(event_id)})
    # Return response
    return {"data": replace_mongo_id(event)}


@events_router.get("/events/{event_id}/similar")
def get_similar_events(event_id, limit=10, skip=0):
    # Check if event id is valid
    if not ObjectId.is_valid(event_id):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid mongo id received!"
        )
    # Get event from database by id
    event = events_collection.find_one({"_id": ObjectId(event_id)})
    # Get similar events from database
    events = events_collection.find(
        filter={
            "$or": [
                {"title": {"$regex": event["title"], "$options": "i"}},
                {"description": {"$regex": event["description"], "$options": "i"}},
                {"venue": {"$regex": event["venue"], "$options": "i"}},
            ]
        },
        limit=int(limit),
        skip=int(skip),
    ).to_list()
    # Return response
    return {"data": list(map(replace_mongo_id, events))}


@events_router.put(
    "/events/{event_id}", dependencies=[Depends(has_roles(["vendor", "admin"]))]
)
def replace_event(
    event_id,
    title: Annotated[str, Form()],
    venue: Annotated[str, Form()],
    start_time: Annotated[time, Form()],
    end_time: Annotated[time, Form()],
    start_date: Annotated[date, Form()],
    end_date: Annotated[date, Form()],
    description: Annotated[str, Form()],
    user_id: Annotated[str, Depends(is_authenticated)],
    image: Annotated[bytes, File()] = None,
):
    # Check if event_id is valid mongo id
    if not ObjectId.is_valid(event_id):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid mongo id received!"
        )
    # Handle when no image uploaded
    if not image:
        # Generate AI image
        response = genai_client.models.generate_images(
            model="imagen-4.0-generate-001",
            prompt=title,
            config=types.GenerateImagesConfig(number_of_images=1),
        )
        image = response.generated_images[0].image.image_bytes
    # Upload image to cloudinary to get a url
    upload_result = cloudinary.uploader.upload(image)
    # Replace event in database
    replace_result = events_collection.replace_one(
        filter={"_id": ObjectId(event_id), "owner": user_id},
        replacement={
            "title": title,
            "venue": venue,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "image": upload_result["secure_url"],
            "description": description,
            "owner": user_id,
        },
    )
    if not replace_result.modified_count:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No event found to replace!")
    # Return reponse
    return {"message": "Event replaced successfully"}


@events_router.delete(
    "/events/{event_id}", dependencies=[Depends(has_roles(["vendor", "admin"]))]
)
def delete_event(
    event_id,
    user_id: Annotated[str, Depends(is_authenticated)],
):
    # Check if event_id is valid mongo id
    if not ObjectId.is_valid(event_id):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid mongo id received!"
        )
    # Delete event from database
    delete_result = events_collection.delete_one(
        filter={"_id": ObjectId(event_id), "owner": user_id}
    )
    if not delete_result.deleted_count:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No event found to delete!")
    # Return response
    return {"message": "Event deleted successfully!"}
