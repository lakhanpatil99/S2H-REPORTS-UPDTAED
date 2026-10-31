from fastapi import APIRouter
from app.api.v1.endpoints import auth, device, telemetry

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(device.router, prefix="/device", tags=["Device"])
api_router.include_router(telemetry.router, prefix="/telemetry", tags=["Telemetry"])
