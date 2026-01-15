from fastapi import APIRouter

router = APIRouter(prefix="/reports", tags=["reports"])

# Stub routes – add real ones later!
@router.get("/")
async def reports_root():
    return {"message": "Reports stub – dashboards coming soon!"}