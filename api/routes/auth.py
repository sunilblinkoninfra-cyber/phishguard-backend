from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])

# Stub routes – add real ones later!
@router.get("/")
async def auth_root():
    return {"message": "Auth stub – login/register coming soon!"}