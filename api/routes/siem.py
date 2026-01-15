from fastapi import APIRouter

router = APIRouter(prefix="/siem", tags=["siem"])

# Stub routes – add real ones later!
@router.get("/")
async def siem_root():
    return {"message": "SIEM stub – logs & alerts coming soon!"}