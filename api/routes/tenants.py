from fastapi import APIRouter

router = APIRouter(prefix="/tenants", tags=["tenants"])

# Stub routes – add real ones later!
@router.get("/")
async def tenants_root():
    return {"message": "Tenants stub – manage teams coming soon!"}