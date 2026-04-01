from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.router import dashboard, email, url, file

app = FastAPI(title="SCAMURAI API", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email.router, prefix="/email", tags=["email"])
app.include_router(url.router, prefix="/url", tags=["url"])
app.include_router(file.router, prefix="/file", tags=["file"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])

@app.get("/")
def health():
    return {"status": "ok", "version": "3.0"}
