from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
from backend.router import dashboard, email, url, file

app = FastAPI(title="SCAMURAI API", version="3.0")


def get_allowed_origins() -> list[str]:
    default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    env_origins = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]
    return [*default_origins, *env_origins]

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_origin_regex=r"https://.*\.up\.railway\.app",
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email.router, prefix="/email", tags=["email"])
app.include_router(url.router, prefix="/url", tags=["url"])
app.include_router(file.router, prefix="/file", tags=["file"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, str) else "The request could not be completed."
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": detail,
            "detail": detail,
            "status_code": exc.status_code,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError):
    errors = exc.errors()
    first_error = errors[0] if errors else {}
    location = " -> ".join(str(part) for part in first_error.get("loc", [])[1:])
    issue = first_error.get("msg", "Invalid request payload.")
    detail = f"{location}: {issue}" if location else issue
    return JSONResponse(
        status_code=422,
        content={
            "message": detail,
            "detail": detail,
            "status_code": 422,
        },
    )


@app.exception_handler(Exception)
async def unexpected_exception_handler(_: Request, __: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "message": "An unexpected server error occurred while processing the request.",
            "detail": "An unexpected server error occurred while processing the request.",
            "status_code": 500,
        },
    )

@app.get("/")
def health():
    return {"status": "ok", "version": "3.0"}
