from pathlib import Path
import sys

from fastapi import FastAPI


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCAMURAI_ROOT = PROJECT_ROOT / "Scamurai"

if str(SCAMURAI_ROOT) not in sys.path:
    sys.path.insert(0, str(SCAMURAI_ROOT))

from backend.main import app as backend_app  # noqa: E402


app = FastAPI(title="SCAMURAI Vercel Gateway")
app.mount("/api", backend_app)
