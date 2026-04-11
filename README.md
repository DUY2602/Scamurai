# Scamurai

Scamurai is a cybersecurity web app that detects threats across three inputs:

- `URL` scan for phishing or malicious links
- `File` scan for suspicious PE executables
- `Email` scan for spam or phishing content

The project includes:

- a FastAPI backend in [Scamurai/backend](/d:/Assignment%203/Scamurai/backend)
- a React + Vite frontend in [Scamurai/frontend](/d:/Assignment%203/Scamurai/frontend)
- ML assets and training resources in [URL](/d:/Assignment%203/URL), [FILE](/d:/Assignment%203/FILE), and [Email](/d:/Assignment%203/Email)

## Requirements

Install these first:

- Python `3.10+` recommended
- Node.js `18+`
- npm

## Project Structure

```text
d:\Assignment 3
|-- Scamurai/
|   |-- backend/          FastAPI app
|   |-- frontend/         React frontend
|   `-- requirements.txt  Backend Python dependencies
|-- URL/                  URL model assets and training files
|-- FILE/                 File model assets and training files
|-- Email/                Email model assets and training files
|-- api/                  Vercel Python entrypoint
|-- start-web.bat         Local one-click startup script
|-- requirements.txt      Root deployment requirements
`-- .env.local            Local environment overrides
```

## Local Run

### Option 1: Quick start with `start-web.bat`

This is the easiest way to run the app locally.

1. Open the repo root:

```powershell
cd "d:\Assignment 3"
```

2. Create a virtual environment if you do not have one yet:

```powershell
python -m venv .venv
```

3. Install backend dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r Scamurai\requirements.txt
```

4. Start the project:

```powershell
.\start-web.bat
```

What this script does:

- loads variables from `.env.local` if the file exists
- starts the FastAPI backend at `http://127.0.0.1:8000`
- starts the React frontend at `http://127.0.0.1:5173`
- auto-installs frontend packages if `node_modules` is missing

After startup, open:

- frontend: `http://127.0.0.1:5173`
- backend docs: `http://127.0.0.1:8000/docs`

### Option 2: Run backend and frontend manually

Use this if you want more control during debugging.

#### Backend

```powershell
cd "d:\Assignment 3"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r Scamurai\requirements.txt
cd "d:\Assignment 3\Scamurai"
d:\Assignment 3\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000
```

#### Frontend

Open a second terminal:

```powershell
cd "d:\Assignment 3\Scamurai\frontend"
npm install
npm run dev -- --host 127.0.0.1 --port 5173 --force
```

## Environment Variables

Local values can be placed in [.env.local](/d:/Assignment%203/.env.local).

Common variables:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_TABLE`
- `ALLOWED_ORIGINS`
- `VITE_API_BASE_URL`
- `DASHBOARD_TIMEZONE`
- `DASHBOARD_TREND_ANCHOR`

### Minimal local example

```env
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
SUPABASE_TABLE=detection_results
```

Notes:

- if Supabase is not configured, some persistence/dashboard features may be limited
- the app can still run locally without every optional variable

## Install Commands

### Backend dependencies

From the repo root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r Scamurai\requirements.txt
```

### Frontend dependencies

```powershell
cd "d:\Assignment 3\Scamurai\frontend"
npm install
```

## Useful Local URLs

- Frontend app: `http://127.0.0.1:5173`
- Backend API: `http://127.0.0.1:8000`
- Swagger docs: `http://127.0.0.1:8000/docs`

## Troubleshooting

### Backend does not start

Check:

- Python is installed
- `.venv` exists
- dependencies were installed from `Scamurai/requirements.txt`

Try:

```powershell
cd "d:\Assignment 3\Scamurai"
d:\Assignment 3\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000
```

### Frontend does not start

Check:

- Node.js is installed
- `npm install` completed in `Scamurai/frontend`

Try:

```powershell
cd "d:\Assignment 3\Scamurai\frontend"
npm install
npm run dev -- --host 127.0.0.1 --port 5173 --force
```

### URL/File/Email result looks outdated

If you changed backend logic but the UI still shows old behavior:

1. stop the backend process
2. run [start-web.bat](/d:/Assignment%203/start-web.bat) again
3. refresh the frontend page

### Dashboard data does not appear

Check:

- `.env.local` is loaded correctly
- Supabase credentials are valid
- the `detection_results` table exists

## Deployment

### Railway

Recommended split:

- backend service from repository root using [Dockerfile](/d:/Assignment%203/Dockerfile)
- frontend service from [Scamurai/frontend](/d:/Assignment%203/Scamurai/frontend) using [Scamurai/frontend/Dockerfile](/d:/Assignment%203/Scamurai/frontend/Dockerfile)

Backend env example:

- `ALLOWED_ORIGINS=https://your-frontend-domain.up.railway.app`

Frontend env example:

- `VITE_API_BASE_URL=https://your-backend-domain.up.railway.app`

### Vercel

This repo also includes:

- [api/index.py](/d:/Assignment%203/api/index.py) for Python entrypoint
- root [requirements.txt](/d:/Assignment%203/requirements.txt) for deployment installs

If Vercel runtime limits are too strict for the backend ML stack, prefer Railway or another less restrictive host for the API.
