# Scamurai

Scamurai is a cybersecurity web application that detects threats across three input types:

- **URL** - Scans for phishing or malicious links
- **File** - Scans suspicious PE executables (.exe, .dll, .sys)
- **Email** - Scans for spam or phishing content

The project includes:

- A FastAPI backend in `Scamurai/backend/`
- A React + Vite frontend in `Scamurai/frontend/`
- ML assets and training resources in `URL/`, `FILE/`, and `Email/`

## Requirements

Before running, install:

- Python `3.10+`
- Node.js `18+`
- npm

## Project Structure

```
Scamurai/
├── Scamurai/
│   ├── backend/
│   │   ├── config/          # Threshold & model config
│   │   ├── services/        # ML detection services
│   │   │   ├── url_service.py
│   │   │   ├── file_service.py
│   │   │   ├── email_service.py
│   │   │   ├── dashboard_service.py
│   │   │   └── supabase_service.py
│   │   ├── router/         # API endpoints
│   │   │   ├── url.py
│   │   │   ├── file.py
│   │   │   ├── email.py
│   │   │   └── dashboard.py
│   │   └── main.py         # FastAPI app entry
│   ├── frontend/           # React app
│   └── requirements.txt    # Python dependencies
├── URL/                    # URL ML models & training
├── FILE/                   # File ML models & training
├── Email/                 # Email ML models & training
├── setup-run.bat          # Auto setup & run script
├── Dockerfile             # Backend container
└── .env.local             # Local env (auto-created)
```

## Quick Start

1. **Clone the repo** and open the project folder:
   ```powershell
   cd "path\to\Scamurai"
   ```

2. **Run the setup script**:
   ```powershell
   .\setup-run.bat
   ```

3. **First run**: The script creates `.env.local` with Supabase config. Edit if needed:
   - Go to [supabase.com](https://supabase.com) → Project Settings → API
   - Copy **Project URL** → `SUPABASE_URL`
   - Copy **anon public** key (JWT, starts with `eyJ...`) → `SUPABASE_ANON_KEY`

4. **Done!** Access the app:
   - Frontend: http://127.0.0.1:5173
   - Backend API: http://127.0.0.1:8000
   - Swagger Docs: http://127.0.0.1:8000/docs

The script automatically:

- Creates Python virtual environment (`.venv`)
- Installs backend dependencies
- Installs frontend npm packages
- Starts both backend and frontend servers

## Manual Setup (Optional)

### Backend

```powershell
cd "path\to\Scamurai"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r Scamurai\requirements.txt
cd Scamurai
..\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000
```

### Frontend

In a new terminal:

```powershell
cd "path\to\Scamurai\Scamurai\frontend"
npm install
npm run dev -- --host 127.0.0.1 --port 5173 --force
```

## Environment Variables

Create `.env.local` in the project root:

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_URL` | Supabase project URL | Yes |
| `SUPABASE_ANON_KEY` | Supabase anon public key (JWT) | Yes |
| `SUPABASE_TABLE` | Table name for detection logs | No |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) | No |
| `VITE_API_BASE_URL` | Backend URL (for frontend) | No |
| `DASHBOARD_TIMEZONE` | Dashboard timezone | No |
| `DASHBOARD_TREND_ANCHOR` | Trend chart start date | No |

### Example `.env.local`

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
ALLOWED_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_TABLE=detection_results
```

**Note**: Without Supabase config, dashboard data is stored in memory and resets on server restart.

## API Endpoints

### URL Detection

| Method | Path | Description |
|--------|------|-------------|
| POST | `/url` | Scan URL for phishing/malware |
| POST | `/url/feedback` | Submit feedback to improve model |

### File Detection

| Method | Path | Description |
|--------|------|-------------|
| POST | `/file` | Upload file to scan for malware |

### Email Detection

| Method | Path | Description |
|--------|------|-------------|
| POST | `/email` | Scan email text for spam/phishing |

### Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard/stats` | Get detection statistics |
| GET | `/dashboard/trends` | Get trend data over time |
| GET | `/dashboard/geo` | Get geo distribution data |

### Health Check

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | API health status |

## Troubleshooting

### Backend won't start

Check:

- Python 3.10+ is installed
- `.venv` exists and dependencies are installed
- Port 8000 is available

Try:
```powershell
cd Scamurai
..\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000
```

### Frontend won't start

Check:

- Node.js 18+ is installed
- `npm install` completed in `Scamurai/frontend`
- Port 5173 is available

Try:
```powershell
cd Scamurai\frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173 --force
```

### Dashboard shows no data

- Without Supabase: Data is in-memory, requires active session
- With Supabase: Check credentials in `.env.local`, ensure `detection_results` table exists

### Results look outdated

1. Stop backend process
2. Run `setup-run.bat` again
3. Refresh frontend page

## Deployment

### Railway (Recommended)

**Backend**: Deploy from repository root using `Dockerfile`

Required environment variables:

- `ALLOWED_ORIGINS=https://your-frontend.railway.app`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`

**Frontend**: Deploy from `Scamurai/frontend/`

Required environment variable:

- `VITE_API_BASE_URL=https://your-backend.railway.app`

### Vercel (Alternative)

This repo also includes:

- `api/index.py` - Python entrypoint for Vercel
- `requirements.txt` - Root Python dependencies

**Note**: Vercel's runtime limits may be too strict for the ML stack. Railway is recommended for the backend.

## ML Models

### URL Detection (`URL/models/`)

- `lgbm_model.pkl` - LightGBM classifier
- `xgb_model.pkl` - XGBoost classifier  
- `scaler.pkl` - Feature scaler
- `feature_names.pkl` - 85+ feature names
- `adaptive_safe_patterns.json` - Safe domain patterns

### File Detection (`FILE/models/`)

- `lightgbm_malware_model.pkl` - LightGBM classifier
- `xgboost_malware_model.ubj` - XGBoost model (native)
- `feature_scaler.pkl` - Feature scaler

### Email Detection (`Email/models/`)

- `best_model.pkl` - Best performing model
- `vectorizer.pkl` - TF-IDF vectorizer
- `spam_model.joblib` - Spam classifier
- `kmeans_model.pkl` - KMeans clustering