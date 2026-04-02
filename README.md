# Malware Detection System – HCMC Assignment

**Three modular detectors** for different malware/spam threats:

- **FILE** → Malware in PE executables (.exe, .dll) using static features
- **URL**  → Malicious / phishing URLs using lexical & structural features
- **Email** → Spam or malicious email content using text features

Each module:

- Loads **all** compatible `*_model.pkl` files from its `models/` folder
- Extracts appropriate features from the input
- Runs inference with every available model
- Shows per-model **prediction** + **confidence score**

---

## Project Structure

```
assignment-hcmc1_6/
├── Email/
│   ├── data/                # CSV contains emails data here
│   ├── models/              # *_model.pkl files go here
│   └── scripts/             # *.ipynb files for model training & EDA
├── FILE/
│   ├── data/                  # CSV contains files data here
│   ├── models/                # *_model.pkl files go here
│   ├── scripts/               # *.ipynb files for model training & EDA
│   ├── utils/                 # *_model.pkl files go here
│       ├── preprocess.py      # Extract features from files
│   └── main.py                # Test model with custom input test
├── URL/
│   ├── data/                  # CSV contains URL data here
│   ├── models/                # *_model.pkl files go here
│   ├── scripts/               # *.ipynb files for model training & EDA
│   ├── utils/                 # *_model.pkl files go here
│       ├── preprocess.py      # Extract features from URLs
│   └── main.py                # Test model with custom input test
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Setup (do once)

1. Use **Python 3.8 – 3.13** (3.11 recommended)
2. Open terminal / PowerShell and go to project folder

```powershell
cd C:\Users\LENOVO\assignment-hcmc1_6
```

3. (Strongly recommended) Create virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # PowerShell
# or for cmd:
# .\.venv\Scripts\activate
```

4. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Modules

### 1. File Malware Scanner (PE executables)

```bash
python FILE/main.py
```

**Input example**
`C:\Users\LENOVO\assignment-hcmc1_6\FILE\data\sample.exe`

**Typical output**

- List of loaded models
- Extracted features (entropy, sections, imports, suspicious APIs, …)
- Table like:

```
Model          Prediction  Confidence
-------------  ----------  ----------
kmeans          MALWARE      0.62
lightgbm        BENIGN       0.89
xgboost         BENIGN       0.94
```

### 2. Malicious URL Detector

```bash
python URL/main.py
```

**Input examples**

```
http://secure-login-paypal-verify-2025.net/update
https://www.google.com
https://bit.ly/malicious-shortlink
```

**Output shows**

- Parsed URL features (length, dots, special chars, entropy, suspicious keywords, …)
- Prediction table per model

### 3. Email / Spam / Malicious Text Detector

```bash
EMAIL/scripts/Prediction.ipynb
```

**Input**
Change the content in cell 4 and cell 5 in Prediction.ipynb file

**Output**

- Exclamation Mark count
- Number of link
- Per-model prediction (SPAM / HAM)
- Model's confidence 

---
**Custom Run**
User can customize the test email they want the model to predict by changing the contents in Cell 4 and 5 in Prediction.ipynb File. By changing the sender domain, subject and email content just by copying and pasting, user can easily get result in 2-3 seconds in the terminal prompt along with the model's confidence, number link and exclamation mark count. In the future, this feature will be integrated onto a website where user can upload their email file and immediately get result without filling in each part as current
## Demo Talking Points (for presentation / recording)

1. “This project contains three separate detectors: for executable files, URLs, and email content.”
2. Show running `python FILE/main.py` → input .exe → explain output
3. Show running `python URL/main.py` → test clean + suspicious URLs
4. Show running `python Email/main.py` → test phishing / normal email
5. “Each module automatically tests all models in its `models/` folder. Adding a new trained model is as simple as dropping the .pkl file there.”

---

## Troubleshooting Checklist

| Problem                         | Most likely cause / solution                                        |
| ------------------------------- | ------------------------------------------------------------------- |
| No models found                 | Run training notebook → check `models/` has `*.pkl` files      |
| Cannot extract features         | Input file is not .exe/.dll                                         |
| URL feature mismatch / KeyError | `feature_names.pkl` missing or doesn't match model training       |
| ImportError / ModuleNotFound    | Re-run `pip install -r requirements.txt` in the virtual env       |
| Confidence = N/A                | Model doesn't implement `predict_proba`                           |
| Wrong directory / path errors   | Run commands from project root folder                               |
| Models exist but not loaded     | File name must end with `_model.pkl` (check exact naming pattern) |

---
# assignment3-hcmc1-6

## Deploy On Vercel

This repo now includes a Vercel setup that serves:

- `Scamurai/frontend` as the static React app
- `api/index.py` as the Python entrypoint for the FastAPI backend

### Recommended project settings

1. Import the repo into Vercel
2. Keep the project root at the repository root
3. Vercel will use:
   - `vercel.json`
   - root `requirements.txt`
   - frontend build output from `Scamurai/frontend/dist`

### Local behavior after this change

- Frontend dev still uses `http://localhost:8000`
- Production frontend defaults to `/api`

### Important note

The backend uses `lightgbm`, `xgboost`, `scikit-learn`, and bundled model files. If Vercel rejects the deployment because of Python package size or serverless runtime limits, the code/config is still correct, but you may need a less restrictive backend host such as Railway, Render, or Fly.io and point `VITE_API_BASE_URL` there.

## Deploy On Railway (2 Services)

Recommended split:

- `backend` service on Railway using the repo root
- `frontend` service on Railway using `Scamurai/frontend`

### Backend service

- Root directory: repository root
- Builder: Dockerfile
- Railway will build from [Dockerfile](/d:/Assignment%203/Dockerfile)

Environment variables:

- `ALLOWED_ORIGINS=https://your-frontend-domain.up.railway.app`

### Frontend service

- Root directory: `Scamurai/frontend`
- Builder: Dockerfile
- Railway will build from [Scamurai/frontend/Dockerfile](/d:/Assignment%203/Scamurai/frontend/Dockerfile)

Environment variables:

- `VITE_API_BASE_URL=https://your-backend-domain.up.railway.app`

### Deployment order

1. Deploy backend first
2. Copy backend public URL
3. Add `VITE_API_BASE_URL` to frontend service
4. Deploy frontend
5. Copy frontend public URL
6. Add that URL to backend `ALLOWED_ORIGINS`
7. Redeploy backend once more
