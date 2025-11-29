# Topocoin Backend (Python FastAPI)

This is the Python FastAPI backend for Topocoin wallet.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the server:
   ```bash
   python api.py
   ```

## Docker

```bash
docker build -t topocoin-backend .
docker run -p 8000:8000 --env-file .env topocoin-backend
```

## Environment Variables

Create a `.env` file with:
- MONGO_URI
- MONGO_DB_NAME
- JWT_SECRET
- TOPOCOIN_MINT
