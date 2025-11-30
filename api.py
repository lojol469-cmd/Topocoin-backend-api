from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from solana.rpc.async_api import AsyncClient
from solders.transaction import Transaction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.message import Message
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
from spl.token.instructions import (
    mint_to,
    MintToParams,
    create_idempotent_associated_token_account,  # <-- Nom correct !
    get_associated_token_address,
    transfer_checked,  # Pour transfer TPC (meilleur que spl_transfer pour checks)
    TransferCheckedParams,
)
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64
import os
import uvicorn
from dotenv import load_dotenv
from mnemonic import Mnemonic
from typing import Optional

load_dotenv()

# === Logging au démarrage (Render) ===
print("Environment variables loaded:")
for key in ["MONGO_URI", "MONGO_DB_NAME", "TOPOCOIN_MINT", "MINT_AUTHORITY_KEYPAIR", "JWT_SECRET"]:
    value = os.getenv(key)
    status = "Loaded" if value else "MISSING!"
    if key in ["MONGO_URI", "MINT_AUTHORITY_KEYPAIR", "JWT_SECRET"]:
        print(f"{key}: {status}")
    else:
        print(f"{key}: {value or 'Not set'}")

app = FastAPI(title="Topocoin Wallet API", version="2.1.0")

# === MongoDB ===
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI is required")
client = AsyncIOMotorClient(MONGO_URI)
db = client[os.getenv("MONGO_DB_NAME", "topocoin")]

# === Security ===
SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET is required")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer()

# === Constants ===
TOPOCOIN_MINT_STR = os.getenv("TOPOCOIN_MINT")
if not TOPOCOIN_MINT_STR:
    raise RuntimeError("TOPOCOIN_MINT is required")
TOPOCOIN_MINT = Pubkey.from_string(TOPOCOIN_MINT_STR)
TOKEN_DECIMALS = 6  # Assume 6 decimals for TPC

# === Solana Client ===
def get_solana_client():
    return AsyncClient("https://api.devnet.solana.com")

# === Models ===
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    seed_phrase_encrypted: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class SendRequest(BaseModel):
    recipient: str
    amount: float

# === Auth Helpers ===
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_jwt(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    expire = datetime.utcnow() + expires_delta
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# === Keypair from user (mnemonic or raw seed) ===
def load_user_keypair(user: dict) -> Keypair:
    encrypted = user.get("seed_phrase_encrypted")
    if not encrypted:
        raise HTTPException(status_code=400, detail="No wallet found")

    try:
        if " " in encrypted.strip():  # mnemonic
            mnemo = Mnemonic("english")
            seed = mnemo.to_seed(encrypted)
            return Keypair.from_bytes(seed[:64])  # Full 64 bytes for Ed25519
        else:  # base64 raw secret key
            raw_bytes = base64.b64decode(encrypted)
            return Keypair.from_bytes(raw_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid seed: {str(e)}")

# === Mint Authority (server-side) ===
def get_mint_authority() -> Keypair:
    b64 = os.getenv("MINT_AUTHORITY_KEYPAIR")
    if not b64:
        raise HTTPException(status_code=500, detail="Mint authority not configured on server")
    try:
        return Keypair.from_bytes(base64.b64decode(b64))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Invalid MINT_AUTHORITY_KEYPAIR: {str(e)}")

# === Endpoints ===

@app.post("/api/auth/register", response_model=Token)
async def register(req: UserCreate):
    if await db.users.find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = hash_password(req.password)

    if req.seed_phrase_encrypted:
        # Validate provided seed
        temp_kp = load_user_keypair({"seed_phrase_encrypted": req.seed_phrase_encrypted})
        wallet = str(temp_kp.pubkey())
        seed_stored = req.seed_phrase_encrypted
    else:
        mnemo = Mnemonic("english")
        words = mnemo.generate(strength=128)  # 12 words
        seed = mnemo.to_seed(words)
        kp = Keypair.from_bytes(seed[:64])
        wallet = str(kp.pubkey())
        seed_stored = words

    await db.users.insert_one({
        "email": req.email,
        "hashed_password": hashed,
        "wallet_address": wallet,
        "seed_phrase_encrypted": seed_stored,
        "created_at": datetime.utcnow()
    })

    token = create_jwt({"sub": req.email})
    return {"access_token": token}

@app.post("/api/auth/login", response_model=Token)
async def login(req: UserLogin):
    user = await db.users.find_one({"email": req.email})
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_jwt({"sub": req.email})
    return {"access_token": token}

@app.get("/api/auth/me")
async def me(user = Depends(get_current_user)):
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "wallet_address": user["wallet_address"],
        "created_at": user.get("created_at")
    }

@app.get("/api/wallet/balance")
async def balance(user = Depends(get_current_user)):
    async with get_solana_client() as client:
        pubkey = Pubkey.from_string(user["wallet_address"])

        # SOL balance
        resp = await client.get_balance(pubkey)
        sol = float(resp.value) / 1e9

        # TPC balance
        ata = get_associated_token_address(pubkey, TOPOCOIN_MINT)
        try:
            resp = await client.get_token_account_balance(ata)
            tpc = resp.value.ui_amount or 0.0
        except Exception:
            tpc = 0.0

        return {"sol_balance": sol, "tpc_balance": tpc}

@app.post("/api/wallet/send_sol")
async def send_sol(req: SendRequest, user = Depends(get_current_user)):
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    keypair = load_user_keypair(user)
    to_pubkey = Pubkey.from_string(req.recipient)
    lamports = int(req.amount * 1e9)

    async with get_solana_client() as client:
        ix = transfer(TransferParams(
            from_pubkey=keypair.pubkey(),
            to_pubkey=to_pubkey,
            lamports=lamports
        ))

        blockhash_resp = await client.get_latest_blockhash()
        recent_blockhash = blockhash_resp.value.blockhash

        msg = Message.new_with_blockhash([ix], keypair.pubkey(), recent_blockhash)
        tx = Transaction.new_unsigned(msg)
        tx.sign([keypair])

        sig = await client.send_transaction(tx)
        return {"signature": str(sig.value)}

@app.post("/api/wallet/send_tpc")
async def send_tpc(req: SendRequest, user = Depends(get_current_user)):
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    keypair = load_user_keypair(user)
    from_pubkey = keypair.pubkey()
    to_pubkey = Pubkey.from_string(req.recipient)
    mint_pubkey = TOPOCOIN_MINT
    amount = int(req.amount * (10 ** TOKEN_DECIMALS))

    async with get_solana_client() as client:
        from_ata = get_associated_token_address(from_pubkey, mint_pubkey)
        to_ata = get_associated_token_address(to_pubkey, mint_pubkey)

        instructions = [
            create_idempotent_associated_token_account(  # Idempotent pour to_ata
                payer=from_pubkey,
                owner=to_pubkey,
                mint=mint_pubkey
            )
        ]

        ix = transfer_checked(TransferCheckedParams(
            program_id=TOKEN_PROGRAM_ID,
            source=from_ata,
            mint=mint_pubkey,
            dest=to_ata,
            owner=from_pubkey,
            amount=amount,
            decimals=TOKEN_DECIMALS,
            signers=[]
        ))
        instructions.append(ix)

        blockhash_resp = await client.get_latest_blockhash()
        recent_blockhash = blockhash_resp.value.blockhash

        msg = Message.new_with_blockhash(instructions, from_pubkey, recent_blockhash)
        tx = Transaction.new_unsigned(msg)
        tx.sign([keypair])

        sig = await client.send_transaction(tx)
        return {"signature": str(sig.value)}

@app.post("/api/wallet/mint_tpc")
async def mint_tpc(req: SendRequest, user = Depends(get_current_user)):
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    authority_kp = get_mint_authority()
    dest_pubkey = Pubkey.from_string(user["wallet_address"])
    amount = int(req.amount * (10 ** TOKEN_DECIMALS))

    async with get_solana_client() as client:
        ata = get_associated_token_address(dest_pubkey, TOPOCOIN_MINT)

        instructions = [
            create_idempotent_associated_token_account(  # Idempotent pour l'ATA du user
                payer=authority_kp.pubkey(),
                owner=dest_pubkey,
                mint=TOPOCOIN_MINT
            )
        ]

        ix = mint_to(MintToParams(
            program_id=TOKEN_PROGRAM_ID,
            mint=TOPOCOIN_MINT,
            dest=ata,
            mint_authority=authority_kp.pubkey(),  # <-- Correct !
            amount=amount
        ))
        instructions.append(ix)

        blockhash_resp = await client.get_latest_blockhash()
        recent_blockhash = blockhash_resp.value.blockhash

        msg = Message.new_with_blockhash(instructions, authority_kp.pubkey(), recent_blockhash)
        tx = Transaction.new_unsigned(msg)
        tx.sign([authority_kp])

        try:
            sig = await client.send_transaction(tx)
            return {"signature": str(sig.value)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Mint failed: {str(e)}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)  # Assume fichier s'appelle api.py
