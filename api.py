from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from solana.rpc.async_api import AsyncClient
from solders.transaction import Transaction  # ← CORRIGÉ
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams  # ← CORRIGÉ
from solders.message import Message
from spl.token.constants import TOKEN_PROGRAM_ID  # ← SPL
from spl.token.instructions import (  # ← SPL, nécessite spl-token
    mint_to,
    MintToParams,
    create_idempotent_associated_token_account,  # Idempotent (sûr)
    get_associated_token_address,
    transfer_checked,
    TransferCheckedParams,
)
from motor.motor_asyncio import AsyncIOMotorClient
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

app = FastAPI(title="Topocoin Wallet API", version="3.0.0")

# === Config ===
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI required")
db = AsyncIOMotorClient(MONGO_URI)[os.getenv("MONGO_DB_NAME", "topocoin")]

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET required")

TOPOCOIN_MINT = Pubkey.from_string(os.getenv("TOPOCOIN_MINT"))
TOKEN_DECIMALS = 6
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer()

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

# === Auth ===
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_jwt(email: str):
    return jwt.encode({"sub": email, "exp": datetime.utcnow() + timedelta(minutes=60)}, SECRET_KEY, algorithm="HS256")

async def get_current_user(cred: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = jwt.decode(cred.credentials, SECRET_KEY, algorithms=["HS256"])
        user = await db.users.find_one({"email": payload["sub"]})
        if not user:
            raise HTTPException(status_code=401)
        return user
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

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

def get_mint_authority() -> Keypair:
    b64 = os.getenv("MINT_AUTHORITY_KEYPAIR")
    if not b64:
        raise HTTPException(500, detail="Mint authority missing")
    return Keypair.from_bytes(base64.b64decode(b64))

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

    token = create_jwt(req.email)
    return {"access_token": token}

@app.post("/api/auth/login", response_model=Token)
async def login(req: UserLogin):
    user = await db.users.find_one({"email": req.email})
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_jwt(req.email)
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
        sol = (await client.get_balance(pubkey)).value / 1e9
        ata = get_associated_token_address(pubkey, TOPOCOIN_MINT)
        try:
            tpc = (await client.get_token_account_balance(ata)).value.ui_amount or 0
        except:
            tpc = 0
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

        message = Message.new_with_blockhash([ix], keypair.pubkey(), recent_blockhash)
        tx = Transaction.new_unsigned(message)
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

        message = Message.new_with_blockhash(instructions, from_pubkey, recent_blockhash)
        tx = Transaction.new_unsigned(message)
        tx.sign([keypair])

        sig = await client.send_transaction(tx)
        return {"signature": str(sig.value)}

@app.post("/api/wallet/mint_tpc")
async def mint_tpc(req: SendRequest, user = Depends(get_current_user)):
    if req.amount <= 0:
        raise HTTPException(400, detail="Invalid amount")

    authority = get_mint_authority()
    dest = Pubkey.from_string(user["wallet_address"])
    amount = int(req.amount * 10**TOKEN_DECIMALS)
    ata = get_associated_token_address(dest, TOPOCOIN_MINT)

    async with get_solana_client() as client:
        instructions = [
            create_idempotent_associated_token_account(
                payer=authority.pubkey(),
                owner=dest,
                mint=TOPOCOIN_MINT,
            ),
            mint_to(MintToParams(
                program_id=TOKEN_PROGRAM_ID,
                mint=TOPOCOIN_MINT,
                dest=ata,
                mint_authority=authority.pubkey(),
                amount=amount
            ))
        ]

        # Blockhash
        blockhash_resp = await client.get_latest_blockhash()
        recent_blockhash = blockhash_resp.value.blockhash

        # Construction TX corrigée
        message = Message.new_with_blockhash(instructions, authority.pubkey(), recent_blockhash)
        tx = Transaction.new_unsigned(message)
        tx.sign([authority])  # Seulement les signers

        try:
            sig = await client.send_transaction(tx)
            return {"signature": str(sig.value)}
        except Exception as e:
            raise HTTPException(500, detail=f"Mint failed: {str(e)}")

# Garde tes autres routes (login, register, send_sol, send_tpc) identiques
# (elles marchent déjà avec cette méthode)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
