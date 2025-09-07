# main.py
import os
import uuid
from fastapi import FastAPI, Request, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional

# import the SDK and exceptions you created
from gurutvapay_sdk import GuruTvapayClient, AuthError, GuruTvapayError

# Config from env (set these in your deployment)
ENV = os.getenv("GURUTVA_ENV", "uat")           # 'uat' or 'live'
API_KEY = os.getenv("GURUTVA_API_KEY")         # prefer API key mode
CLIENT_ID = os.getenv("GURUTVA_CLIENT_ID")     # optional OAuth client id
CLIENT_SECRET = os.getenv("GURUTVA_CLIENT_SECRET")
USERNAME = os.getenv("GURUTVA_USERNAME")       # optional password grant username
PASSWORD = os.getenv("GURUTVA_PASSWORD")       # optional password grant password
WEBHOOK_SECRET = os.getenv("GURUTVA_WEBHOOK_SECRET", "changeme")  # used to verify webhooks

app = FastAPI(title="My Checkout Service")

class Customer(BaseModel):
    buyer_name: str
    email: str
    phone: str
    address1: Optional[str] = None
    address2: Optional[str] = None

class CreatePaymentReq(BaseModel):
    amount: int
    merchant_order_id: str
    channel: str = "web"
    purpose: str = "Online Payment"
    customer: Customer
    metadata: Optional[dict] = None

# Startup: instantiate SDK and optionally login (password grant)
@app.on_event("startup")
def startup():
    client = GuruTvapayClient(
        env=ENV,
        api_key=API_KEY,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    # Optionally perform password-grant login if username/password provided (and you use OAuth flow)
    if CLIENT_ID and CLIENT_SECRET and USERNAME and PASSWORD and not API_KEY:
        try:
            client.login_with_password(username=USERNAME, password=PASSWORD)
            app.logger = getattr(app, "logger", None)
        except AuthError as e:
            # decide whether to raise or log and continue (we'll log)
            print("Warning: login failed at startup:", e)
    app.state.gurutva_client = client

# Dependency
def get_guru_client():
    return app.state.gurutva_client

# Create payment endpoint
@app.post("/create-payment")
def create_payment(req: CreatePaymentReq, client: GuruTvapayClient = Depends(get_guru_client)):
    try:
        # Example of using Idempotency: create an Idempotency-Key header for create payment
        idemp_key = str(uuid.uuid4())
        headers = {"Idempotency-Key": idemp_key}

        # SDK's create_payment uses a fixed URL per docs. If you need to set headers, use request(...)
        # Use client.request to include custom headers (the SDK will add auth header automatically)
        resp = client.request(
            "POST",
            "/initiate-payment",          # path joined with SDK root
            headers=headers,
            json_body={
                "amount": req.amount,
                "merchantOrderId": req.merchant_order_id,
                "channel": req.channel,
                "purpose": req.purpose,
                "customer": req.customer.dict(),
                **({"metadata": req.metadata} if req.metadata else {}),
            }
        )
        return resp
    except AuthError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except GuruTvapayError as e:
        raise HTTPException(status_code=500, detail=str(e))

# Transaction status (POST form-style like docs)
@app.post("/transaction-status/{merchant_order_id}")
def transaction_status(merchant_order_id: str, client: GuruTvapayClient = Depends(get_guru_client)):
    try:
        resp = client.transaction_status(merchant_order_id)
        return resp
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except GuruTvapayError as e:
        raise HTTPException(status_code=500, detail=str(e))

# Transaction list
@app.get("/transactions")
def transactions(limit: int = 50, page: int = 0, client: GuruTvapayClient = Depends(get_guru_client)):
    try:
        return client.transaction_list(limit=limit, page=page)
    except GuruTvapayError as e:
        raise HTTPException(status_code=500, detail=str(e))

# Webhook endpoint - receives raw bytes and verifies HMAC-SHA256 signature
@app.post("/webhook")
async def webhook(request: Request, client: GuruTvapayClient = Depends(get_guru_client)):
    raw = await request.body()  # bytes
    # adjust header name to whatever your gateway uses (example: X-Signature or X-Gurutvapay-Signature)
    signature_header = request.headers.get("X-Signature") or request.headers.get("X-Gurutvapay-Signature")
    if not signature_header:
        raise HTTPException(status_code=400, detail="Missing signature header")

    # verify using the SDK utility
    verified = client.verify_webhook(payload_bytes=raw, signature_header=signature_header, secret=WEBHOOK_SECRET)
    if not verified:
        raise HTTPException(status_code=401, detail="Invalid signature")

    # parse payload and process
    payload = await request.json()
    # Example: handle payment completed
    event_type = payload.get("event") or payload.get("status") or "unknown"
    if payload.get("status") == "success":
        # update order in your DB, fulfill, notify user, etc.
        print("Payment success for order:", payload.get("merchantOrderId") or payload.get("orderId"))

    # respond 200 quickly
    return {"ok": True}

# Simple health & info
@app.get("/health")
def health():
    return {"status": "ok", "env": ENV}

