"""
GuruTvapay Python SDK (gurutvapay_sdk.py)

Files contained in this single-module SDK (below):
- GuruTvapayClient: main client class
- Exceptions: custom exceptions for SDK users
- Simple retry/backoff built-in (no external deps except `requests`)

Quickstart
----------
1. Save this file as `gurutvapay_sdk.py` in your project.
2. Install requests: `pip install requests`
3. Example (API-Key mode):

    from gurutvapay_sdk import GuruTvapayClient

    client = GuruTvapayClient(env='uat', api_key='YOUR_API_KEY')
    resp = client.create_payment(
        amount=100,
        merchant_order_id='ORD123456',
        channel='web',
        purpose='Online Payment',
        customer={
            'buyer_name': 'John Doe',
            'email': 'john.doe@example.com',
            'phone': '9876543210',
            'address1': '123 MG Road',
            'address2': 'Bangalore, India'
        }
    )
    print(resp)

Example (OAuth login mode):

    client = GuruTvapayClient(env='uat', client_id='CLIENT_12345', client_secret='SECRET_67890')
    client.login_with_password(username='john@example.com', password='your_password')
    # then use client.create_payment(...) same as above

Notes
-----
- This SDK aims to be a small, idiomatic client wrapper for the API docs you provided.
- Endpoints used are based on the API doc you pasted. Some endpoints live under the environment prefix (`/uat_mode` or `/live`) and some examples in docs use the root domain (`/initiate-payment`). This client supports both: login, transaction-status, transaction-list use the environment prefix; create-payment uses the root `/initiate-payment` path (matching the docs).
- If any endpoint path differs in your real API, you can pass `custom_base` to the constructor or call `client.request(...)` directly.

"""

from __future__ import annotations

import time
import json
import hmac
import hashlib
import logging
import typing as t
from dataclasses import dataclass

import requests

# Public objects
__all__ = ["GuruTvapayClient", "GuruTvapayError", "AuthError", "NotFoundError", "RateLimitError"]

DEFAULT_ROOT = "https://api.gurutvapay.com"
ENV_PREFIXES = {
    "uat": "/uat_mode",
    "live": "/live",
}

log = logging.getLogger("gurutvapay")

# -----------------------------
# Exceptions
# -----------------------------

class GuruTvapayError(Exception):
    """Base SDK exception."""

class AuthError(GuruTvapayError):
    pass

class NotFoundError(GuruTvapayError):
    pass

class RateLimitError(GuruTvapayError):
    pass

# -----------------------------
# Helper dataclasses
# -----------------------------

@dataclass
class TokenInfo:
    access_token: str
    expires_at: int  # epoch seconds

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at - 10  # small safety window

# -----------------------------
# Main client
# -----------------------------

class GuruTvapayClient:
    """Simple Python client for GuruTvapay API.

    Two modes:
      - api_key mode: pass api_key to constructor and calls use it in Authorization header.
      - oauth mode: pass client_id and client_secret and call login_with_password to populate token.

    Example:
        client = GuruTvapayClient(env='uat', api_key='sk_test_...')
        client.create_payment(...)
    """

    def __init__(
        self,
        env: str = "uat",
        api_key: t.Optional[str] = None,
        client_id: t.Optional[str] = None,
        client_secret: t.Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        custom_root: t.Optional[str] = None,
    ):
        if env not in ENV_PREFIXES:
            raise ValueError("env must be 'uat' or 'live'")
        self.env = env
        self.api_key = api_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._token: t.Optional[TokenInfo] = None
        self.root = custom_root or DEFAULT_ROOT

    # -----------------------------
    # Low-level request helper with simple retry/backoff
    # -----------------------------
    def _request(
        self,
        method: str,
        url: str,
        headers: t.Optional[dict] = None,
        params: t.Optional[dict] = None,
        data: t.Optional[t.Union[dict, str]] = None,
        json_body: t.Optional[dict] = None,
    ) -> dict:
        headers = headers or {}
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_body,
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                if attempt > self.max_retries:
                    log.exception("HTTP request failed after retries")
                    raise GuruTvapayError(f"HTTP request failed: {e}")
                sleep = self.backoff_factor * (2 ** (attempt - 1))
                time.sleep(sleep)
                continue

            # Try to parse JSON response
            text = resp.text
            try:
                parsed = resp.json()
            except ValueError:
                parsed = None

            if 200 <= resp.status_code < 300:
                return parsed if parsed is not None else {"raw": text}

            # Handle common errors
            if resp.status_code in (401, 403):
                raise AuthError(f"Authentication failed: {resp.status_code} - {text}")
            if resp.status_code == 404:
                raise NotFoundError(f"Not found: {url}")
            if resp.status_code == 429:
                # Rate limited; optional Retry-After
                retry_after = resp.headers.get("Retry-After")
                if retry_after and attempt <= self.max_retries:
                    try:
                        wait = int(retry_after)
                    except Exception:
                        wait = self.backoff_factor * (2 ** (attempt - 1))
                    time.sleep(wait)
                    continue
                raise RateLimitError(f"Rate limited: {text}")

            # 5xx - server errors -> retry
            if 500 <= resp.status_code < 600 and attempt <= self.max_retries:
                sleep = self.backoff_factor * (2 ** (attempt - 1))
                time.sleep(sleep)
                continue

            # Other errors
            raise GuruTvapayError(f"HTTP {resp.status_code}: {text}")

    # -----------------------------
    # Authentication helpers
    # -----------------------------
    def _auth_header(self) -> dict:
        """Return Authorization header depending on api_key or token.

        Priority: explicit api_key > oauth token
        """
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        if self._token and not self._token.is_expired():
            return {"Authorization": f"Bearer {self._token.access_token}"}
        # no token or expired
        return {}

    def login_with_password(self, username: str, password: str, grant_type: str = "password") -> TokenInfo:
        """Perform login using the /login endpoint under the chosen env prefix.

        The API doc shows form-encoded POST with fields grant_type, username, password, client_id, client_secret.
        """
        if not (self.client_id and self.client_secret):
            raise ValueError("client_id and client_secret are required for oauth login")

        login_url = f"{self.root}{ENV_PREFIXES[self.env]}/login"

        data = {
            "grant_type": grant_type,
            "username": username,
            "password": password,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        # API example supplied a JSON-like body for curl; servers often accept form-encoded.
        # We'll post as form data.
        resp = self._request("POST", login_url, headers=headers, data=data)

        if not resp or "access_token" not in resp:
            raise AuthError("Login failed or response missing access_token")

        expires_at = resp.get("expires_at") or (int(time.time()) + int(resp.get("expires_in", 0)))
        token = TokenInfo(access_token=resp["access_token"], expires_at=int(expires_at))
        self._token = token
        return token

    # -----------------------------
    # High-level API methods
    # -----------------------------
    def create_payment(
        self,
        amount: int,
        merchant_order_id: str,
        channel: str,
        purpose: str,
        customer: dict,
        expires_in: t.Optional[int] = None,
        metadata: t.Optional[dict] = None,
    ) -> dict:
        """Call POST /initiate-payment (root endpoint in provided docs).

        Returns parsed JSON response.
        """
        url = f"{DEFAULT_ROOT}/initiate-payment"
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth_header())

        payload = {
            "amount": amount,
            "merchantOrderId": merchant_order_id,
            "channel": channel,
            "purpose": purpose,
            "customer": customer,
        }
        if expires_in is not None:
            payload["expires_in"] = expires_in
        if metadata is not None:
            payload["metadata"] = metadata

        return self._request("POST", url, headers=headers, json_body=payload)

    def transaction_status(self, merchant_order_id: str) -> dict:
        """POST to /<env_prefix>/transaction-status with form-encoded `merchantOrderId`"""
        url = f"{self.root}{ENV_PREFIXES[self.env]}/transaction-status"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers.update(self._auth_header())
        data = {"merchantOrderId": merchant_order_id}
        return self._request("POST", url, headers=headers, data=data)

    def transaction_list(self, limit: int = 50, page: int = 0) -> dict:
        """GET to /<env_prefix>/transaction-list?limit=..&page=.."""
        url = f"{self.root}{ENV_PREFIXES[self.env]}/transaction-list"
        headers = {}
        headers.update(self._auth_header())
        params = {"limit": limit, "page": page}
        return self._request("GET", url, headers=headers, params=params)

    # -----------------------------
    # Utility: verify webhook (HMAC SHA256)
    # -----------------------------
    @staticmethod
    def verify_webhook(payload_bytes: bytes, signature_header: str, secret: str) -> bool:
        """Verify webhook signature using HMAC-SHA256.

        The exact header format must match what your server sends. Common pattern:
            X-Signature: sha256=<hex>
        This function supports both raw hex or `sha256=` prefix.
        """
        if signature_header.startswith("sha256="):
            signature_hex = signature_header.split("=", 1)[1]
        else:
            signature_hex = signature_header
        mac = hmac.new(secret.encode(), msg=payload_bytes, digestmod=hashlib.sha256).hexdigest()
        # Use compare_digest to avoid timing attacks
        return hmac.compare_digest(mac, signature_hex)

    # -----------------------------
    # Generic request helper for advanced use
    # -----------------------------
    def request(self, method: str, path: str, **kwargs) -> dict:
        """Make an arbitrary request.

        `path` may be either an absolute URL or a path which will be joined with `self.root`.
        """
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            # join root + path
            if not path.startswith("/"):
                path = "/" + path
            url = self.root + path
        headers = kwargs.pop("headers", {}) or {}
        headers.update(self._auth_header())
        return self._request(method, url, headers=headers, **kwargs)

# -----------------------------
# If run as script - simple smoke test (will not run network requests unless configured)
# -----------------------------
if __name__ == "__main__":
    print("This module provides GuruTvapayClient. Import it in your project and use as shown in the header examples.")
