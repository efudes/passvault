"""TOTP helpers (wired into endpoints in milestone M7).

TOTP is a server-side second factor and is intentionally OUTSIDE the
zero-knowledge boundary: the secret must be stored in plaintext to verify codes.
"""
import base64
import io

import pyotp
import qrcode


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str, issuer: str = "PassVault") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def qr_png_data_uri(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    # valid_window=1 tolerates one 30s step of clock skew.
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
