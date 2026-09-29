"""Arranca el servidor de desarrollo local con la configuracion ya lista en
.env (ver README.md y LOCAL_SETUP.md). El puerto sale de DEV_SERVER_PORT en
.env (por defecto 5010, el mismo registrado como redirect_uri de Azure AD) —
cambialo ahi, no en este archivo.

Uso:
    ./.venv/Scripts/python.exe run_dev.py
"""

import os

import uvicorn
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    uvicorn.run(
        "repositoryuta.main:app",
        host="127.0.0.1",
        port=int(os.environ.get("DEV_SERVER_PORT", "5010")),
        reload=True,
        app_dir="src",
    )
