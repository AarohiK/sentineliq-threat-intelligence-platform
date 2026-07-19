# ==========================================================
# Threat Intelligence Platform Backend Workflow
#
# Client sends IOC request + Auth0 JWT token
#        ↓
# main.py receives API request
#        ↓
# verify_token() validates Auth0 JWT
#        ↓
# Calls helper modules:
#    • virustotal.py  → investigate IOC
#    • risk_engine.py → calculate risk score
#    • database.py    → store investigation history
#        ↓
# main.py returns JSON response
# ==========================================================
from fastapi import FastAPI, Depends
from contextlib import asynccontextmanager
from models import IOCRequest
from virustotal import check_type
from risk_engine import risk_score
from database import create_tables, get_connection
from auth0 import verify_token

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs when FastAPI starts
    create_tables()
    yield
app = FastAPI(lifespan=lifespan)

@app.get("/")
def home():

    return {
        "message": "Threat Intelligence Backend Running"
    }

@app.post("/investigate")
def investigate(
    request: IOCRequest,
    user=Depends(verify_token)
):

    vt_result = check_type(request.ioc)
    score = risk_score(vt_result)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO iocs
        (ioc_value, ioc_type, risk_score, risk_level)
        VALUES (?, ?, ?, ?)
        """,
        (
            request.ioc,
            request.type,
            score["risk_score"],
            score["risk_level"]
        )
    )

    conn.commit()
    conn.close()

    return {
        "ioc": request.ioc,
        "type": request.type,
        "virustotal": vt_result,
        "riskscore": score

    }


