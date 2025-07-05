from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import uvicorn
import os
import sys

# Aggiungi la cartella app al path per importare il modulo
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from password_tool import PasswordSecurityTool, PasswordStats

app = FastAPI(
    title="🔐 Password Security Tool",
    description="Tool completo per la sicurezza delle password",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="templates")

# Initialize password tool
password_tool = PasswordSecurityTool()

# Pydantic models per le API
class GeneratePasswordRequest(BaseModel):
    length: int = 16
    include_symbols: bool = True
    exclude_ambiguous: bool = True

class CheckPasswordRequest(BaseModel):
    password: str

class PasswordResponse(BaseModel):
    password: str
    strength_score: int
    strength_label: str

class PasswordAnalysisResponse(BaseModel):
    length: int
    has_upper: bool
    has_lower: bool
    has_digits: bool
    has_special: bool
    strength_score: int
    strength_label: str
    is_common: bool
    recommendations: list[str]

class BreachResponse(BaseModel):
    is_breached: bool
    count: Optional[int] = None
    message: str

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Pagina principale"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/generate", response_model=PasswordResponse)
async def generate_password(request: GeneratePasswordRequest):
    """Genera una password sicura"""
    try:
        if request.length < 8 or request.length > 128:
            raise HTTPException(status_code=400, detail="La lunghezza deve essere tra 8 e 128 caratteri")
        
        password = password_tool.generate_password(
            length=request.length,
            include_symbols=request.include_symbols,
            exclude_ambiguous=request.exclude_ambiguous
        )
        
        # Analizza la password generata
        stats = password_tool.check_password_strength(password)
        
        return PasswordResponse(
            password=password,
            strength_score=stats.strength_score,
            strength_label=stats.strength_label
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/check", response_model=PasswordAnalysisResponse)
async def check_password(request: CheckPasswordRequest):
    """Analizza la robustezza di una password"""
    try:
        if not request.password:
            raise HTTPException(status_code=400, detail="Password non può essere vuota")
        
        stats = password_tool.check_password_strength(request.password)
        recommendations = password_tool.get_password_recommendations(stats)
        
        return PasswordAnalysisResponse(
            length=stats.length,
            has_upper=stats.has_upper,
            has_lower=stats.has_lower,
            has_digits=stats.has_digits,
            has_special=stats.has_special,
            strength_score=stats.strength_score,
            strength_label=stats.strength_label,
            is_common=stats.is_common,
            recommendations=recommendations
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/breach", response_model=BreachResponse)
async def check_breach(request: CheckPasswordRequest):
    """Controlla se la password è stata compromessa"""
    try:
        if not request.password:
            raise HTTPException(status_code=400, detail="Password non può essere vuota")
        
        is_breached, count = password_tool.check_breach(request.password)
        
        if is_breached:
            message = f"⚠️ Password trovata in {count:,} data breach!"
        elif count == 0:
            message = "✅ Password non trovata in breach conosciuti"
        else:
            message = "❓ Impossibile controllare (API non disponibile)"
        
        return BreachResponse(
            is_breached=is_breached,
            count=count,
            message=message
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Errore nel controllo breach")

@app.get("/api/stats")
async def get_stats():
    """Ottieni statistiche di utilizzo"""
    return password_tool.stats

# Endpoint per form HTML (alternative ai JSON)
@app.post("/generate-form")
async def generate_password_form(
    request: Request,
    length: int = Form(16),
    include_symbols: bool = Form(True),
    exclude_ambiguous: bool = Form(True)
):
    """Genera password tramite form HTML"""
    try:
        password = password_tool.generate_password(length, include_symbols, exclude_ambiguous)
        stats = password_tool.check_password_strength(password)
        
        return templates.TemplateResponse("result.html", {
            "request": request,
            "password": password,
            "stats": stats,
            "type": "generate"
        })
    except ValueError as e:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })

@app.post("/check-form")
async def check_password_form(
    request: Request,
    password: str = Form(...)
):
    """Controlla password tramite form HTML"""
    try:
        stats = password_tool.check_password_strength(password)
        recommendations = password_tool.get_password_recommendations(stats)
        
        return templates.TemplateResponse("result.html", {
            "request": request,
            "stats": stats,
            "recommendations": recommendations,
            "type": "check"
        })
    except ValueError as e:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)