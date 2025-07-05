from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
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

# Initialize password tool
password_tool = PasswordSecurityTool()

# Serve static files if directory exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

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

# NUOVO: Endpoint per servire la pagina HTML principale
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve la pagina HTML principale del Password Security Tool"""
    
    # Leggi il file HTML che hai già creato
    html_file_path = "paste.txt"  # o il percorso del tuo file HTML
    
    if os.path.exists(html_file_path):
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        
        # Modifica il contenuto HTML per utilizzare le API FastAPI
        html_content = html_content.replace(
            "// Event listeners",
            """
        // Configurazione API
        const API_BASE = window.location.origin + '/api';
        
        // Event listeners"""
        )
        
        # Aggiorna le chiamate API nel JavaScript
        html_content = html_content.replace(
            """setTimeout(() => {
                const password = generatePassword(length, symbols, excludeAmbiguous);
                const strength = calculateStrength(password);
                updateStats('generate');""",
            """fetch(`${API_BASE}/generate`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    length: length,
                    include_symbols: symbols,
                    exclude_ambiguous: excludeAmbiguous
                })
            })
            .then(response => response.json())
            .then(data => {
                updateStats('generate');"""
        )
        
        return HTMLResponse(content=html_content, status_code=200)
    else:
        # Fallback: HTML inline semplice
        return HTMLResponse(content="""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Password Security Tool</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 50px; }
                .container { max-width: 600px; margin: 0 auto; }
                h1 { color: #333; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Password Security Tool</h1>
                <p>Benvenuto nel Password Security Tool!</p>
                <p class="error">File HTML non trovato. Crea un file HTML o usa le API direttamente:</p>
                <ul>
                    <li><strong>POST /api/generate</strong> - Genera password</li>
                    <li><strong>POST /api/check</strong> - Analizza password</li>
                    <li><strong>POST /api/breach</strong> - Controlla breach</li>
                    <li><strong>GET /api/stats</strong> - Statistiche</li>
                </ul>
                <p>Documentazione API disponibile su: <a href="/docs">/docs</a></p>
            </div>
        </body>
        </html>
        """, status_code=200)

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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)