from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
import uvicorn
from .password_tool import PasswordTool

# Initialize FastAPI app
app = FastAPI(title="Password Security Tool")

# Security middleware
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["*"]  # Restringe a domini specifici in produzione
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restringe a domini specifici in produzione
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize password tool
password_tool = PasswordTool()

# API models
class GenerateRequest(BaseModel):
    length: int = 16
    include_symbols: bool = True
    exclude_ambiguous: bool = True

class CheckRequest(BaseModel):
    password: str

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/generate")
async def generate_password(request: GenerateRequest):
    try:
        if request.length < 8 or request.length > 128:
            raise HTTPException(status_code=400, detail="Length must be between 8 and 128")
        
        password = password_tool.generate_password(
            length=request.length,
            include_symbols=request.include_symbols,
            exclude_ambiguous=request.exclude_ambiguous
        )
        return {"password": password}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/check")
async def check_password(request: CheckRequest):
    try:
        if not request.password:
            raise HTTPException(status_code=400, detail="Password required")
        
        result = password_tool.check_password_strength(request.password)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/breach")
async def check_breach(request: CheckRequest):
    try:
        if not request.password:
            raise HTTPException(status_code=400, detail="Password required")
        
        count = password_tool.check_breach(request.password)
        return {"count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Breach check failed")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
