# Password Security Tool

A modern web application for password generation, strength analysis, and breach detection, built with FastAPI and vanilla JavaScript.

## 🌐 Try it Online
**[🚀 Use Password Security Tool](https://password-security-tool-8hd8.onrender.com/)**

## 🚀 Features

- **🔑 Password Generation**: Create secure passwords with customizable options
- **🛡️ Strength Analysis**: Analyze password strength with detailed feedback
- **🔍 Breach Detection**: Check if passwords have been compromised using HaveIBeenPwned API
- **🌐 Multilingual**: Available in English and Italian
- **📱 Responsive Design**: Works on desktop, tablet, and mobile devices
- **🔒 Security Focused**: Client-side password handling with secure API communication

## 🛠️ Tech Stack

- **Backend**: FastAPI (Python 3.12)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (No frameworks!)
- **APIs**: HaveIBeenPwned for breach detection
- **Deployment**: Ready for Render, Vercel, or any Python hosting

## ⚙️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-security-tool.git
cd password-security-tool
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
uvicorn app.main:app --reload
```

5. Open your browser and navigate to `http://localhost:8000`

## 📝 Usage

### Generate Passwords
- Adjust length with the slider (8-32 characters)
- Choose to include symbols and exclude ambiguous characters
- Click "Generate Password" to create a secure password
- Copy the generated password to your clipboard

### Check Password Strength
- Enter your password in the strength checker
- View detailed analysis including character types and recommendations
- See visual strength meter with color-coded feedback

### Check Data Breaches
- Enter a password to check against known data breaches
- Uses HaveIBeenPwned API to check compromise status
- Displays breach count if password was found in breaches

## 🔌 API Endpoints

- `GET /` - Main application page
- `POST /api/generate` - Generate secure password
- `POST /api/check` - Analyze password strength
- `POST /api/breach` - Check password breaches

## 🔒 Security Features

- Passwords are hashed using SHA-1 before breach checking
- Only first 5 characters of hash are sent to external API (k-anonymity)
- No passwords are stored or logged
- Content Security Policy implemented
- CORS protection

## 🚀 Deployment

### Render
1. Create a new Web Service
2. Connect your GitHub repository
3. Use the following settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

---

# Password Security Tool (Italiano)

Un'applicazione web moderna per la generazione di password, analisi della sicurezza e rilevamento di violazioni, costruita con FastAPI e JavaScript vanilla.

## 🚀 Caratteristiche

- **🔑 Generazione Password**: Crea password sicure con opzioni personalizzabili
- **🛡️ Analisi Sicurezza**: Analizza la forza della password con feedback dettagliato
- **🔍 Rilevamento Violazioni**: Verifica se le password sono state compromesse usando l'API HaveIBeenPwned
- **🌐 Multilingue**: Disponibile in inglese e italiano
- **📱 Design Responsivo**: Funziona su desktop, tablet e dispositivi mobili
- **🔒 Sicurezza Prioritaria**: Gestione password lato client con comunicazione API sicura

## 🛠️ Stack Tecnologico

- **Backend**: FastAPI (Python 3.12)
- **Frontend**: HTML5, CSS3, JavaScript Vanilla (Nessun framework!)
- **API**: HaveIBeenPwned per il rilevamento violazioni
- **Deployment**: Pronto per Render, Vercel o qualsiasi hosting Python

## ⚙️ Installazione

1. Clona il repository:
```bash
git clone https://github.com/yourusername/password-security-tool.git
cd password-security-tool
```

2. Crea un ambiente virtuale:
```bash
python -m venv venv
source venv/bin/activate  # Su Windows: venv\Scripts\activate
```

3. Installa le dipendenze:
```bash
pip install -r requirements.txt
```

4. Avvia l'applicazione:
```bash
uvicorn app.main:app --reload
```

5. Apri il browser e naviga su `http://localhost:8000`

## 📝 Utilizzo

### Generare Password
- Regola la lunghezza con il cursore (8-32 caratteri)
- Scegli di includere simboli ed escludere caratteri ambigui
- Clicca "Genera Password" per creare una password sicura
- Copia la password generata negli appunti

### Controlla Forza Password
- Inserisci la tua password nel controllo forza
- Visualizza analisi dettagliata inclusi tipi di carattere e raccomandazioni
- Vedi il misuratore visivo con feedback colorato

### Controlla Violazioni Dati
- Inserisci una password per verificare violazioni note
- Usa l'API HaveIBeenPwned per controllare lo stato di compromissione
- Mostra il conteggio delle violazioni se la password è stata trovata

## 🔌 Endpoint API

- `GET /` - Pagina principale applicazione
- `POST /api/generate` - Genera password sicura
- `POST /api/check` - Analizza forza password
- `POST /api/breach` - Controlla violazioni password

## 🔒 Caratteristiche di Sicurezza

- Le password vengono hash con SHA-1 prima del controllo violazioni
- Solo i primi 5 caratteri dell'hash vengono inviati all'API esterna (k-anonimato)
- Nessuna password viene memorizzata o registrata
- Content Security Policy implementata
- Protezione CORS

## 🚀 Deployment

### Render
1. Crea un nuovo Web Service
2. Connetti il tuo repository GitHub
3. Usa le seguenti impostazioni:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

## 📄 License

MIT

MIT License - see LICENSE file for details

## Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) for breach detection API
- [Lucide](https://lucide.dev/) for beautiful icons
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
