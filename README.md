# Password Security Tool

A modern web application for password generation, strength analysis, and breach detection, built with FastAPI and vanilla JavaScript.

![Password Security Tool Screenshot](https://via.placeholder.com/800x450.png?text=Password+Security+Tool)

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

## 📄 License

MIT

MIT License - see LICENSE file for details

## Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) for breach detection API
- [Lucide](https://lucide.dev/) for beautiful icons
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
