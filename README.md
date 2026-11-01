# Gmail Phishing Detector 2.0

An AI-powered Chrome extension that analyzes Gmail emails to help identify potential phishing threats before users interact with them.

The project combines a multi-layer detection engine, a local FastAPI backend, and Gemini-powered email summarization to provide contextual risk insights directly inside Gmail.

## Features

- **Phishing Detection:** Classifies emails as Safe, Suspicious, or Phishing.
- **Multi-Layer Analysis:** Examines sender domains, URLs, credential requests, email authentication, and semantic signals.
- **Risk Scoring:** Provides a risk score with supporting indicators and explanations.
- **AI Email Summary:** Summarizes email content, sender intent, key points, and requested actions.
- **Gmail Integration:** Analyzes emails directly within the Gmail interface.
- **Local Backend:** Runs the detection API on the user's own machine.

## Architecture

1. Gmail displays an email.
2. Chrome Extension extracts relevant email information.
3. Local FastAPI Backend receives the extracted information.
4. Detection modules analyze:
   - Sender domain
   - URLs
   - Credential requests
   - Email authentication
   - Semantic content
5. The backend returns a prediction, risk score, and supporting indicators.
6. Gemini API generates an email summary when requested.

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **Machine Learning:** Scikit-learn, Sentence Transformers, PyTorch
- **Data Processing:** NumPy, Pandas
- **ML Libraries:** XGBoost, LightGBM
- **Generative AI:** Google Gemini API
- **Extension:** JavaScript, HTML, Chrome Manifest V3

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/khan123-code/gmail-phishing-detector-2.0.git
cd gmail-phishing-detector-2.0
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Gemini API

Create a `.env` file inside the `backend` folder and add your own Gemini API key:

```env
GEMINI_API_KEY=your_gemini_api_key_here
```

Never share or commit your API key.

### 5. Start the backend

Run this command from the project root:

```powershell
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

API documentation: http://127.0.0.1:8000/docs

### 6. Install the Chrome Extension

1. Open `chrome://extensions/` in Google Chrome.
2. Enable Developer mode.
3. Click **Load unpacked**.
4. Select the project's `extension` folder.
5. Open Gmail and test the extension.

Keep the backend running while using the extension.

## Running Tests

Install development dependencies:

```powershell
pip install -r requirements-dev.txt
```

Run the test suite:

```powershell
python -m pytest -q -p no:cacheprovider
```

Latest verified test result: **14 tests passed.**

## Privacy and Security

- Email detection is processed by a backend running locally on the user's machine.
- Email content used for summarization is sent to the Google Gemini API.
- Users must configure their own Gemini API key.
- API keys and `.env` files should never be committed to GitHub.
- Detection results are indicators, not a guarantee that an email is safe or malicious.

## Current Limitations

- The local backend must be running while using the extension.
- The extension currently supports Gmail.
- Gemini API access is required for AI-powered summarization.
- Chrome extension installation currently requires manual setup through Developer mode.

## Project Structure

```text
gmail-phishing-detector-2.0/
|-- backend/
|   |-- app.py
|   |-- smart_predict.py
|   |-- domain_checker.py
|   |-- url_analyzer.py
|   |-- credential_detector.py
|   |-- email_auth_checker.py
|   |-- semantic_analyzer.py
|   |-- summarizer.py
|   |-- train.py
|
|-- extension/
|   |-- background.js
|   |-- content.js
|   |-- manifest.json
|   |-- popup.html
|   |-- popup.js
|
|-- scripts/
|-- tests/
|-- requirements.txt
|-- requirements-dev.txt
|-- README.md
|-- .gitignore
```

## Disclaimer

This project is intended to assist users in identifying potentially suspicious emails. It should not be treated as a substitute for independent security checks or professional cybersecurity tools.
