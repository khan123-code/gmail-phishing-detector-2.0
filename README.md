@'
# Gmail Phishing Detector 2.0

An AI-powered Chrome extension that analyzes Gmail messages and helps users identify potentially malicious emails.

The project combines a multi-layer detection engine, a local FastAPI backend, and Gemini-powered email summarization.

## Features

- **Phishing Detection:** Classifies emails as Safe, Suspicious, or Phishing.
- **Multi-Layer Analysis:** Examines sender domains, suspicious URLs, credential requests, email authentication, and semantic signals.
- **Risk Scoring:** Produces a phishing risk score with supporting indicators.
- **AI Email Summary:** Generates a summary of the email, sender intent, key points, and required actions.
- **Chrome Integration:** Analyzes emails directly inside Gmail.
- **Local Backend:** Runs the detection API on the user's own machine.

## Architecture

```text
Gmail
  |
  v
Chrome Extension
  |
  v
Local FastAPI Backend
  |
  +--> Domain Analysis
  +--> URL Analysis
  +--> Credential Detection
  +--> Email Authentication Checks
  +--> Semantic Analysis
  |
  v
Risk Score and Prediction
  |
  v
Gmail Extension

Email Summary --> Google Gemini API
