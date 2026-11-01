from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from backend import smart_predict # Yeh import hote hi semantic_analyzer ka model load ho jayega (one-time)
from backend.summarizer import summarize_email

app = FastAPI(title="Smart Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mail.google.com"],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

class EmailRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    sender: str = Field(default="", max_length=320)
    body: str = Field(default="", max_length=50000)


@app.get("/")
def root():
    return {"status": "Smart Phishing Detector API is running"}

@app.post("/predict")
def predict(email: EmailRequest):
    result = smart_predict.smart_predict(email.subject, email.sender, email.body)
    return result



@app.post("/summarize")
def summarize(email: EmailRequest):
    result = summarize_email(email.subject, email.sender, email.body)
    return result
