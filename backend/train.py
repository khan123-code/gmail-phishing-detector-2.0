# backend/train.py
import pandas as pd
import numpy as np
import joblib, re, os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

# ── 1. Load data ──────────────────────────────────────────
df = pd.read_csv('../dataset/phishing_email.csv')
print(f"Dataset loaded: {len(df)} rows")
print(df['label'].value_counts())

# ── 2. Clean text ─────────────────────────────────────────
def clean(text):
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)   # replace links
    text = re.sub(r'\S+@\S+', ' EMAIL ', text)         # replace emails
    text = re.sub(r'[^a-z\s]', ' ', text)              # keep letters only
    text = re.sub(r'\s+', ' ', text).strip()
    return text

df['clean_text'] = df['text_combined'].apply(clean)

# ── 3. Split data ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    df['clean_text'], df['label'], test_size=0.2, random_state=42
)

joblib.dump(X_test, "model/X_test.pkl")
print("X_test saved")

joblib.dump(y_test, "model/y_test.pkl")
print("y_test saved")

# ── 4. Convert text to numbers (TF-IDF) ──────────────────
vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1,2))
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)

# ── 5. Train all 5 models ─────────────────────────────────
models = {
    'Logistic Regression': LogisticRegression(max_iter=1000),
    'Naive Bayes':         MultinomialNB(),
    'Random Forest':       RandomForestClassifier(n_estimators=100, n_jobs=-1),
    'XGBoost':             XGBClassifier(use_label_encoder=False, eval_metric='logloss', n_jobs=-1),
    'LightGBM':            LGBMClassifier(n_jobs=-1),
}

results = {}
for name, model in models.items():
    model.fit(X_train_vec, y_train)
    acc = accuracy_score(y_test, model.predict(X_test_vec))
    results[name] = (acc, model)
    print(f"{name}: accuracy = {acc:.4f}")
    

# ── 6. Pick and save the best model ──────────────────────
best_name = max(results, key=lambda k: results[k][0])
best_model = results[best_name][1]
print(f"\n✅ Best model: {best_name} ({results[best_name][0]:.4f})")

os.makedirs('model', exist_ok=True)
joblib.dump({'model': best_model, 'vectorizer': vectorizer}, 'model/best_model.pkl')
print("✅ Saved to model/best_model.pkl")

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# Predictions
y_pred = best_model.predict(X_test_vec)
y_prob = best_model.predict_proba(X_test_vec)[:, 1]

print("\n" + "="*60)
print("FINAL MODEL EVALUATION")
print("="*60)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score : {f1_score(y_test, y_pred):.4f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.4f}")

print("\nConfusion Matrix")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report")
print(classification_report(y_test, y_pred))