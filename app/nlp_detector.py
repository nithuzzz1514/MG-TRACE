"""
nlp_detector.py
A lightweight ML classifier (TF-IDF + Logistic Regression) trained on
an embedded sample dataset of phishing vs. legitimate email text, plus
a rule-based layer that catches classic BEC / urgency / impersonation
patterns. Combining both gives a more explainable fraud score than a
black-box model alone -- important for a *forensic* tool where an
analyst needs to know WHY something was flagged.
"""

import re
import pickle
import os
import tempfile

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Stored outside the project folder (in the OS temp dir) on purpose --
# Flask's debug-mode file watcher reloads the whole app whenever a file
# changes inside the project tree, so writing the pickle next to the
# source code would trigger a restart loop on first run.
MODEL_PATH = os.path.join(tempfile.gettempdir(), "phishing_model.pkl")

# ---------------------------------------------------------------------
# Embedded training data. In production this would be swapped for a
# real corpus (e.g. Nazario phishing corpus + Enron ham dataset), but
# this hand-written set is enough to demonstrate a working pipeline
# without any external downloads.
# ---------------------------------------------------------------------
PHISHING_SAMPLES = [
    "Your account will be suspended immediately, click here now to verify your password",
    "Urgent action required: your bank account has been locked, confirm your details within 24 hours",
    "Dear customer your payment failed please update your billing information immediately or lose access",
    "You have won a prize, click this link to claim your reward before it expires today",
    "This is your CEO, I need you to process a wire transfer urgently, keep this confidential",
    "Invoice attached, payment is overdue, please pay immediately to the new account details below",
    "Verify your identity now or your account will be permanently deleted within 24 hours",
    "Your package could not be delivered, click here to reschedule and pay a small fee",
    "Security alert: unusual sign in detected, confirm your password immediately to secure your account",
    "Final notice, your subscription will be cancelled today unless you update your payment method now",
    "We noticed suspicious activity on your account, verify your login credentials immediately",
    "Your mailbox is almost full, click here immediately to upgrade or lose your emails",
    "Confidential: please process this payment request urgently and do not discuss with anyone",
    "Congratulations you have been selected, claim your gift card now before the offer expires",
    "Immediate action needed, your tax refund is pending, click here to claim it now",
    "Your password expires today, click this link now to reset it and avoid lockout",
    "Attached is the invoice, kindly transfer the funds to the updated account urgently",
    "Dear user, unusual login attempt from a new device, verify now to avoid suspension",
    "Act now, limited time offer, verify your card details to avoid service interruption",
    "Please review and approve this urgent wire transfer request before end of day today",
    "Your email storage limit exceeded, click here immediately to avoid losing important messages",
    "Bank alert, your account has been compromised, login here immediately to secure it",
    "Time sensitive, HR requires your login details to update payroll information today",
    "Your document is ready, click the link below to view the shared confidential file now",
    "We could not verify your billing address, update it immediately to avoid account suspension",
]

LEGIT_SAMPLES = [
    "Hi team, please find attached the meeting notes from yesterday's discussion",
    "Thanks for your email, I will review the document and get back to you by Friday",
    "The quarterly report is ready for review, let me know if you have any questions",
    "Reminder: our weekly sync is scheduled for 10am tomorrow in the usual conference room",
    "Please see the attached invoice for services rendered last month for your records",
    "Congratulations on the successful launch, great work by the entire team this quarter",
    "Following up on our conversation, I have shared the project timeline in the drive folder",
    "Your order has been shipped and should arrive within five to seven business days",
    "Thank you for subscribing to our newsletter, here are this month's top articles",
    "The conference schedule has been updated, please check the attached agenda for details",
    "I wanted to check in on how the onboarding process is going for the new hires",
    "Attached is the presentation for tomorrow's client meeting, feel free to add comments",
    "Your subscription renewal receipt is attached for your records, thank you for your business",
    "We appreciate your feedback and will incorporate it into the next product update",
    "Here is the summary of action items from today's stand up meeting",
    "The office will be closed next Monday for the public holiday, plan accordingly",
    "Please find the updated project proposal attached, looking forward to your thoughts",
    "Thanks for reaching out, I have forwarded your query to the relevant department",
    "The training session recording is now available on the internal learning portal",
    "Happy to schedule a call next week, let me know what time works best for you",
    "Attached are the minutes from the board meeting held earlier this week",
    "Your annual leave request has been approved, enjoy your time off",
    "The system maintenance window is scheduled for this weekend between 2am and 4am",
    "Please review the attached contract draft and share any redline comments by Thursday",
    "Great meeting you at the conference, looking forward to staying in touch",
]

# Rule-based signal words -- kept separate from the ML model so the
# final report can explain *which specific phrases* triggered concern,
# which matters for a forensic / evidentiary report.
URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify now", "click here",
    "suspended", "locked", "expire", "final notice", "confirm your",
    "act within", "24 hours", "limited time", "wire transfer",
    "gift card", "confidential", "do not discuss", "won a prize",
]


def _train_model():
    texts = PHISHING_SAMPLES + LEGIT_SAMPLES
    labels = [1] * len(PHISHING_SAMPLES) + [0] * len(LEGIT_SAMPLES)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000)),
    ])
    pipeline.fit(texts, labels)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    return pipeline


def _load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return _train_model()


_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        _MODEL = _load_model()
    return _MODEL


def rule_based_signals(text: str):
    text_lower = text.lower()
    hits = [w for w in URGENCY_WORDS if w in text_lower]
    return hits


def score_email_text(subject: str, body: str) -> dict:
    """
    Returns a fraud probability (0-1), the rule-based trigger words
    found, and a combined risk label. Combining ML probability with
    rule hits keeps the score explainable for a forensic report.
    """
    full_text = f"{subject} {body}".strip()
    if not full_text:
        return {
            "ml_phishing_probability": 0.0,
            "rule_hits": [],
            "combined_score": 0.0,
            "label": "insufficient_content",
        }

    model = get_model()
    proba = model.predict_proba([full_text])[0][1]  # P(phishing)

    hits = rule_based_signals(full_text)
    rule_boost = min(len(hits) * 0.06, 0.3)  # each matched phrase nudges score up, capped

    combined = min(proba + rule_boost, 1.0)

    if combined >= 0.7:
        label = "high_risk_phishing"
    elif combined >= 0.4:
        label = "suspicious"
    else:
        label = "likely_legitimate"

    return {
        "ml_phishing_probability": round(float(proba), 3),
        "rule_hits": hits,
        "combined_score": round(float(combined), 3),
        "label": label,
    }
