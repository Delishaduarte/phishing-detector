import sys
import pickle
import scipy.sparse as sp
import os

# ===== LOAD MODEL CORRECTLY =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = pickle.load(open(os.path.join(BASE_DIR, "model.pkl"), "rb"))
vectorizer = pickle.load(open(os.path.join(BASE_DIR, "vectorizer.pkl"), "rb"))

# ===== GET EMAIL INPUT =====
email = " ".join(sys.argv[1:])  # handles multi-line input

# ===== TEXT FEATURES =====
text_features = vectorizer.transform([email])

# ===== FEATURE 1: LINK =====
has_link = 1 if "http" in email.lower() else 0

# ===== FEATURE 2: URGENCY =====
urgent_words = ["urgent","immediately","verify","suspend","within 24 hours","action required","confirm your account","account suspended","failure to act","verify now","login now","security alert","unauthorized access","reset your password"
]
has_urgency = 1 if any(w in email.lower() for w in urgent_words) else 0

# ===== FEATURE 3: SUSPICIOUS DOMAIN =====
suspicious_domains = [".net",".xyz",".ru","bit.ly","tinyurl","verify-","login-","secure-","update-","account-","http://"
]
has_suspicious = 1 if any(d in email.lower() for d in suspicious_domains) else 0

# ===== FEATURE 4: HTTP (NOT HTTPS) =====
has_http_not_https = 1 if "http://" in email.lower() else 0

# ===== CONVERT TO MATRIX =====
f1 = sp.csr_matrix([[has_link]])
f2 = sp.csr_matrix([[has_urgency]])
f3 = sp.csr_matrix([[has_suspicious]])
f4 = sp.csr_matrix([[has_http_not_https]])

# ===== COMBINE FEATURES =====
vector = sp.hstack((text_features, f1, f2, f3, f4))

# ===== PREDICT =====
proba = model.predict_proba(vector)[0]
phishing_confidence = proba[1]  # probability of being phishing

# Lower threshold from 0.5 to 0.35
# meaning: flag as phishing if model thinks there's >35% chance
if phishing_confidence >= 0.35:
    confidence = round(phishing_confidence * 100)
    print(f"PHISHING|{confidence}")
else:
    confidence = round(proba[0] * 100)
    print(f"SAFE|{confidence}")