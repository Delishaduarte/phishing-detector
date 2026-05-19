import pandas as pd
import pickle
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ================= LOAD DATA =================
df = pd.read_csv("../Phishing_Email.csv")

# rename columns
df.columns = ["index", "text", "label"]

# ================= CLEAN DATA =================
df = df.dropna(subset=["text"])
df = df[df["text"] != "empty"]
df["label"] = df["label"].astype(str).str.strip().str.lower()

# convert labels
df["label"] = df["label"].map({
    "safe email": 0,
    "phishing email": 1
})

# ================= TEXT FEATURES =================
vectorizer = TfidfVectorizer(max_features=5000)
X_text = vectorizer.fit_transform(df["text"])

# ================= FEATURE 1: LINK =================
has_link = df["text"].apply(lambda x: 1 if "http" in str(x).lower() else 0)

# ================= FEATURE 2: URGENCY =================
urgent_words = ["urgent", "immediately", "verify", "suspend", "within 24 hours"]
has_urgency = df["text"].apply(lambda x: 1 if any(w in str(x).lower() for w in urgent_words) else 0)

# ================= FEATURE 3: SUSPICIOUS DOMAIN =================
suspicious_domains = [".net", "bit.ly", "verify", "login"]
has_suspicious = df["text"].apply(lambda x: 1 if any(d in str(x).lower() for d in suspicious_domains) else 0)

# ===== FEATURE 4: HTTP (NOT HTTPS) =====
has_http_not_https = df["text"].apply(
    lambda x: 1 if "http://" in str(x).lower() else 0
)

# ================= CONVERT TO MATRIX =================
f1 = sp.csr_matrix(has_link.values.reshape(-1, 1))
f2 = sp.csr_matrix(has_urgency.values.reshape(-1, 1))
f3 = sp.csr_matrix(has_suspicious.values.reshape(-1, 1))
f4 = sp.csr_matrix(has_http_not_https.values.reshape(-1, 1))

# ================= COMBINE ALL FEATURES =================
X = sp.hstack((X_text, f1, f2, f3, f4))

# ================= TRAIN MODEL =================
model = MultinomialNB()
model.fit(X, df["label"])

# ================= SAVE =================
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained with enhanced features successfully")