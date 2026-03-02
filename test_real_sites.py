import pandas as pd
from sklearn.linear_model import LogisticRegression
from extract_features import extract
import re

# تحميل البيانات والتدريب
df = pd.read_csv("dataset_features.csv")
X = df.drop("label", axis=1)
y = df["label"]

model = LogisticRegression(max_iter=2000)
model.fit(X, y)

FEATURE_COLUMNS = list(X.columns)

low = 0
medium = 0
high = 0

with open("real_malicious_test.txt", "r", encoding="utf-8") as f:
    urls = [line.strip() for line in f if line.strip()]

print("\nTesting Malicious-like URLs:\n")

for url in urls:
    features = extract(url)

    if features is None:
        continue

    row = {c: float(features.get(c, 0)) for c in FEATURE_COLUMNS}
    feats_df = pd.DataFrame([row])

    prob = model.predict_proba(feats_df)[0][1]

    if prob >= 0.7:
        level = "HIGH"
        high += 1
    elif prob >= 0.4:
        level = "MEDIUM"
        medium += 1
    else:
        level = "LOW"
        low += 1

    print(f"{url} --> {level} ({prob*100:.2f}%)")

print("\n===== Summary =====")
print("LOW:", low)
print("MEDIUM:", medium)
print("HIGH:", high)