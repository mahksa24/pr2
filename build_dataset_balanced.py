import pandas as pd
import random

random.seed(42)

def read_list(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

benign = read_list("all_benign.txt")
malicious = read_list("all_malicious.txt")

# ✅ توازن: ناخذ نفس العدد من الطرفين (على الأقل)
n = min(len(benign), len(malicious))

benign_sample = random.sample(benign, n)
malicious_sample = random.sample(malicious, n)

data = [{"url": u, "label": 0} for u in benign_sample] + [{"url": u, "label": 1} for u in malicious_sample]
df = pd.DataFrame(data).sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv("dataset_urls.csv", index=False)

print("✅ Balanced dataset created")
print("Benign used:", n)
print("Malicious used:", n)
print("Total:", len(df))