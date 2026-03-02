import pandas as pd

with open("all_benign.txt", "r", encoding="utf-8") as f:
    benign_urls = [line.strip() for line in f if line.strip()]

with open("all_malicious.txt", "r", encoding="utf-8") as f:
    malicious_urls = [line.strip() for line in f if line.strip()]

data = []

# نحط label 0 للروابط السليمة
for url in benign_urls:
    data.append({"url": url, "label": 0})

# نحط label 1 للروابط الخبيثة
for url in malicious_urls:
    data.append({"url": url, "label": 1})

df = pd.DataFrame(data)

# نخزنهم في ملف CSV
df.to_csv("dataset_urls.csv", index=False)

print("تم إنشاء dataset بنجاح ✅")