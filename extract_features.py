import pandas as pd
import re
from urllib.parse import urlparse
import math

def entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract(url):
    # Normalize
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    url_l = url.lower()

    # --- word list (phishing-ish)
    suspicious_words = [
        "login","verify","update","secure","account","bank","invoice","payment",
        "reset","password","confirm","support","signin","wallet","otp"
    ]
    suspicious_word_count = sum(1 for w in suspicious_words if w in url_l)

    # --- counts
    digit_count = sum(ch.isdigit() for ch in url)
    special_count = sum(ch in "-_&%?=@" for ch in url)
    dash_count = url.count("-")
    slash_count = url.count("/")
    dot_count_total = url.count(".")
    at_count = url.count("@")

    # --- structural
    host_length = len(host)
    path_length = len(path)
    query_length = len(query)

    # subdomain count (rough)
    subdomain_count = max(0, host.count(".") - 1)

    # uses HTTPS
    https_flag = 1 if url.startswith("https://") else 0

    # punycode
    has_punycode = 1 if "xn--" in host else 0

    # IP host
    has_ip = 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host) else 0

    # suspicious TLD (simple list)
    suspicious_tlds = [".xyz", ".top", ".ru", ".cn", ".tk", ".pw", ".zip", ".mov"]
    suspicious_tld = 1 if any(host.endswith(tld) for tld in suspicious_tlds) else 0

    # params count
    num_params = len(query.split("&")) if query else 0

    # ratios (avoid divide by zero)
    L = max(1, len(url))
    digit_ratio = digit_count / L
    special_ratio = special_count / L

    # "domain in url" heuristic: if main domain appears again in path/query كثير
    # main domain = last two labels تقريباً (example.com)
    parts = host.split(".")
    main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    domain_repeat = url_l.count(main_domain) if main_domain else 0

    return {
        # old ones (keep)
        "url_length": len(url),
        "num_dots": host.count("."),
        "has_ip": has_ip,
        "has_at": 1 if at_count > 0 else 0,
        "has_punycode": has_punycode,
        "num_params": num_params,
        "entropy": entropy(url),

        # new strong features
        "https_flag": https_flag,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "subdomain_count": subdomain_count,
        "suspicious_word_count": suspicious_word_count,
        "digit_count": digit_count,
        "special_char_count": special_count,
        "dash_count": dash_count,
        "slash_count": slash_count,
        "dot_count_total": dot_count_total,
        "suspicious_tld": suspicious_tld,
        "digit_ratio": digit_ratio,
        "special_ratio": special_ratio,
        "domain_repeat": domain_repeat,
    }

df = pd.read_csv("dataset_urls.csv")

features = []

for _, row in df.iterrows():
    f = extract(row["url"])
    f["label"] = row["label"]
    features.append(f)

feature_df = pd.DataFrame(features)
feature_df.to_csv("dataset_features.csv", index=False)

print("تم إنشاء ملف features بنجاح ✅")