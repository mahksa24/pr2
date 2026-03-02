import random

brands = [
    "paypal","amazon","bankofamerica","microsoft","apple",
    "facebook","instagram","netflix","google","chase",
    "alrajhi","riyadbank","snapchat","linkedin","twitter"
]

keywords = [
    "login","verify","update","secure","account","billing",
    "reset","password","confirm","support","security",
    "session","wallet","authentication","validation"
]

tlds = [".xyz",".top",".ru",".cn",".tk",".pw",".zip",".mov"]

paths = [
    "/login","/verify","/update","/security-check",
    "/account/verify","/billing/update",
    "/confirm-session","/reset-password",
    "/secure-auth","/identity-validation"
]

def generate_url():
    brand = random.choice(brands)
    word1 = random.choice(keywords)
    word2 = random.choice(keywords)
    tld = random.choice(tlds)
    path = random.choice(paths)

    # مثال: paypal-secure-login-update.xyz/reset-password
    domain = f"{brand}-{word1}-{word2}{tld}"
    return f"http://{domain}{path}"

# توليد 200 رابط
urls = set()
while len(urls) < 200:
    urls.add(generate_url())

with open("real_malicious_test.txt", "w", encoding="utf-8") as f:
    for url in urls:
        f.write(url + "\n")

print("Generated 200 suspicious test URLs successfully!")