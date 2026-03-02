from pathlib import Path

def read_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    lines = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    return lines

def write_unique(path, items):
    seen = set()
    out = []
    for x in items:
        x = x.strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")
    return len(out)

# ====== مصادر benign ======
benign_sources = [
    "benign.txt",
    "real_benign_test.txt"
]

# ====== مصادر malicious ======
malicious_sources = [
    "malicious.txt",
    "real_malicious_test.txt"
]

benign_all = []
for s in benign_sources:
    benign_all += read_lines(s)

malicious_all = []
for s in malicious_sources:
    malicious_all += read_lines(s)

b_count = write_unique("all_benign.txt", benign_all)
m_count = write_unique("all_malicious.txt", malicious_all)

print("✅ Done")
print("Benign total:", b_count, "-> all_benign.txt")
print("Malicious total:", m_count, "-> all_malicious.txt")