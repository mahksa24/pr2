import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

# اقرأ بيانات التدريب
df = pd.read_csv("dataset_features.csv")
X = df.drop("label", axis=1)
y = df["label"]

# درب أفضل موديل (Random Forest)
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X, y)

# احفظه
joblib.dump(model, "smartshield_model.joblib")

# احفظ ترتيب الأعمدة عشان التطبيق يستخدم نفس الترتيب
joblib.dump(list(X.columns), "feature_columns.joblib")

print("✅ Model saved: smartshield_model.joblib")
print("✅ Feature columns saved: feature_columns.joblib")