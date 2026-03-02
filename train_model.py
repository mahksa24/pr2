import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, cross_val_predict
from sklearn.metrics import roc_curve, auc

# 1) اقرأ بيانات الـ features
df = pd.read_csv("dataset_features.csv")

X = df.drop("label", axis=1)
y = df["label"]

# 2) نماذجنا
log_model = LogisticRegression(max_iter=2000)
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

# 3) 5-Fold Cross Validation (Accuracy)
print("\n===== Logistic Regression (5-Fold CV) =====")
log_scores = cross_val_score(log_model, X, y, cv=5)
print("Accuracy scores:", log_scores)
print("Mean Accuracy:", np.mean(log_scores))

print("\n===== Random Forest (5-Fold CV) =====")
rf_scores = cross_val_score(rf_model, X, y, cv=5)
print("Accuracy scores:", rf_scores)
print("Mean Accuracy:", np.mean(rf_scores))

# 4) ROC Curve + AUC (Logistic Regression)
y_prob = cross_val_predict(log_model, X, y, cv=5, method="predict_proba")[:, 1]
fpr, tpr, _ = roc_curve(y, y_prob)
roc_auc = auc(fpr, tpr)

print("\n===== Logistic Regression ROC/AUC =====")
print("AUC:", roc_auc)

plt.figure()
plt.plot(fpr, tpr, label=f"Logistic Regression (AUC = {roc_auc:.4f})")
plt.plot([0, 1], [0, 1], linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve (5-Fold CV)")
plt.legend()
plt.show()