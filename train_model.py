import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
import joblib

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

# Load BOTH files separately - train on one, test on the other
train_df = pd.read_csv('sample_data/KDDTrain.txt', header=None, names=columns)
test_df = pd.read_csv('sample_data/KDDTest+.txt', header=None, names=columns)

train_df['is_attack'] = (train_df['label'] != 'normal').astype(int)
test_df['is_attack'] = (test_df['label'] != 'normal').astype(int)

print("Train shape:", train_df.shape)
print("Test shape:", test_df.shape)
print("\nAttack types in TEST but NOT in TRAIN (novel/unseen attacks):")
train_labels = set(train_df['label'].unique())
test_labels = set(test_df['label'].unique())
print(test_labels - train_labels)

categorical_features = ['protocol_type', 'service', 'flag']
numeric_features = [c for c in columns if c not in categorical_features + ['label', 'difficulty']]

# IMPORTANT: fit encoders on TRAIN only, then apply to test
# Some categories in test might not exist in train - we handle that below
encoders = {}
for col in categorical_features:
    le = LabelEncoder()
    le.fit(train_df[col])
    encoders[col] = le
    train_df[col + '_enc'] = le.transform(train_df[col])

    # Handle unseen categories in test set by mapping them to a known value
    known_classes = set(le.classes_)
    test_df[col + '_safe'] = test_df[col].apply(lambda x: x if x in known_classes else le.classes_[0])
    test_df[col + '_enc'] = le.transform(test_df[col + '_safe'])

encoded_categorical = [c + '_enc' for c in categorical_features]
feature_columns = encoded_categorical + numeric_features

X_train = train_df[feature_columns]
y_train = train_df['is_attack']
X_test = test_df[feature_columns]
y_test = test_df['is_attack']

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Cross-validation on training data only
base_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
cv_scores = cross_val_score(base_model, X_train_scaled, y_train, cv=5, scoring='f1')
print("\nCross-validation F1 scores (on train data):", cv_scores)
print("Mean CV F1:", round(cv_scores.mean(), 3))

# Light tuning
param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5]
}
grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42, class_weight='balanced'),
    param_grid, cv=3, scoring='f1', n_jobs=-1
)
grid_search.fit(X_train_scaled, y_train)
print("\nBest params:", grid_search.best_params_)

model = grid_search.best_estimator_

# THE REAL TEST: evaluate on genuinely unseen KDDTest+ data
preds = model.predict(X_test_scaled)
probs = model.predict_proba(X_test_scaled)[:, 1]

print("\n--- Results on TRULY UNSEEN Test Set (KDDTest+.txt) ---")
print("Precision:", round(precision_score(y_test, preds), 3))
print("Recall:", round(recall_score(y_test, preds), 3))
print("F1 Score:", round(f1_score(y_test, preds), 3))
print("ROC-AUC:", round(roc_auc_score(y_test, probs), 3))
print("Confusion Matrix:\n", confusion_matrix(y_test, preds))

importances = pd.Series(model.feature_importances_, index=feature_columns).sort_values(ascending=False)
print("\nTop 10 most important features:")
print(importances.head(10))

joblib.dump(model, 'model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(encoders, 'encoders.pkl')
joblib.dump(feature_columns, 'feature_columns.pkl')
importances.to_csv('feature_importance.csv')
print("\nSaved model, scaler, encoders, feature importance.")