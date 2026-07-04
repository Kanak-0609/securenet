import pandas as pd
import joblib
import uuid
from datetime import datetime

# Load the trained model and preprocessing objects once, when the app starts
model = joblib.load('model.pkl')
scaler = joblib.load('scaler.pkl')
encoders = joblib.load('encoders.pkl')
feature_columns = joblib.load('feature_columns.pkl')

# Same column names used during training - needed to read incoming CSVs correctly
ALL_COLUMNS = [
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

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']


def detect_anomalies(file):
    """
    Takes an uploaded file (NSL-KDD formatted CSV, no header),
    runs it through the trained model, and returns a list of alert dicts
    for every row predicted as an attack.
    """
    df = pd.read_csv(file, header=None, names=ALL_COLUMNS)

    # Encode categorical columns using the SAME encoders fit during training.
    # If a category wasn't seen during training, fall back to a known class
    # instead of crashing - this can happen with live/new traffic data.
    for col in CATEGORICAL_FEATURES:
        le = encoders[col]
        known_classes = set(le.classes_)
        safe_col = df[col].apply(lambda x: x if x in known_classes else le.classes_[0])
        df[col + '_enc'] = le.transform(safe_col)

    X = df[feature_columns]
    X_scaled = scaler.transform(X)

    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)[:, 1]  # confidence it's an attack

    alerts = []
    for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
        if pred == 1:  # flagged as attack
            row = df.iloc[i]
            severity = "high" if prob > 0.85 else "medium" if prob > 0.6 else "low"
            alerts.append({
                "id": str(uuid.uuid4()),
                "protocol": row["protocol_type"],
                "service": row["service"],
                "flag": row["flag"],
                "src_bytes": int(row["src_bytes"]),
                "dst_bytes": int(row["dst_bytes"]),
                "confidence": round(float(prob), 3),
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat(),
                "resolved": False
            })

    return alerts, len(df)