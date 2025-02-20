import os
import sqlite3
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import time


# Load timestamps from logs and train anomaly detection model
def train_anomaly_detector():
    """Trains an anomaly detection model using multiple features"""
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()

    cursor.execute("SELECT timestamp, path FROM logs")
    data = cursor.fetchall()
    conn.close()

    if len(data) < 10:  # Require sufficient data
        print("[WARNING] Not enough data to train the anomaly model. Skipping training.")
        return

    # Extract features
    timestamps = [int(time.mktime(time.strptime(row[0], "%Y-%m-%d %H:%M:%S"))) for row in data]
    file_sizes = [os.path.getsize(row[1]) if os.path.exists(row[1]) else 0 for row in data]
    file_extensions = [1 if row[1].endswith(('.exe', '.dll', '.sh')) else 0 for row in data]
    change_intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
    change_intervals.insert(0, 0)  # First file event has no previous interval

    # Prepare feature matrix
    feature_matrix = np.array([timestamps, file_sizes, file_extensions, change_intervals]).T

    # Train Isolation Forest
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(feature_matrix)

    # Save the trained model
    joblib.dump(model, "models/anomaly_model.pkl")
    print("[INFO] Anomaly detection model trained and saved.")

if __name__ == "__main__":
    train_anomaly_detector()
