import json
import os
import time
import hashlib
import sqlite3
import joblib
import numpy as np
import requests
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sklearn.ensemble import IsolationForest
from flask_socketio import SocketIO
from plyer import notification

# Load configuration from config.json
with open("config.json") as f:
    config = json.load(f)

MONITOR_PATH = config["monitor_path"]
VIRUSTOTAL_API_KEY = config["virustotal_api_key"]
MAILGUN_API_KEY = config["mailgun_api_key"]
MAILGUN_DOMAIN = config["mailgun_domain"]
ALERT_EMAIL = config["alert_email"]
DISCORD_WEBHOOK_URL = config["discord_webhook_url"]
TELEGRAM_BOT_TOKEN = config["telegram_bot_token"]
TELEGRAM_CHAT_ID = config["telegram_chat_id"]

socketio = SocketIO(message_queue="redis://")  # Using Redis for WebSockets

# Ensure required directories exist
os.makedirs("logs", exist_ok=True)
os.makedirs("models", exist_ok=True)

# Initialize database
def init_db():
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS file_hashes (
                        path TEXT PRIMARY KEY,
                        hash TEXT,
                        last_modified TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT,
                        path TEXT,
                        timestamp TEXT)''')
    conn.commit()
    conn.close()

# Compute SHA256 hash of a file
def compute_hash(file_path):
    try:
        with open(file_path, "rb") as read_file:
            return hashlib.sha256(read_file.read()).hexdigest()
    except Exception as e:
        print(f"[ERROR] Error hashing {file_path}: {e}")
        return None

# Log events to the database
def log_event(event_type, file_path):
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (event_type, path, timestamp) VALUES (?, ?, ?)",
                   (event_type, file_path, time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    rotate_logs()

# VirusTotal File Scan
def scan_file_with_virustotal(file_path):
    """Uploads a file to VirusTotal in a background thread"""
    if not VIRUSTOTAL_API_KEY:
        print("[WARNING] VirusTotal API key is missing. Skipping scan.")
        return

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, files={"file": file})

        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            print(f"[INFO] File {file_path} submitted for VirusTotal scan. Scan ID: {scan_id}")

            # Run VirusTotal result checking in a separate thread
            thread = threading.Thread(target=check_virustotal_results, args=(scan_id, file_path))
            thread.start()

        else:
            print(f"[ERROR] VirusTotal scan submission failed: {response.json()}")

    except Exception as e:
        print(f"[ERROR] Failed to upload file to VirusTotal: {e}")

def check_virustotal_results(scan_id, file_path):
    """Fetches scan results from VirusTotal using scan ID in a background thread"""
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        print(f"[INFO] Checking VirusTotal results for {file_path}...")

        for _ in range(6):  # Retry every 10 sec, up to 1 min
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                status = result["data"]["attributes"]["status"]

                if status == "completed":
                    detected_count = result["data"]["attributes"]["stats"]["malicious"]
                    print(f"[INFO] VirusTotal scan completed. {detected_count} engines flagged the file.")

                    if detected_count > 0:
                        print(f"[SECURITY] {file_path} is malicious! Moving to quarantine.")
                        quarantine_file(file_path)
                    return

                print("[INFO] Scan still in progress. Retrying in 10 sec...")
            else:
                print(f"[ERROR] Failed to fetch scan results: {response.json()}")
                return

            time.sleep(10)  # Wait before retrying

    except Exception as e:
        print(f"[ERROR] Failed to check VirusTotal results: {e}")

def send_alerts(event_type, file_path):
    """ Sends alerts via Email, Slack, Discord, Push, and WebSockets """
    message = f"{event_type.upper()} Alert: {file_path}"

    send_email_alert(event_type, message)
    send_discord_alert(message)
    send_telegram_alert(message)
    send_push_notification(event_type, message)
    send_realtime_web_alert(event_type, file_path)

def send_email_alert(subject, message):
    """ Send an Email Alert using Mailgun """
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("[WARNING] Mailgun API key or domain missing. Skipping email alert.")
        return

    url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    data = {
        "from": f"File Integrity Monitor <admin@{MAILGUN_DOMAIN}>",
        "to": ALERT_EMAIL,
        "subject": subject,
        "text": message
    }

    try:
        response = requests.post(url, auth=("api", MAILGUN_API_KEY), data=data)
        if response.status_code == 200:
            print("[INFO] Email sent via Mailgun API.")
        else:
            print(f"[ERROR] Failed to send email via Mailgun API: {response.text}")
    except Exception as e:
        print(f"[ERROR] Mailgun request failed: {e}")

def send_discord_alert(message):
    """ Send a Discord Notification """
    if not DISCORD_WEBHOOK_URL:
        print("[WARNING] Discord webhook URL missing. Skipping Discord alert.")
        return

    data = {"content": message}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code in [200, 204]:
            print("[INFO] Discord alert sent.")
        else:
            print(f"[ERROR] Failed to send Discord alert: {response.text}")
    except Exception as e:
        print(f"[ERROR] Discord request failed: {e}")

def send_push_notification(title, message):
    """ Send a Desktop Notification """
    try:
        notification.notify(title=title, message=message, timeout=10)
    except Exception as e:
        print(f"[ERROR] Failed to send push notification: {e}")

def send_telegram_alert(message):
    """ Sends an alert message to a Telegram chat """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARNING] Telegram bot token or chat ID missing. Skipping Telegram alert.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}

    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            print("[INFO] Telegram alert sent successfully.")
        else:
            print(f"[ERROR] Failed to send Telegram alert: {response.text}")
    except Exception as e:
        print(f"[ERROR] Telegram request failed: {e}")

def send_realtime_web_alert(event_type, file_path):
    """ Send a WebSocket Update to the Web UI """
    try:
        socketio.emit("update_logs", {"event_type": event_type, "file_path": file_path})
    except Exception as e:
        print(f"[ERROR] Failed to send WebSocket alert: {e}")

#Logs Delete after a limit
def rotate_logs():
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()

    # Keep only the latest 1000 logs
    cursor.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 1000)")

    conn.commit()
    conn.close()
    print("[INFO] Log rotation completed. Older logs deleted.")

#Quarantine Files after checking for anomaly
def quarantine_file(file_path):
    """Moves suspicious files to a quarantine folder"""
    quarantine_dir = "quarantine/"
    os.makedirs(quarantine_dir, exist_ok=True)
    new_path = os.path.join(quarantine_dir, os.path.basename(file_path))

    try:
        os.rename(file_path, new_path)
        print(f"[SECURITY] File {file_path} moved to quarantine at {new_path}!")
        send_alerts("QUARANTINED", file_path)
    except Exception as e:
        print(f"[ERROR] Failed to quarantine {file_path}: {e}")

# File monitoring class
class FileMonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            file_hash = compute_hash(event.src_path)
            if file_hash:
                conn = sqlite3.connect("logs/monitor_logs.db")
                cursor = conn.cursor()
                cursor.execute("SELECT hash FROM file_hashes WHERE path = ?", (event.src_path,))
                row = cursor.fetchone()

                if row and row[0] != file_hash:
                    print(f"[ALERT] File modified: {event.src_path}")
                    log_event("MODIFIED", event.src_path)
                    send_alerts("MODIFIED", event.src_path)

                    cursor.execute("UPDATE file_hashes SET hash = ?, last_modified = ? WHERE path = ?",
                                   (file_hash, time.strftime("%Y-%m-%d %H:%M:%S"), event.src_path))
                elif not row:
                    cursor.execute("INSERT INTO file_hashes (path, hash, last_modified) VALUES (?, ?, ?)",
                                   (event.src_path, file_hash, time.strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                conn.close()
                scan_file_with_virustotal(event.src_path)
                check_anomaly(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            print(f"[INFO] New file created: {event.src_path}")
            log_event("CREATED", event.src_path)
            send_alerts("CREATED", event.src_path)
            scan_file_with_virustotal(event.src_path)
            file_hash = compute_hash(event.src_path)

            if file_hash:
                conn = sqlite3.connect("logs/monitor_logs.db")
                cursor = conn.cursor()
                cursor.execute("INSERT INTO file_hashes (path, hash, last_modified) VALUES (?, ?, ?)",
                               (event.src_path, file_hash, time.strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                conn.close()

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[WARNING] File deleted: {event.src_path}")
            send_email_alert("File Deleted Alert", f"The file {event.src_path} was deleted.")
            log_event("DELETED", event.src_path)
            send_alerts("DELETED", event.src_path)
            conn = sqlite3.connect("logs/monitor_logs.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM file_hashes WHERE path = ?", (event.src_path,))
            conn.commit()
            conn.close()

# Anomaly Detection Model
def train_anomaly_detector():
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp FROM logs")
    timestamps = [int(time.mktime(time.strptime(row[0], "%Y-%m-%d %H:%M:%S"))) for row in cursor.fetchall()]
    conn.close()

    if len(timestamps) < 10:
        print("[WARNING] Not enough data to train the anomaly model. Skipping training.")
        return

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(np.array(timestamps).reshape(-1, 1))
    joblib.dump(model, "models/anomaly_model.pkl")
    print("[INFO] Anomaly detection model trained and saved.")

# Check for anomalies
def check_anomaly(file_path):
    """Detects anomalies using the trained model with enhanced logic"""
    model_path = "models/anomaly_model.pkl"

    if not os.path.exists(model_path):
        print(f"[WARNING] Anomaly model not found. Skipping anomaly detection for {file_path}.")
        return

    model = joblib.load(model_path)
    timestamp = int(time.time())
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    file_extension = 1 if file_path.endswith(('.exe', '.dll', '.sh')) else 0
    last_mod_time = os.path.getmtime(file_path) if os.path.exists(file_path) else timestamp
    change_interval = timestamp - last_mod_time

    # Prepare input for anomaly detection
    input_features = np.array([[timestamp, file_size, file_extension, change_interval]])
    prediction = model.predict(input_features)

    if prediction[0] == -1:
        print(f"[ALERT] Anomaly detected for {file_path}!")
        send_alerts("ANOMALY", file_path)

# Start monitoring function
def start_monitoring(path):
    observer = Observer()
    event_handler = FileMonitorHandler()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"Monitoring started on: {path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Initialize database
init_db()
train_anomaly_detector()

# Start monitoring
if __name__ == "__main__":
    directory_to_monitor = MONITOR_PATH
    start_monitoring(directory_to_monitor)
