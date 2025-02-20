from flask import Flask, render_template
from flask_socketio import SocketIO
import sqlite3
import time

app = Flask(__name__)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

def get_logs(limit=10):
    """Fetches the latest file event logs from the database."""
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT event_type, path, timestamp FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    data = [{"event_type": row[0], "file_path": row[1], "timestamp": row[2]} for row in cursor.fetchall()]
    conn.close()
    return data

@app.route("/")
def home():
    """Serves the web dashboard."""
    logs = get_logs()
    return render_template("index.html", logs=logs)

@socketio.on("connect")
def handle_connect():
    """Sends the latest logs when a client connects."""
    print("[INFO] Client connected, sending logs...")
    socketio.emit("update_logs", get_logs())

def send_realtime_web_alert(event_type, file_path):
    """Emit real-time log updates to all connected clients."""
    try:
        log_entry = {
            "event_type": event_type,
            "file_path": file_path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        socketio.emit("update_logs", [log_entry], broadcast=True)
        print(f"[INFO] WebSocket update sent: {log_entry}")
    except Exception as e:
        print(f"[ERROR] WebSocket update failed: {e}")

if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)