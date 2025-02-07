from flask import Flask, render_template
from flask_socketio import SocketIO
import sqlite3

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

def get_logs():
    conn = sqlite3.connect("logs/monitor_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT event_type, path, timestamp FROM logs ORDER BY timestamp DESC LIMIT 10")
    data = cursor.fetchall()
    conn.close()
    return data

@app.route("/")
def home():
    logs = get_logs()
    return render_template("index.html", logs=logs)

@socketio.on("connect")
def handle_connect():
    socketio.emit("update_logs", get_logs())

if __name__ == "__main__":
    socketio.run(app, debug=True)
