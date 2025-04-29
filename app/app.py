import os
import time
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, async_mode='threading')

LOG_FILE = "..\\tls_packets.log"
last_position = 0


def monitor_log_file():
    """Monitor the log file for changes and emit new content"""
    global last_position

    while True:
        if not os.path.exists(LOG_FILE):
            # Даем время на создание log
            time.sleep(1)
            continue

        try:
            with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                # Go to the end if it's a new file
                if last_position == 0:
                    f.seek(0, 2)
                    last_position = f.tell()
                    time.sleep(1)
                    continue

                # Check if file was rotated
                current_size = os.path.getsize(LOG_FILE)
                if current_size < last_position:
                    last_position = 0
                    continue

                # Read new content
                f.seek(last_position)
                new_content = f.read()
                if new_content:
                    socketio.emit('log_update', {'data': new_content}, namespace='/')
                    last_position = f.tell()

        except Exception as e:
            print(f"Error monitoring log file: {e}")

        # Меньше проца кушаем
        time.sleep(0.1)


@socketio.on('connect', namespace='/')
def handle_connect():
    """Handle new WebSocket connection"""
    print('Client connected')
    # Send existing log content when client first connects
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                emit('log_update', {'data': content})
        except Exception as e:
            print(f"Error reading log file: {e}")


@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')


if __name__ == '__main__':
    # Start background thread before running the app
    thread = threading.Thread(target=monitor_log_file)
    thread.daemon = True
    thread.start()

    # Run the app
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)