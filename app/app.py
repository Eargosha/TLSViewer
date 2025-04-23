import threading
import time

from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
socketIO = SocketIO(app, cors_allowed_origins="*")

def watch_log():
    with open("tls_packets.log", "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                socketIO.emit("packet_update", {"data": line})
            time.sleep(0.1)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    threading.Thread(target=watch_log, deamon=True).start()
    socketIO.run(app, debug=True, port=5000)


