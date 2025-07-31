from flask import Flask, jsonify, render_template, Response
import json
import pyshark
import threading
import time
import base64
import ipaddress
import joblib
import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from datetime import datetime, timedelta
from collections import defaultdict
import os

# ------------------------------------
# Flask App Initialization
# ------------------------------------
app = Flask(__name__)
captured_packets = []

# ------------------------------------
# Training + Saving the Model (One-time)
# ------------------------------------
def generate_dataset():
    def generate_ip(private=True):
        if private:
            return str(ipaddress.IPv4Address(random.randint(0x0A000000, 0x0AFFFFFF)))  # 10.0.0.0/8
        else:
            return str(ipaddress.IPv4Address(random.randint(0x0B000000, 0xDF000000)))  # public

    def generate_packet(label):
        srcport = random.randint(1000, 65535)
        dstnport = random.choice([80, 443, 21, 22, 23, 25, 53, 8080, 3306, 3389, random.randint(1000, 65535)])
        transport_layer = random.choice(['TCP', 'UDP'])
        higest_layer = random.choice(['HTTP', 'TLS', 'DNS', 'FTP', 'SSH', 'SMTP'])
        src_ip_private = random.choice([True, False])
        dst_ip_private = random.choice([True, False])

        return {
            "srcport": srcport,
            "dstnport": dstnport,
            "TCP": 1 if transport_layer == 'TCP' else 0,
            "UDP": 1 if transport_layer == 'UDP' else 0,
            "HTTP": 1 if higest_layer == 'HTTP' else 0,
            "TLS": 1 if higest_layer == 'TLS' else 0,
            "src_private": int(src_ip_private),
            "dst_private": int(dst_ip_private),
            "label": label
        }

    normal_data = [generate_packet(0) for _ in range(1000)]
    mitm_data = [generate_packet(1) for _ in range(300)]
    df = pd.DataFrame(normal_data + mitm_data)
    df = df.sample(frac=1).reset_index(drop=True)
    df.to_csv("network_data.csv", index=False)
    print("✅ Dataset generated.")

def train_model():
    df = pd.read_csv("network_data.csv")
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    print("📊 Model Accuracy Report:")
    print(classification_report(y_test, model.predict(X_test)))
    joblib.dump(model, "mitm_model.pkl")
    print("✅ Model saved as mitm_model.pkl")

if not os.path.exists("mitm_model.pkl"):
    generate_dataset()
    train_model()

model = joblib.load("mitm_model.pkl")

# ------------------------------------
# Packet Feature Extraction
# ------------------------------------
def extract_features(packet):
    try:
        features = [
            int(packet['srcport']) if packet['srcport'] else 0,
            int(packet['dstnport']) if packet['dstnport'] else 0,
            1 if packet['transport_layer'] == 'TCP' else 0,
            1 if packet['transport_layer'] == 'UDP' else 0,
            1 if packet['higest_layer'] == 'HTTP' else 0,
            1 if packet['higest_layer'] == 'TLS' else 0,
            int(ipaddress.ip_address(packet['ipsrc']).is_private) if packet['ipsrc'] else 0,
            int(ipaddress.ip_address(packet['ipdst']).is_private) if packet['ipdst'] else 0
        ]
        return features
    except:
        return [0] * 8

# ------------------------------------
# Packet Serialization & ML Prediction
# ------------------------------------
def serialize_packet(packet, anomaly_status=False):
    return {
        'time_stamp': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else '',
        'ipsrc': packet.ip.src if hasattr(packet, 'ip') else '',
        'ipdst': packet.ip.dst if hasattr(packet, 'ip') else '',
        'srcport': packet[packet.transport_layer].srcport if hasattr(packet, packet.transport_layer) and hasattr(packet[packet.transport_layer], 'srcport') else '',
        'dstnport': packet[packet.transport_layer].dstport if hasattr(packet, packet.transport_layer) and hasattr(packet[packet.transport_layer], 'dstport') else '',
        'transport_layer': packet.transport_layer if hasattr(packet, 'transport_layer') else '',
        'higest_layer': packet.highest_layer if hasattr(packet, 'highest_layer') else '',
        'anomaly': anomaly_status,
    }

def process_packet(packet):
    serialized = serialize_packet(packet)
    features = extract_features(serialized)
    prediction = model.predict([features])[0]
    serialized['anomaly'] = True if prediction == 1 else False

    if serialized['anomaly']:
        print("🚨 MITM Attack Detected:", serialized)
    else:
        print("✅ Normal Traffic")

    captured_packets.append(serialized)
    if len(captured_packets) > 100:
        captured_packets.pop(0)

# ------------------------------------
# Packet Capture Thread
# ------------------------------------
def capture_packets():
    interface = r"\Device\NPF_{A46656F6-7CCC-4827-ABA7-0B7F03AFAC5A}"  # <-- change this
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        if hasattr(packet, 'ip') and packet.transport_layer in ['TCP', 'UDP']:
            process_packet(packet)

# ------------------------------------
# Flask Routes
# ------------------------------------
@app.route('/')
def index():
    return 
    <html><body>
    <h1>MITM Detection Dashboard</h1>
    <pre id="stream"></pre>
    <script>
    const eventSource = new EventSource('/events');
    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        document.getElementById("stream").innerText +=
          (data.anomaly ? "🚨 MITM DETECTED" : "✅ Normal") +
          " - " + data.ipsrc + " ➜ " + data.ipdst + "\\n";
    };
    </script>
    </body></html>
    

@app.route('/events')
def events():
    def generate():
        while True:
            if captured_packets:
                pkt = captured_packets.pop(0)
                yield f"data: {json.dumps(pkt)}\n\n"
            time.sleep(1)
    return Response(generate(), mimetype='text/event-stream')

@app.route('/data')
def data():
    return jsonify(captured_packets)

# ------------------------------------
# Start Everything
# ------------------------------------
if __name__ == '__main__':
    t = threading.Thread(target=capture_packets)
    t.daemon = True
    t.start()
    app.run(debug=True)
