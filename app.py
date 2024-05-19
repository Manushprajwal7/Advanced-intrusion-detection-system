from flask import Flask, jsonify, render_template, Response
import json
import pyshark
import threading
import time
import base64
import ipaddress
import requests
from datetime import datetime
import time
from collections import defaultdict
from datetime import datetime, timedelta


KNOWN_PORTS = [
    80, 443, 22, 21, 8080, 123, 110, 1433, 25, 3306, 53, 139, 445, 3389, 5900, 
    69, 5060, 1723, 6667, 587, 993, 995, 5432, 1521, 543, 515, 194, 993, 4444, 
    8081, 8888, 9200, 5000, 7000, 6000, 2049, 3306, 27017, 11211, 11371, 5222, 
    465, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 8443, 10000
]

app = Flask(__name__)

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)

app.json_encoder = CustomJSONEncoder

class Packets(object):
    def __init__(self, ipsrc="", time_stamp='', srcport='', transport_layer='', dstnport='', higest_layer='', ipdst=''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstnport = dstnport
        self.transport_layer = transport_layer
        self.higest_layer = higest_layer

class apiServer(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

server = apiServer('192.168.1.6', '3000')

inf = r"\Device\NPF_{A46656F6-7CCC-4827-ABA7-0B7F03AFAC5A}"  # Replace this with a valid interface
capture = pyshark.LiveCapture(interface=inf)

def check_if_api_server(packet, server):
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        if packet.ip.src == server.ip or packet.ip.dst == server.ip:
            return True
    return False

def check_if_private_ipadress(ipadress):
    ip = ipaddress.ip_address(ipadress)
    return ip.is_private

def report(message):
    temp = json.dumps(message.__dict__, default=str)
    jsonString = temp.encode('ascii')
    b64 = base64.b64encode(jsonString)
    jsonPayload = b64.decode('utf-8').replace("'", '"')
    print(jsonPayload)

    try:
        x = requests.get(f'https://{server.ip}:{server.port}/api/?{jsonPayload}')
    except requests.ConnectionError:
        pass

def check_packet_filter(packet):
    if check_if_api_server(packet, server):
        return
    if hasattr(packet, 'icmp'):
        DataGram = Packets()
        DataGram.ipdst = packet.ip.dst
        DataGram.ipsrc = packet.ip.src
        DataGram.higest_layer = packet.highest_layer
        DataGram.time_stamp = packet.sniff_time
        report(DataGram)
    if packet.transport_layer in ['TCP', 'UDP']:
        DataGram = Packets()
        if hasattr(packet, 'ipv6'):
            return
        if hasattr(packet, 'ip'):
            if check_if_private_ipadress(packet.ip.src) and check_if_private_ipadress(packet.ip.dst):
                DataGram.ipsrc = packet.ip.src
                DataGram.ipdst = packet.ip.dst
                DataGram.time_stamp = packet.sniff_time
                DataGram.higest_layer = packet.highest_layer
                DataGram.transport_layer = packet.transport_layer
                if hasattr(packet, 'udp'):
                    DataGram.dstnport = packet.udp.dstport
                    DataGram.srcport = packet.udp.srcport
                if hasattr(packet, 'tcp'):
                    DataGram.dstnport = packet.tcp.dstport
                    DataGram.srcport = packet.tcp.srcport
                report(DataGram)

def serialize_packet(packet, anomaly_status):
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


captured_packets = []

def check_signatures(packet):
    signatures = [
        {'ip_src': '192.168.1.100', 'port_dst': 80, 'pattern': 'malicious payload 1'},
        {'ip_src': '192.168.1.101', 'port_dst': 443, 'pattern': 'malicious payload 2'},
        {'ip_src': '10.0.0.1', 'port_dst': 22, 'pattern': 'malicious payload 3'},
        {'ip_src': '172.16.0.1', 'port_dst': 21, 'pattern': 'malicious payload 4'},
        {'ip_src': '192.168.2.200', 'port_dst': 8080, 'pattern': 'malicious payload 5'},
        {'ip_src': '192.168.1.200', 'port_dst': 123, 'pattern': 'malicious payload 6'},
        {'ip_src': '172.16.0.2', 'port_dst': 110, 'pattern': 'malicious payload 7'},
        {'ip_src': '10.0.0.2', 'port_dst': 1433, 'pattern': 'malicious payload 8'},
        {'ip_src': '192.168.0.50', 'port_dst': 25, 'pattern': 'malicious payload 9'},
        {'ip_src': '192.168.3.100', 'port_dst': 3306, 'pattern': 'malicious payload 10'},
        {'ip_src': '192.168.1.102', 'port_dst': 53, 'pattern': 'malicious payload 11'},
        {'ip_src': '192.168.1.103', 'port_dst': 139, 'pattern': 'malicious payload 12'},
        {'ip_src': '10.0.0.3', 'port_dst': 445, 'pattern': 'malicious payload 13'},
        {'ip_src': '172.16.0.3', 'port_dst': 3389, 'pattern': 'malicious payload 14'},
        {'ip_src': '192.168.2.201', 'port_dst': 5900, 'pattern': 'malicious payload 15'},
        {'ip_src': '192.168.1.201', 'port_dst': 69, 'pattern': 'malicious payload 16'},
        {'ip_src': '172.16.0.4', 'port_dst': 5060, 'pattern': 'malicious payload 17'},
        {'ip_src': '10.0.0.4', 'port_dst': 1723, 'pattern': 'malicious payload 18'},
        {'ip_src': '192.168.0.51', 'port_dst': 25, 'pattern': 'malicious payload 19'},
        {'ip_src': '192.168.3.101', 'port_dst': 6667, 'pattern': 'malicious payload 20'},
        {'ip_src': '192.168.1.104', 'port_dst': 80, 'pattern': 'malicious payload 21'},
        {'ip_src': '192.168.1.105', 'port_dst': 443, 'pattern': 'malicious payload 22'},
        {'ip_src': '10.0.0.5', 'port_dst': 22, 'pattern': 'malicious payload 23'},
        {'ip_src': '172.16.0.5', 'port_dst': 21, 'pattern': 'malicious payload 24'},
        {'ip_src': '192.168.2.202', 'port_dst': 8080, 'pattern': 'malicious payload 25'},
        {'ip_src': '192.168.1.202', 'port_dst': 123, 'pattern': 'malicious payload 26'},
        {'ip_src': '172.16.0.6', 'port_dst': 110, 'pattern': 'malicious payload 27'},
        {'ip_src': '10.0.0.6', 'port_dst': 1433, 'pattern': 'malicious payload 28'},
        {'ip_src': '192.168.0.52', 'port_dst': 25, 'pattern': 'malicious payload 29'},
        {'ip_src': '192.168.3.102', 'port_dst': 3306, 'pattern': 'malicious payload 30'},
        {'ip_src': '192.168.1.106', 'port_dst': 53, 'pattern': 'malicious payload 31'},
        {'ip_src': '192.168.1.107', 'port_dst': 139, 'pattern': 'malicious payload 32'},
        {'ip_src': '10.0.0.7', 'port_dst': 445, 'pattern': 'malicious payload 33'},
        {'ip_src': '172.16.0.7', 'port_dst': 3389, 'pattern': 'malicious payload 34'},
        {'ip_src': '192.168.2.203', 'port_dst': 5900, 'pattern': 'malicious payload 35'},
        {'ip_src': '192.168.1.203', 'port_dst': 69, 'pattern': 'malicious payload 36'},
        {'ip_src': '172.16.0.8', 'port_dst': 5060, 'pattern': 'malicious payload 37'},
        {'ip_src': '10.0.0.8', 'port_dst': 1723, 'pattern': 'malicious payload 38'},
        {'ip_src': '192.168.0.53', 'port_dst': 25, 'pattern': 'malicious payload 39'},
        {'ip_src': '192.168.3.103', 'port_dst': 6667, 'pattern': 'malicious payload 40'},
        {'ip_src': '192.168.1.108', 'port_dst': 80, 'pattern': 'malicious payload 41'},
        {'ip_src': '192.168.1.109', 'port_dst': 443, 'pattern': 'malicious payload 42'},
        {'ip_src': '10.0.0.9', 'port_dst': 22, 'pattern': 'malicious payload 43'},
        {'ip_src': '172.16.0.9', 'port_dst': 21, 'pattern': 'malicious payload 44'},
        {'ip_src': '192.168.2.204', 'port_dst': 8080, 'pattern': 'malicious payload 45'},
        {'ip_src': '192.168.1.204', 'port_dst': 123, 'pattern': 'malicious payload 46'},
        {'ip_src': '172.16.0.10', 'port_dst': 110, 'pattern': 'malicious payload 47'},
        {'ip_src': '10.0.0.10', 'port_dst': 1433, 'pattern': 'malicious payload 48'},
        {'ip_src': '192.168.0.54', 'port_dst': 25, 'pattern': 'malicious payload 49'},
        {'ip_src': '192.168.3.104', 'port_dst': 3306, 'pattern': 'malicious payload 50'},
    ]
    for signature in signatures:
        if packet['ipsrc'] == signature['ip_src'] and packet['dstnport'] == signature['port_dst']:
            if signature['pattern'] in packet['higest_layer']:
                return True  # Intrusion detected
    return False


traffic_data = defaultdict(list)

# Function to collect data for two hours and determine normal traffic patterns
def collect_traffic_data():
    global traffic_data
    end_time = datetime.now() + timedelta(hours=2)
    
    while datetime.now() < end_time:
        for packet in capture.sniff_continuously(packet_count=1):
            if hasattr(packet, 'ip') and packet.transport_layer in ['TCP', 'UDP']:
                src_ip = packet.ip.src
                dst_port = int(packet[packet.transport_layer].dstport)
                traffic_data[dst_port].append((src_ip, datetime.now()))
                time.sleep(0.1)  # Adjust this as necessary to manage packet capture rate

# Function to establish normal traffic based on collected data
def establish_normal_traffic():
    global traffic_data
    normal_traffic = set()
    
    for port, records in traffic_data.items():
        if len(records) > 5:  # Example threshold, adjust based on your data
            normal_traffic.add(port)
    
    return normal_traffic

# Function for anomaly detection
def check_anomaly(packet, normal_traffic):
    dst_port = packet['dstnport']
    
    if dst_port not in normal_traffic:
        return True  # Anomaly detected
    return False

# Run the data collection process
collect_traffic_data()

# Establish normal traffic
normal_traffic = establish_normal_traffic()

# Example packet processing (this would be integrated with your packet processing pipeline)
def process_packet(packet):
    if check_anomaly(packet, normal_traffic):
        print("Anomaly detected:", packet)
    else:
        print("Normal traffic:", packet)

def check_behavioral(packet):
    # Example basic behavioral detection
    if packet['higest_layer'] == 'HTTP' and packet['srcport'] == '80':
        return True  # Behavior anomaly detected
    return False

@app.route('/data', methods=['GET'])
def data():
    serialized_packets = [serialize_packet(packet) for packet in captured_packets]
    return jsonify(serialized_packets)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/events')
def events():
    def generate():
        while True:
            if captured_packets:
                packet = captured_packets.pop(0)
                anomaly_status = check_anomaly(serialize_packet(packet), normal_traffic)
                yield f"data: {json.dumps(serialize_packet(packet, anomaly_status))}\n\n"
            time.sleep(1)
    return Response(generate(), mimetype='text/event-stream')

def capture_packets():
    for packet in capture.sniff_continuously():
        check_packet_filter(packet)
        captured_packets.append(packet)
        if len(captured_packets) > 100:
            captured_packets.pop(0)

if __name__ == '__main__':
    import threading

    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True
    capture_thread.start()
    app.run(debug=True)
