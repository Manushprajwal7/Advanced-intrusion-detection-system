# 🛡️ Man-in-the-Middle (MITM) Attack Detection System using Machine Learning

This project is a **real-time MITM (Man-in-the-Middle) attack detection system** that captures live network traffic using **PyShark**, processes packets through a trained **Random Forest classifier**, and flags any suspicious activity through a **Flask web interface**.

---

## 📌 Features

- 🚨 Detects MITM attacks in real-time
- 📡 Live network traffic monitoring using `pyshark`
- 🧠 Built-in synthetic dataset generator and ML model trainer
- 🌐 Real-time web interface with live updates via SSE (Server-Sent Events)
- 🐍 Single Python file implementation for ease of use

---

## 🛠️ Technologies Used

| Tool           | Purpose                              |
|----------------|--------------------------------------|
| Python         | Core language                        |
| Flask          | Web interface and streaming          |
| PyShark        | Live packet capture (Wireshark API)  |
| Scikit-learn   | Machine Learning                     |
| Pandas         | Data manipulation                    |
| Joblib         | Model serialization                  |



---

## 📁 Project Structure

```bash
mitm-detector/
│
├── mitm_detector.py        # Main detection + Flask app (single file)
├── network_data.csv        # Generated synthetic dataset (auto-generated)
├── mitm_model.pkl          # Trained ML model (auto-generated)
├── README.md               # Project documentation
📦 Installation
1. Clone the repository
git clone https://github.com/yourusername/mitm-detector.git
cd mitm-detector
2. Install dependencies
Make sure you have Python 3.7+ installed.


pip install flask scikit-learn pandas pyshark joblib
⚠️ On Windows, you must install Npcap (https://nmap.org/npcap/) for PyShark to work.

🚀 Run the MITM Detection System

python mitm_detector.py
The first time you run the app:

It generates synthetic network data.

Trains a Random Forest model on this data.

Starts capturing and analyzing live packets.

Then, open your browser:


http://127.0.0.1:5000
You'll see live packets being classified as ✅ Normal or 🚨 MITM.

⚙️ Configuration
Change the Network Interface
By default, the app uses a hardcoded interface string:


interface = r"\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
To find your available interfaces, run this in Python:


import pyshark
print(pyshark.LiveCapture().interfaces)
Then replace the interface string in the script:


interface = 'your_interface_name_here'
🧪 Testing
You can simulate MITM attacks using tools like:

mitmproxy

ettercap

bettercap

Or enhance the synthetic dataset to better reflect known attack vectors.

📊 ML Model Details
Algorithm: Random Forest Classifier

Features Used:

Source & destination port

Transport protocol (TCP/UDP)

Highest layer (HTTP, TLS)

Whether IPs are private

Labels:

0: Normal traffic

1: MITM attack (simulated)

You can expand this system with:

Payload inspection

Time-series behavior modeling (LSTM)

Real-world packet capture logs


💡 Future Enhancements
Store logs in SQLite or MongoDB

Real-time alerting via email/Slack/webhooks

Frontend dashboard with charts and logs

Use real captured data to improve model accuracy

Docker containerization for deployment

🙋‍♂️ Contributing
Contributions are welcome! Open issues, suggest improvements, or submit pull requests.

📬 Contact
If you'd like to get in touch:

Email: manushprajwal555@gmail.com

GitHub: https://github.com/Manushprajwal7


