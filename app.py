from flask import Flask, request, render_template_string, Response
import socket
import os
import ssl
import requests
from datetime import datetime

app = Flask(__name__)

# قائمة المنافذ لفحصها
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRecon Pro - Fawzi Srawi</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', sans-serif; }
        .container { max-width: 1000px; margin-top: 40px; padding-bottom: 60px; }
        .main-card { background-color: #1e293b; border: 1px solid #334155; border-radius: 15px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        
        .header-section { border-bottom: 2px solid #3b82f6; margin-bottom: 25px; padding-bottom: 20px; text-align: center; }
        /* تحسين وضوح اسم فوزي */
        .dev-badge { background-color: #3b82f6; color: #ffffff !important; padding: 8px 30px; border-radius: 50px; font-weight: bold; font-size: 1.3rem; display: inline-block; margin: 10px 0; border: 2px solid #60a5fa; }
        .uni-tag { color: #94a3b8; font-size: 0.9rem; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
        
        .result-card { background-color: #020617; border-radius: 12px; padding: 20px; border: 1px solid #334155; height: 100%; }
        .section-title { color: #3b82f6; font-size: 1.1rem; border-left: 4px solid #3b82f6; padding-left: 12px; margin-bottom: 15px; font-weight: bold; }
        
        .status-open { color: #4ade80; font-weight: bold; }
        .status-closed { color: #f87171; }
        
        .form-control { background-color: #0f172a; border: 1px solid #334155; color: white; border-radius: 10px; }
        .form-control:focus { background-color: #0f172a; color: white; border-color: #3b82f6; box-shadow: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-card">
            <div class="header-section">
                <h1 class="text-primary fw-bold">WebRecon Pro 🛡️</h1>
                <div>
                    <span style="color: #cbd5e1; font-weight: 500;">Lead Developer:</span> <br>
                    <div class="dev-badge">Fawzi Srawi</div>
                </div>
                <div class="uni-tag">Al-Zaytoonah University of Jordan</div>
            </div>
            
            <form method="POST" action="/scan" class="mb-5">
                <div class="input-group input-group-lg">
                    <input type="text" name="target" class="form-control" placeholder="Domain to scan (e.g. google.com)" required>
                    <button class="btn btn-primary px-5" type="submit">Execute Scan</button>
                </div>
            </form>

            {% if results %}
            <div class="row g-4">
                <div class="col-md-4">
                    <div class="result-card text-center">
                        <h5 class="section-title text-start">Analysis Visualization</h5>
                        <div style="max-width: 180px; margin: auto;">
                            <canvas id="portsChart"></canvas>
                        </div>
                        <p class="mt-3 small text-info fw-bold">Target IP: {{ ip_addr }}</p>
                    </div>
                </div>

                <div class="col-md-8">
                    <div class="result-card">
                        <h5 class="section-title">Network Ports Inventory</h5>
                        <div class="row px-2">
                            {% for res in results %}
                                <div class="col-6 col-md-4 mb-2 small" style="border-bottom: 1px solid #1e293b;">{{ res | safe }}</div>
                            {% endfor %}
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="result-card">
                        <h5 class="section-title">SSL Certificate Profile</h5>
                        {% if ssl_info.error %}
                            <p class="text-danger small">{{ ssl_info.error }}</p>
                        {% else %}
                            <p class="mb-1"><b>Issuer:</b> <span class="text-info">{{ ssl_info.issuer }}</span></p>
                            <p class="mb-1"><b>Days Remaining:</b> <span class="text-warning fw-bold">{{ ssl_info.days_left }}</span></p>
                        {% endif %}
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="result-card">
                        <h5 class="section-title">Recon: Security Files</h5>
                        {% for file, status in security_files.items() %}
                            <div class="d-flex justify-content-between border-bottom border-secondary py-2 small">
                                <span>{{ file }}</span>
                                <span class="{{ 'text-success fw-bold' if status == 'Found' else 'text-muted' }}">
                                    {{ '✔ Found' if status == 'Found' else 'Not Detected' }}
                                </span>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>

            <script>
                const ctx = document.getElementById('portsChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Open', 'Closed'],
                        datasets: [{
                            data: [{{ open_count }}, {{ closed_count }}],
                            backgroundColor: ['#4ade80', '#f87171'],
                            borderWidth: 0
                        }]
                    },
                    options: { 
                        plugins: { legend: { position: 'bottom', labels: { color: '#f8fafc', padding: 20 } } },
                        cutout: '70%'
                    }
                });
            </script>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

def get_ssl_info(h):
    try:
        c = ssl.create_default_context()
        with socket.create_connection((h, 443), timeout=2) as s:
            with c.wrap_socket(s, server_hostname=h) as ss:
                cert = ss.getpeercert()
                exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return {"issuer": dict(x[0] for x in cert['issuer'])['commonName'], "days_left": (exp - datetime.utcnow()).days}
    except: return {"error": "SSL Connection Failure"}

def check_files(t):
    results = {}
    for f in ['/robots.txt', '/.env', '/security.txt']:
        try:
            r = requests.get(f"http://{t}{f}", timeout=2)
            results[f] = "Found" if r.status_code == 200 else "Not Found"
        except: results[f] = "Error"
    return results

@app.route('/')
def home(): return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target').replace("https://", "").replace("http://", "").split('/')[0]
    results, open_p = [], 0
    try:
        ip = socket.gethostbyname(target)
        for p in COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.3)
            if s.connect_ex((ip, p)) == 0:
                results.append(f"Port {p}: <span class='status-open'>OPEN</span>"); open_p += 1
            else: results.append(f"Port {p}: <span class='status-closed'>CLOSED</span>")
            s.close()
    except: ip = "N/A"
    
    return render_template_string(HTML_TEMPLATE, results=results, target=target, ip_addr=ip, 
                               ssl_info=get_ssl_info(target), security_files=check_files(target), 
                               open_count=open_p, closed_count=len(COMMON_PORTS)-open_p)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
