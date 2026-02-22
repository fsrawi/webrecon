from flask import Flask, request, render_template_string, Response
import socket
import os

app = Flask(__name__)

# قائمة المنافذ الشائعة لفحصها
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRecon Pro - Fawzi Srawi</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { max-width: 800px; margin-top: 50px; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 25px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5); }
        .btn-primary { background-color: #3b82f6; border: none; font-weight: 600; }
        .result-box { background-color: #020617; border-radius: 8px; padding: 15px; margin-top: 20px; font-family: 'Courier New', Courier, monospace; }
        .status-open { color: #4ade80; font-weight: bold; }
        .status-closed { color: #f87171; }
        /* تحسين ألوان التذييل لتناسب الخلفية السوداء */
        footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; color: #ffffff !important; }
        .dev-name { color: #3b82f6; font-weight: bold; }
        .uni-name { color: #94a3b8; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card text-center">
            <h1 class="mb-4 text-primary">WebRecon Pro</h1>
            <p class="text-muted">Enter a domain to scan and download the security report.</p>
            
            <form method="POST" action="/scan">
                <div class="input-group mb-3">
                    <input type="text" name="target" class="form-control" placeholder="e.g., google.com" required>
                    <button class="btn btn-primary" type="submit">Start Scan</button>
                </div>
            </form>

            {% if results %}
            <div class="result-box text-start">
                <h4 class="text-info border-bottom pb-2">Results for: {{ target }}</h4>
                <p><strong>IP:</strong> {{ ip_addr }}</p>
                <ul class="list-unstyled mt-3">
                    {% for res in results %}
                        <li class="mb-1">{{ res | safe }}</li>
                    {% endfor %}
                </ul>
                
                <form action="/download" method="post" class="mt-4">
                    <input type="hidden" name="report_data" value="{{ raw_results }}">
                    <button type="submit" class="btn btn-outline-success btn-sm">Download Report (TXT)</button>
                    <a href="/" class="btn btn-outline-secondary btn-sm ms-2">New Scan</a>
                </form>
            </div>
            {% endif %}

            <footer>
                <p class="mb-1">Developed by: <span class="dev-name">Fawzi Srawi</span></p>
                <p class="uni-name">Al-Zaytoonah University of Jordan</p>
            </footer>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    results = []
    raw_text = f"Security Scan Report for {target}\n"
    ip_addr = "Unknown"
    
    try:
        ip_addr = socket.gethostbyname(target)
        raw_text += f"IP Address: {ip_addr}\n\n"
        for port in COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip_addr, port))
            status = "CLOSED"
            if result == 0:
                status = "OPEN"
                results.append(f"Port {port}: <span class='status-open'>OPEN</span>")
            else:
                results.append(f"Port {port}: <span class='status-closed'>CLOSED</span>")
            raw_text += f"Port {port}: {status}\n"
            s.close()
    except Exception as e:
        results.append(f"Error: {str(e)}")
    
    return render_template_string(HTML_TEMPLATE, results=results, target=target, ip_addr=ip_addr, raw_results=raw_text)

@app.route('/download', methods=['POST'])
def download():
    report_data = request.form.get('report_data')
    return Response(
        report_data,
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=scan_report.txt"}
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
