from flask import Flask, request, render_template_string
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
    <title>WebRecon Pro - Security Suite</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { max-width: 800px; margin-top: 50px; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 25px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5); }
        .btn-primary { background-color: #3b82f6; border: none; font-weight: 600; }
        .btn-primary:hover { background-color: #2563eb; }
        .result-box { background-color: #020617; border-radius: 8px; padding: 15px; margin-top: 20px; font-family: 'Courier New', Courier, monospace; }
        .status-open { color: #4ade80; font-weight: bold; }
        .status-closed { color: #f87171; }
        footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card text-center">
            <h1 class="mb-4 text-primary">WebRecon Pro</h1>
            <p class="text-muted">Enter a domain or IP to perform a security port scan.</p>
            
            <form method="POST" action="/scan">
                <div class="input-group mb-3">
                    <input type="text" name="target" class="form-control" placeholder="e.g., google.com or 8.8.8.8" required>
                    <button class="btn btn-primary" type="submit">Start Scan</button>
                </div>
            </form>

            {% if results %}
            <div class="result-box text-start">
                <h4 class="text-info border-bottom pb-2">Scan Results for: {{ target }}</h4>
                <p><strong>IP Address:</strong> {{ ip_addr }}</p>
                <ul class="list-unstyled mt-3">
                    {% for res in results %}
                        <li class="mb-1">{{ res | safe }}</li>
                    {% endfor %}
                </ul>
                <div class="mt-4">
                    <a href="/" class="btn btn-sm btn-outline-secondary">New Scan</a>
                </div>
            </div>
            {% endif %}

            <footer>
                <p>Developed by: <strong>Fawzi Srawi</strong></p>
                <p>Al-Zaytoonah University of Jordan</p>
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
    ip_addr = "Unknown"
    
    try:
        ip_addr = socket.gethostbyname(target)
        for port in COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip_addr, port))
            if result == 0:
                service = "Unknown"
                if port == 80: service = "HTTP (Plaintext - Insecure)"
                elif port == 443: service = "HTTPS (Secure)"
                elif port == 22: service = "SSH (Remote Access)"
                results.append(f"Port {port} ({service}): <span class='status-open'>OPEN</span>")
            s.close()
        
        if not results:
            results.append("<span class='status-closed'>All common ports scanned are closed.</span>")
            
    except Exception as e:
        results.append(f"<span class='status-closed'>Error: {str(e)}</span>")
    
    return render_template_string(HTML_TEMPLATE, results=results, target=target, ip_addr=ip_addr)

if __name__ == '__main__':
    # استخدام المنفذ من نظام Render تلقائياً
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
