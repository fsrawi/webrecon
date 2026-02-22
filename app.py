from flask import Flask, request, render_template_string, Response
import socket
import time

app = Flask(__name__)

# قاعدة بيانات المنافذ والثغرات
COMMON_PORTS = {
    21: ("FTP", "⚠️ ضعيف: نقل ملفات غير مشفر"),
    22: ("SSH", "✅ آمن: وصول مشفر"),
    80: ("HTTP", "⚠️ خطير: تواصل غير مشفر (Plaintext)"),
    443: ("HTTPS", "✅ آمن: تواصل مشفر"),
    3306: ("MySQL", "⚠️ تنبيه: قاعدة بيانات مكشوفة")
}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>WebRecon Security Suite</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #38bdf8; border-radius: 15px; }
        .progress-bar { background: linear-gradient(90deg, #38bdf8, #818cf8); }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="card p-5 shadow-lg text-center">
            <h1 style="color: #38bdf8;">🛡️ WebRecon Pro</h1>
            <p class="text-muted">مشروع الأمن السيبراني - جامعة الزيتونة</p>
            
            <form action="/scan" method="get" class="row g-3 justify-content-center">
                <div class="col-md-8">
                    <input type="text" name="target" class="form-control" placeholder="أدخل الموقع (مثلاً google.com)" required>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-info w-100">فحص</button>
                </div>
            </form>

            {% if results %}
            <div class="mt-5 text-start">
                <div class="progress mb-4"><div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%">اكتمل الفحص</div></div>
                <h4>النتائج لـ: <span class="text-info">{{ target }} ({{ ip }})</span></h4>
                <table class="table table-dark mt-3">
                    <thead><tr><th>المنفذ</th><th>الخدمة</th><th>الحالة</th><th>ملاحظات</th></tr></thead>
                    <tbody>
                        {% for r in results %}
                        <tr>
                            <td>{{ r.port }}</td>
                            <td>{{ r.svc }}</td>
                            <td><span class="badge {{ 'bg-success' if 'OPEN' in r.status else 'bg-danger' }}">{{ r.status }}</span></td>
                            <td class="text-warning small">{{ r.vuln }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <form action="/download" method="post">
                    <input type="hidden" name="data" value="{{ report_content }}">
                    <button type="submit" class="btn btn-outline-success">⬇️ تحميل التقرير (TXT)</button>
                </form>

        <footer class="mt-5 text-center text-muted border-top pt-3">
            <p>Developed by: <strong>Fawzi Srawi</strong></p>
            <p>Al-Zaytoonah University of Jordan</p>
        </footer>

    </div> {% endif %}
            </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan')
def scan():
    user_input = request.args.get('target')
    try:
        target_ip = socket.gethostbyname(user_input)
        results = []
        report_text = f"Security Report for {user_input}\n" + "="*30 + "\n"
        for port, info in COMMON_PORTS.items():
            svc, vuln_desc = info
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            res = s.connect_ex((target_ip, port))
            status = "OPEN ✅" if res == 0 else "CLOSED ❌"
            vuln_note = vuln_desc if res == 0 else "N/A"
            results.append({"port": port, "svc": svc, "status": status, "vuln": vuln_note})
            report_text += f"Port {port}: {status} | {vuln_note}\n"
            s.close()
        return render_template_string(HTML_TEMPLATE, results=results, target=user_input, ip=target_ip, report_content=report_text)
    except:
        return "<h2>خطأ في العنوان!</h2><a href='/'>رجوع</a>"

@app.route('/download', methods=['POST'])
def download():
    report_data = request.form.get('data')
    return Response(report_data, mimetype="text/plain", headers={"Content-disposition": "attachment; filename=WebRecon_Report.txt"})
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
