from flask import Flask, render_template, request, send_file, redirect, url_for
from waitress import serve
import os
import secrets
from review_engine import run_full_audit  # ✅ UPDATED function name

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ACCESS_KEY = os.getenv("REPORTSHIELD_KEY", secrets.token_hex(8))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.pdf'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            audit_output, flags = run_full_audit(filepath, file.filename)  # ✅ Dual return
            return render_template('result.html', filename=file.filename, output=audit_output)
        else:
            return "Invalid file format. Only PDF files are supported."
    return render_template('index.html')

@app.route('/legal')
def legal():
    key = request.args.get("key")
    if key != ACCESS_KEY:
        return "Access denied. Append ?key=ACCESS_KEY to the URL."
    return render_template('legal.html')

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
