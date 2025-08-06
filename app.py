from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from waitress import serve
import os
import secrets
import time
from werkzeug.utils import secure_filename
from review_engine import run_compliance_audit

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = secrets.token_hex(16)  # required for flashing messages

ACCESS_KEY = os.getenv("REPORTSHIELD_KEY", secrets.token_hex(8))

# Optional: Auto-delete old files (>1hr) to keep upload folder clean
def cleanup_uploads(folder, age_limit=3600):
    now = time.time()
    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)
        if os.path.isfile(fpath) and now - os.path.getmtime(fpath) > age_limit:
            os.remove(fpath)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Optional: cleanup old files
            cleanup_uploads(app.config['UPLOAD_FOLDER'])

            audit_output = run_compliance_audit(filepath)
            return render_template('result.html', filename=filename, output=audit_output)
        else:
            flash("❌ Invalid file format. Please upload a valid PDF file.")
            return redirect(url_for('index'))
    return render_template('index.html')

@app.route('/legal')
def legal():
    return render_template('legal.html')  # Made public

@app.route('/uploads/<filename>')
def download_file(filename):
    filename = secure_filename(filename)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
