from flask import Flask, render_template, request, send_file
from waitress import serve
import os
import secrets
from werkzeug.utils import secure_filename
from review_engine import run_compliance_audit  # updated import

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
            filename = secure_filename(file.filename)  # sanitize filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            audit_output = run_compliance_audit(filepath)  # single return
            return render_template('result.html', filename=filename, output=audit_output)
        else:
            return "Invalid file format. Only PDF files are supported."
    return render_template('index.html')

@app.route('/legal')
def legal():
    key = request.args.get("key")
    app.logger.debug(f"Legal page access key: {key}")
    if key != ACCESS_KEY:
        return "Access denied. Append ?key=ACCESS_KEY to the URL."
    return render_template('legal.html')

@app.route('/uploads/<filename>')
def download_file(filename):
    filename = secure_filename(filename)  # sanitize filename
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
