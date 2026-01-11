from flask import Flask, render_template, request, jsonify
import os
import hashlib
import sqlite3
from datetime import datetime
from werkzeug.utils import secure_filename
from sklearn.ensemble import IsolationForest
import numpy as np

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
DB_FILE = 'database.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize DB
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            uploader TEXT,
            file_hash TEXT,
            block_hash TEXT,
            timestamp TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ledger_id INTEGER,
            message TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper: get last block hash
def get_last_block_hash():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT block_hash FROM evidence ORDER BY id DESC LIMIT 1')
    row = c.fetchone()
    conn.close()
    return row[0] if row else '0' * 64

# Helper: get historical upload data for AI
def get_historical_data():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT uploader, file_hash, timestamp FROM evidence")
    rows = c.fetchall()
    conn.close()

    # Convert timestamps to numeric intervals
    times = []
    for r in rows:
        try:
            dt = datetime.strptime(r[2], '%Y-%m-%d %H:%M:%S')
            times.append(dt.timestamp())
        except:
            times.append(0)

    # Feature: [upload order, hash uniqueness]
    X = []
    for i, (uploader, file_hash, _) in enumerate(rows):
        uploader_score = hash(uploader) % 10000  # convert string to numeric
        hash_score = int(file_hash[:6], 16) % 10000
        time_val = times[i] / 1e6
        X.append([uploader_score, hash_score, time_val])
    return np.array(X) if X else np.empty((0, 3))

# Home
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify')
def verify():
    return render_template('verify.html')

# Upload API
@app.route('/api/upload', methods=['POST'])
def upload_evidence():
    file = request.files.get('evidence')
    uploader = request.form.get('uploader', 'unknown')

    if not file:
        return jsonify({'ok': False, 'error': 'No file uploaded'})

    filename = secure_filename(file.filename)
    file_bytes = file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    file.seek(0)

    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    prev_hash = get_last_block_hash()
    block_hash = hashlib.sha256((file_hash + uploader + prev_hash).encode()).hexdigest()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO evidence (filename, uploader, file_hash, block_hash, timestamp) VALUES (?, ?, ?, ?, ?)',
              (filename, uploader, file_hash, block_hash, timestamp))
    evidence_id = c.lastrowid
    conn.commit()
    conn.close()

    # === AI Anomaly Detection ===
    X = get_historical_data()
    if len(X) > 5:  # train only if enough data
        model = IsolationForest(contamination=0.2, random_state=42)
        preds = model.fit_predict(X)
        if preds[-1] == -1:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            alert_msg = f"AI anomaly detected: unusual upload behavior for '{filename}' by {uploader}"
            c.execute('INSERT INTO alerts (ledger_id, message, timestamp) VALUES (?, ?, ?)',
                      (evidence_id, alert_msg, timestamp))
            conn.commit()
            conn.close()

    # === Manual rule-based detection (duplicate upload) ===
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM evidence WHERE file_hash=? AND uploader=?', (file_hash, uploader))
    rows = c.fetchall()
    if len(rows) > 1:
        msg = f"Repeated upload detected for file '{filename}' by uploader '{uploader}'"
        c.execute('INSERT INTO alerts (ledger_id, message, timestamp) VALUES (?, ?, ?)',
                  (evidence_id, msg, timestamp))
    conn.commit()
    conn.close()

    print(f"[UPLOAD] File: {filename}, Hash: {file_hash}, Block: {block_hash}, Uploader: {uploader}")
    return jsonify({'ok': True, 'evidence_id': evidence_id, 'file_hash': file_hash, 'block_hash': block_hash})

# Logs API
@app.route('/api/logs')
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, filename, block_hash, timestamp FROM evidence ORDER BY id DESC')
    data = [{'ledger_id': row[0], 'filename': row[1], 'block_hash': row[2], 'timestamp': row[3]} for row in c.fetchall()]
    conn.close()
    return jsonify({'ok': True, 'ledgers': data})

# Alerts API
@app.route('/api/alerts')
def get_alerts():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT ledger_id, message FROM alerts ORDER BY id DESC')
    alerts = [{'ledger_id': row[0], 'message': row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify({'ok': True, 'alerts': alerts})

# Verify API
@app.route('/api/verify', methods=['POST'])
def verify_evidence():
    evidence_id = request.form.get('evidence_id')
    file = request.files.get('evidence')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    if evidence_id:
        c.execute('SELECT * FROM evidence WHERE id=?', (evidence_id,))
    elif file:
        file_bytes = file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        c.execute('SELECT * FROM evidence WHERE file_hash=?', (file_hash,))
    else:
        conn.close()
        return jsonify({'ok': False, 'error': 'No input provided'})

    row = c.fetchone()
    conn.close()

    if row:
        return jsonify({'ok': True, 'match': True, 'record': row})
    else:
        return jsonify({'ok': True, 'match': False})

if __name__ == '__main__':
    app.run(debug=True)