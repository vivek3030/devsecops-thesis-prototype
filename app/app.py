import psutil
import os
import subprocess
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# 🔴 SAST VULNERABILITY: Hardcoded secrets (Semgrep will flag)
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_KEY = "sk_live_51H7X8s2eZvKYlo2C4x6InsecureAPIKey"
DATABASE_URL = "postgres://user:password123@localhost/db"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/cpu')
def cpu():
    return jsonify({'cpu': psutil.cpu_percent(interval=1)})

# 🔴 SAST VULNERABILITY: Command injection
@app.route('/api/process')
def process():
    pid = request.args.get('pid', '1')
    # DANGER: Direct user input in shell command
    result = subprocess.check_output(f"ps -p {pid}", shell=True)
    return jsonify({'output': result.decode()})

# 🔴 SAST VULNERABILITY: Code execution via eval
@app.route('/api/calculate')
def calculate():
    expression = request.args.get('expr', '1+1')
    # DANGER: Using eval on user input
    result = eval(expression)
    return jsonify({'result': result})

# 🔴 SAST VULNERABILITY: SQL injection (simulated)
@app.route('/api/user')
def get_user():
    user_id = request.args.get('id', '1')
    # DANGER: String concatenation in query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return jsonify({'query': query, 'data': 'Simulated response'})

# 🔴 SAST VULNERABILITY: Debug mode in production
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)