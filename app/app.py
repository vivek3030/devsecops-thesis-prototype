import psutil
import os
import subprocess
from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ✅ FIXED: Secrets loaded from environment variables
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
API_KEY = os.getenv('STRIPE_API_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/cpu')
def cpu():
    return jsonify({'cpu': psutil.cpu_percent(interval=1)})

# ✅ FIXED: No shell injection - use safe subprocess call
@app.route('/api/process')
def process():
    pid = request.args.get('pid', '1')
    # SAFE: Using list of arguments without shell
    result = subprocess.check_output(['ps', '-p', pid])
    return jsonify({'output': result.decode()})

# ✅ FIXED: Use ast.literal_eval for safe expression evaluation
import ast
import operator

@app.route('/api/calculate')
def calculate():
    expression = request.args.get('expr', '1+1')
    try:
        # SAFE: Only allows literals, not arbitrary code execution
        result = ast.literal_eval(expression)
        return jsonify({'result': result})
    except (ValueError, SyntaxError):
        return jsonify({'error': 'Invalid expression'}), 400

# 🔴 SAST VULNERABILITY: SQL injection (simulated)
@app.route('/api/user')
def user():
    user_id = request.args.get('id', '1')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return jsonify({'query': query, 'data': 'Simulated response'})

# ✅ FIXED: Debug disabled, localhost only
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)