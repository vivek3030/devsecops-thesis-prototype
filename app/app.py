import psutil
from flask import Flask, jsonify, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/cpu')
def cpu():
    # interval=None is non-blocking but requires a previous call to be accurate.
    # For a simple demo, we can use a very short blocking interval or just return the instantaneous value since last call.
    # psutil.cpu_percent(interval=None) returns 0.0 on first call.
    return jsonify({'cpu': psutil.cpu_percent(interval=1)})

# For production, use a WSGI server like Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000)
