import psutil
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Realtime CPU Monitor</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; background-color: #f0f2f5; }
        #cpu-usage { font-size: 4em; font-weight: bold; color: #333; margin-top: 20px; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
    </style>
    <script>
        function updateCpu() {
            fetch('/api/cpu')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('cpu-usage').innerText = data.cpu + '%';
                })
                .catch(err => console.error('Error fetching CPU usage:', err));
        }
        setInterval(updateCpu, 1000);
        window.onload = updateCpu;
    </script>
</head>
<body>
    <div class="container">
        <h1>Realtime CPU Usage</h1>
        <div id="cpu-usage">Loading...</div>
    </div>
</body>
</html>
    ''')

@app.route('/api/cpu')
def cpu():
    # interval=None is non-blocking but requires a previous call to be accurate.
    # For a simple demo, we can use a very short blocking interval or just return the instantaneous value since last call.
    # psutil.cpu_percent(interval=None) returns 0.0 on first call.
    return jsonify({'cpu': psutil.cpu_percent(interval=1)})

# For production, use a WSGI server like Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000)
