from flask import Flask, render_template, jsonify, redirect, url_for, request, flash
import os
import platform
import configparser
import time
import threading
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta'  # Mude para algo seguro
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Função para carregar os servidores do arquivo .ini
def load_servers():
    config = configparser.ConfigParser()
    config.read('servers.ini')
    
    categories = {}
    for section in config.sections():
        servers = []
        for name, ip in config.items(section):
            servers.append({"name": name.capitalize(), "ip": ip})
        categories[section] = servers
    return categories

# Função para verificar se o servidor está online ou offline e retorna o ping
def check_server(ip):
    system = platform.system()
    response = None
    ping_time = None

    try:
        if system == "Windows":
            response = os.popen(f"ping -n 1 {ip}").read()
        else:  # Linux ou macOS
            response = os.popen(f"ping -c 1 {ip}").read()

        # Extraindo o tempo de ping da resposta
        if "time=" in response:
            ping_time = response.split("time=")[1].split("ms")[0].strip()
        else:
            return False, None  # Servidor offline ou erro
        
    except Exception as e:
        print(f"Erro ao verificar o servidor {ip}: {e}")
        return False, None
    
    return True, ping_time  # Retorna status e ping

# Dicionário para armazenar o histórico de uptime e o status do heartbeat
uptime_history = {}
heartbeat_active = {}

# Função para atualizar o status do servidor a cada 5 minutos
def heartbeat():
    while True:
        servers = load_servers()  # Carrega os servidores uma vez aqui
        current_time = time.time()
        
        for category, server_list in servers.items():
            for server in server_list:
                ip = server['ip']
                status, ping = check_server(ip)

                if ip not in uptime_history:
                    uptime_history[ip] = []

                # Limita o histórico a 2 horas (7200 segundos)
                uptime_history[ip] = [entry for entry in uptime_history[ip]
                                    if current_time - entry['time'] <= 7200]

                # Adiciona nova entrada se o status mudou
                heartbeat_active[ip] = status  # Atualiza o status do coração
                uptime_history[ip].append({'time': current_time, 'status': 'Online' if status else 'Offline'})
            
                # Armazena o ping no histórico
                server['ping'] = ping  # Armazena o ping se o servidor estiver online
                if status:
                    server['ping'] = ping  # Atualiza o ping se o servidor estiver online
                else:
                    server['ping'] = None  # Se offline, o ping é None
        
        time.sleep(300)  # Espera 5 minutos

# Inicia a thread para o heartbeat
threading.Thread(target=heartbeat, daemon=True).start()

@app.route('/')
@login_required  # Protege a rota
def index():
    categories = load_servers()  # Carrega as categorias do arquivo .ini
    return render_template('index.html', categories=categories)

@app.route('/category/<category_name>')
@login_required  # Protege a rota
def show_category(category_name):
    categories = load_servers()  # Carrega os servidores para a página da categoria
    servers = categories.get(category_name, [])
    
    server_status = []
    for server in servers:
        ip = server['ip']
        status, ping = check_server(ip)
        server_status.append({
            "name": server["name"],
            "ip": ip,
            "status": status,  # Booleano para status online/offline
            "color": "green" if status else "red",
            "ping": ping  # Adiciona o ping aqui
        })

    return render_template('category.html', servers=server_status, category_name=category_name)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:  # Substitua isso por uma verificação de hash real
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas. Tente novamente.')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verifica se o usuário já existe
        if User.query.filter_by(username=username).first():
            flash('Usuário já existe. Tente outro nome.')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuário registrado com sucesso! Agora você pode fazer login.')

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/uptime/<ip>')
@login_required
def uptime(ip):
    return jsonify(uptime_history.get(ip, []))

if __name__ == '__main__':
    with app.app_context():  # Cria o contexto de aplicativo
        db.create_all()  # Cria o banco de dados se não existir
    app.run(debug=True)
