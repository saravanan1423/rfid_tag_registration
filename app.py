from flask import Flask, render_template, request, redirect, session, url_for
import hashlib, socket, pymysql
from datetime import timedelta

from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(hours=8)

@app.before_request
def make_session_permanent():
    session.permanent = True

# DB config
db_config = {
    'host': os.getenv("DB_HOST"),
    'user': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASSWORD"),
    'database': os.getenv("DB_DATABASE"),
    'cursorclass': pymysql.cursors.DictCursor
}

READER_IP = os.getenv("RFID_READER_IP")
READER_PORT = (os.getenv("RFID_READER_PORT"))

inventory_command = bytes.fromhex("BB 02 21 08 DE B3")

def get_db_connection():
    return pymysql.connect(**db_config)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def extract_epc(data):
    raw = data.hex().upper()
    results = []
    i = 0
    while i < len(raw):
        if raw[i:i+2] == "E0":
            try:
                epc_start = i + 6
                epc_end = epc_start + 24
                epc = raw[epc_start:epc_end][9:15]
                if len(epc) == 6:
                    results.append(epc)
                i = epc_end
            except:
                i += 2
        else:
            i += 2
    return results

def load_existing_epc_map():
    epc_map = {}
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT epc, name FROM rfid_tags")
    for epc, name in cursor.fetchall():
        epc_map[epc] = name
    cursor.close()
    conn.close()
    return epc_map

def save_epc_to_db(epc, name):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if EPC already exists
        cursor.execute("SELECT name FROM rfid_tags WHERE epc = %s", (epc,))
        existing = cursor.fetchone()

        if existing:
            return f"EPC {epc} already registered as '{existing['name']}'."
        else:
            cursor.execute("INSERT INTO rfid_tags (epc, name) VALUES (%s, %s)", (epc, name))
            conn.commit()
            return f"EPC {epc} saved as '{name}'."
    finally:
        cursor.close()
        conn.close()


def scan_rfid():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect((READER_IP, READER_PORT))
        s.sendall(inventory_command)
        data = s.recv(1024)
        if data:
            results = extract_epc(data)
            return results[0] if results else None
    return None

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_login():
    username = request.form['username']
    password = request.form['password']
    hashed_pwd = hash_password(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM authentication WHERE user=%s AND password=%s", (username, hashed_pwd))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        session['username'] = user['user']
        if user['user'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user['user'] == 'test':
            return redirect(url_for('test_page'))
        else:
            return f"User '{user['user']}' is not recognized."
    else:
        return "Invalid credentials"

@app.route('/admin')
def admin_dashboard():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))

    status = session.pop('status', "")
    epc = session.get('scanned_epc')
    step = session.get('step', 'scan')
    name = session.get('scanned_name')

    if step == 'done':
        session['step'] = 'scan'
        session.pop('scanned_epc', None)
        session.pop('scanned_name', None)

    return render_template('index.html', epc=epc, status=status, step=step, name=name)

@app.route('/admin/scan', methods=['POST'])
def scan():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))

    scanned = scan_rfid()
    if not scanned:
        session['status'] = "No tag detected. Please try again."
        return redirect(url_for('admin_dashboard'))

    epc_map = load_existing_epc_map()
    step = session.get('step')

    # BLOCK ALL PROGRESS IF TAG IS ALREADY REGISTERED
    if scanned in epc_map:
        session['status'] = f"EPC {scanned} is already registered as '{epc_map[scanned]}'."
        session['scanned_epc'] = scanned
        session['scanned_name'] = epc_map[scanned]
        session['step'] = 'done'  # Prevent going to rescan or name entry
        return redirect(url_for('admin_dashboard'))

    # If this is the first scan and tag is not registered
    if step != 'rescan':
        session['scanned_epc'] = scanned
        session['status'] = f"Tag scanned: {scanned}. Please rescan to confirm."
        session['step'] = 'rescan'
        return redirect(url_for('admin_dashboard'))

    # If rescan step and tag is not in DB
    original = session.get('scanned_epc')
    if scanned == original:
        session['status'] = f"Verified! EPC {scanned} matched. Please enter name to save."
        session['step'] = 'name'
    else:
        session['status'] = "Mismatch. Please scan the same tag again."
        session['step'] = 'scan'
        session.pop('scanned_epc', None)

    return redirect(url_for('admin_dashboard'))


@app.route('/register', methods=['POST'])
def register():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))

    epc = session.get('scanned_epc')
    name = request.form.get('name')

    if epc and name:
        message=save_epc_to_db(epc, name)
        session['status'] = message
    else:
        session['status'] = "Missing EPC or name. Please try again."

    session['step'] = 'scan'
    session.pop('scanned_epc', None)
    session.pop('scanned_name', None)

    return redirect(url_for('admin_dashboard'))

@app.route('/registered', methods=['GET'])
def registered_tags():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, epc, name FROM rfid_tags")
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('registered_tags.html', users=users)

@app.route('/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('username') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rfid_tags WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('registered_tags'))

# THIS FUNCTIONALITY IS NOT USED CURRENTLY
# @app.route('/test')
# def test_page():
#     if session.get('username') == 'test':
#         return "Welcome Test User!"
#     return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
