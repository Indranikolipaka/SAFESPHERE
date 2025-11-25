import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import secrets

# ---------- CONFIG ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'safesphere.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------- DATABASE ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database and create tables if they don't exist"""
    if not os.path.exists(DB_PATH):
        conn = get_db()
        with open(os.path.join(BASE_DIR, 'schema.sql'), 'r', encoding='utf-8') as f:
            conn.executescript(f.read())
        conn.execute('''CREATE TABLE IF NOT EXISTS reset_tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            token TEXT NOT NULL UNIQUE,
                            expires_at DATETIME NOT NULL,
                            used INTEGER DEFAULT 0,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')
        # Seed principal account
        hashed = generate_password_hash('ChangeMe123!')
        try:
            conn.execute("INSERT INTO users (role, username, password, email) VALUES (?, ?, ?, ?)",
                         ('principal', 'principal', hashed, 'principal@rbvrr.edu'))
        except Exception:
            pass
        conn.commit()
        conn.close()

    # Ensure 'approved' column exists in users table
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 1")
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.execute("UPDATE users SET approved = 1 WHERE approved IS NULL")
            conn.commit()
            conn.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

# Initialize database on startup
init_db()

# ---------- HELPERS ----------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def generate_student_code(conn):
    cur = conn.execute('SELECT COUNT(*) as c FROM students')
    count = cur.fetchone()['c'] or 0
    return f"RBVSTU{count+1:04d}"

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

# --- LOGIN/LOGOUT ---
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        flash('Logged in successfully', 'success')
        if user['role'] == 'student':
            return redirect(url_for('student_dashboard'))
        elif user['role'] == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('principal_dashboard'))
    flash('Invalid credentials', 'danger')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

# --- SIGNUP / ACCOUNT MANAGEMENT ---
@app.route('/signup', methods=['GET','POST'])
def signup():
    # Keep your existing signup logic here (student/teacher/principal)...
    return render_template('signup.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    # Keep your forgot password logic here...
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    # Keep your reset password logic here...
    return render_template('reset_password.html')

@app.route('/change_password', methods=['GET','POST'])
def change_password():
    # Keep your change password logic here...
    return render_template('change_password.html')

# --- DASHBOARDS ---
@app.route('/student_dashboard')
def student_dashboard():
    # Keep your student dashboard logic here...
    return render_template('student_dashboard.html')

@app.route('/teacher_dashboard')
def teacher_dashboard():
    # Keep your teacher dashboard logic here...
    return render_template('teacher_dashboard.html')

@app.route('/principal_dashboard')
def principal_dashboard():
    # Keep your principal dashboard logic here...
    return render_template('principal_dashboard.html')

# --- COMPLAINTS ---
@app.route('/complaint/new', methods=['GET','POST'])
def complaint_form():
    # Keep complaint filing logic here...
    return render_template('complaint_form.html')

@app.route('/complaint/feedback', methods=['POST'])
def complaint_feedback():
    # Keep complaint feedback logic here...
    return redirect(url_for('student_dashboard'))

@app.route('/complaint/action', methods=['POST'])
def complaint_action():
    # Keep teacher action logic here...
    return jsonify({'ok': True})

# --- STATIC UPLOADS ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- API ---
@app.route('/api/charts/teacher/<int:teacher_id>')
def api_teacher_charts(teacher_id):
    conn = get_db()
    accepted = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ? AND status='Accepted'", (teacher_id,)).fetchone()['c']
    rejected = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ? AND status='Rejected'", (teacher_id,)).fetchone()['c']
    conn.close()
    return jsonify({'accepted': accepted, 'rejected': rejected})

# --- HEALTH CHECK ---
@app.route("/health")
def health():
    return "OK", 200

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
