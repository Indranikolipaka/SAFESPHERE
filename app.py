import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import secrets
from functools import wraps

# ---------- CONFIG ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'safesphere.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DEBUG'] = True

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------- DATABASE ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database if it doesn't exist"""
    if not os.path.exists(DB_PATH):
        conn = get_db()
        schema_path = os.path.join(BASE_DIR, 'schema.sql')
        if os.path.exists(schema_path):
            with open(schema_path, 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
        # Ensure reset_tokens table exists
        conn.execute('''CREATE TABLE IF NOT EXISTS reset_tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            token TEXT NOT NULL UNIQUE,
                            expires_at TEXT NOT NULL,
                            used INTEGER DEFAULT 0,
                            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')
        conn.commit()
        # Seed principal account
        hashed = generate_password_hash('ChangeMe123!')
        try:
            principal_id = conn.execute("INSERT INTO users (role, username, password, email, approved) VALUES (?, ?, ?, ?, 1)",
                                        ('principal', 'principal', hashed, 'principal@rbvrr.edu')).lastrowid
            generate_reset_token(conn, principal_id)
        except Exception:
            pass
        conn.commit()
        conn.close()

    # Ensure 'approved' column exists
    conn = get_db()
    try:
        conn.execute("ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 1")
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists
        pass
    finally:
        conn.close()

# ---------- TOKEN & HELPERS ----------
def generate_reset_token(conn, user_id, hours=24):
    """Generate a reset token and store in DB"""
    conn.execute('DELETE FROM reset_tokens WHERE user_id = ?', (user_id,))
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=hours)
    conn.execute('INSERT INTO reset_tokens (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)',
                 (user_id, token, expires.isoformat()))
    conn.commit()
    return token

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def generate_student_code(conn):
    count = conn.execute('SELECT COUNT(*) as c FROM students').fetchone()['c'] or 0
    return f"RBVSTU{count+1:04d}"

def is_logged_in():
    return 'user_id' in session

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('You must be logged in', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

# ---------- INIT ----------
init_db()

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

# --- LOGIN / LOGOUT ---
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if user and check_password_hash(user['password'], password):
        if user['role'] in ['teacher', 'student'] and not user['approved']:
            flash('Your account is pending approval', 'warning')
            return redirect(url_for('index'))
        session.update({'user_id': user['id'], 'username': user['username'], 'role': user['role']})
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

# --- PASSWORD MANAGEMENT ---
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE username=? OR email=?', (identifier, identifier)).fetchone()
            if user:
                token = generate_reset_token(conn, user['id'])
                flash(f'✓ Reset token: {token}', 'success')
            else:
                flash('User not found', 'warning')
        return redirect(url_for('index'))
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    with get_db() as conn:
        reset = conn.execute('SELECT * FROM reset_tokens WHERE token=? AND used=0', (token,)).fetchone()
        if not reset or datetime.fromisoformat(reset['expires_at']) < datetime.utcnow():
            flash('Invalid or expired token', 'danger')
            return redirect(url_for('index'))
        if request.method == 'POST':
            new_pw = request.form.get('new_password')
            confirm = request.form.get('confirm_password')
            if new_pw != confirm:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('reset_password', token=token))
            hashed = generate_password_hash(new_pw)
            conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, reset['user_id']))
            conn.execute('UPDATE reset_tokens SET used=1 WHERE id=?', (reset['id'],))
            conn.commit()
            flash('Password reset successfully', 'success')
            return redirect(url_for('index'))
    return render_template('reset_password.html')

@app.route('/change_password', methods=['GET','POST'])
@require_login
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password')
        new_pw = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if new_pw != confirm:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
            if not check_password_hash(user['password'], current):
                flash('Current password incorrect', 'danger')
                return redirect(url_for('change_password'))
            conn.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(new_pw), user['id']))
            conn.commit()
        flash('Password changed successfully', 'success')
        return redirect(url_for(f"{session['role']}_dashboard"))
    return render_template('change_password.html')

# ---------- DASHBOARDS ----------
@app.route('/student_dashboard')
@require_login
def student_dashboard():
    if session.get('role') != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    with get_db() as conn:
        student = conn.execute('SELECT * FROM students WHERE id=(SELECT ref_id FROM users WHERE id=?)', (session['user_id'],)).fetchone()
        complaints = conn.execute('SELECT c.*, t.name AS teacher_name FROM complaints c LEFT JOIN teachers t ON t.id=c.teacher_id WHERE c.student_id=? ORDER BY c.created_at DESC', (student['id'],)).fetchall()
        feedback_map = {fb['complaint_id']: fb for fb in conn.execute('SELECT * FROM feedback').fetchall()}
        token_row = conn.execute('SELECT * FROM reset_tokens WHERE user_id=? AND used=0 ORDER BY created_at DESC LIMIT 1', (session['user_id'],)).fetchone()
        token = token_row['token'] if token_row else None
        token_expires = token_row['expires_at'] if token_row else None
    accepted = sum(1 for c in complaints if c['status'] == 'Accepted')
    rejected = sum(1 for c in complaints if c['status'] == 'Rejected')
    return render_template('student_dashboard.html', student=student, complaints=complaints,
                           feedback_map=feedback_map, total=len(complaints), accepted=accepted,
                           rejected=rejected, reset_token=token, reset_expires=token_expires)

@app.route('/teacher_dashboard')
@require_login
def teacher_dashboard():
    if session.get('role') != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    with get_db() as conn:
        teacher = conn.execute('SELECT t.*, u.username, u.email FROM teachers t JOIN users u ON u.id=t.user_id WHERE u.id=?', (session['user_id'],)).fetchone()
        my_students = conn.execute('SELECT * FROM students WHERE mentor_id=? ORDER BY created_at DESC', (teacher['id'],)).fetchall()
        complaints = conn.execute('SELECT c.*, s.name AS student_name FROM complaints c LEFT JOIN students s ON s.id=c.student_id WHERE c.teacher_id=? ORDER BY c.created_at DESC', (teacher['id'],)).fetchall()
        applicants = conn.execute('SELECT u.id AS user_id, u.username, u.email, s.name, s.unique_code FROM users u LEFT JOIN students s ON s.id=u.ref_id WHERE u.role="student" AND u.approved=0').fetchall()
    accepted = sum(1 for c in complaints if c['status'].lower() == 'accepted')
    rejected = sum(1 for c in complaints if c['status'].lower() == 'rejected')
    return render_template('teacher_dashboard.html', teacher=teacher, my_students=my_students,
                           complaints=complaints, accepted=accepted, rejected=rejected, applicants=applicants)

@app.route('/principal_dashboard')
@require_login
def principal_dashboard():
    if session.get('role') != 'principal':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    with get_db() as conn:
        teachers = conn.execute('SELECT * FROM teachers ORDER BY name ASC').fetchall()
        pc = conn.execute('SELECT status, COUNT(*) as c FROM complaints GROUP BY status').fetchall()
        token_row = conn.execute('SELECT * FROM reset_tokens WHERE user_id=? AND used=0 ORDER BY created_at DESC LIMIT 1', (session['user_id'],)).fetchone()
        token = token_row['token'] if token_row else None
        token_expires = token_row['expires_at'] if token_row else None
    return render_template('principal_dashboard.html', teachers=teachers, pc=pc, reset_token=token, reset_expires=token_expires)

# ---------- COMPLAINTS ----------
# ... Include complaint routes similarly with proper get_db() context, allowed_file, and safe updates

@app.route('/create_student', methods=['POST'])
@require_login
def create_student():
    if session.get('role') != 'teacher':
        return redirect(url_for('index'))
    
    fullname = request.form.get('fullname')
    username = request.form.get('username')
    password = request.form.get('password')
    roll_no = request.form.get('roll_no')
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        flash('Username already exists', 'danger')
        conn.close()
        return redirect(url_for('teacher_dashboard'))
    
    teacher = conn.execute('SELECT ref_id FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    teacher_id = teacher['ref_id']
    
    hashed = generate_password_hash(password)
    try:
        code = generate_student_code(conn)
        user_id = conn.execute(
            'INSERT INTO users (role, username, password, email, phone, approved) VALUES (?, ?, ?, ?, ?, 1)',
            ('student', username, hashed, email, phone)
        ).lastrowid
        student_id = conn.execute('INSERT INTO students (name, unique_code, mentor_id, roll_no) VALUES (?, ?, ?, ?)',
                    (fullname, code, teacher_id, roll_no)).lastrowid
        conn.execute('UPDATE users SET ref_id = ? WHERE id = ?', (student_id, user_id))
        conn.commit()
        # Generate reset token for new student
        token = generate_reset_token(conn, user_id)
        flash(f'✓ Student {fullname} created! Reset token: {token}', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/delete_student', methods=['POST'])
@require_login
def delete_student():
    if session.get('role') != 'teacher':
        return redirect(url_for('index'))
    
    student_id = request.form.get('student_id')
    conn = get_db()
    
    conn.execute('DELETE FROM complaints WHERE student_id = ?', (student_id,))
    conn.execute('DELETE FROM feedback WHERE complaint_id IN (SELECT id FROM complaints WHERE student_id = ?)', (student_id,))
    conn.execute('DELETE FROM students WHERE id = ?', (student_id,))
    conn.execute('DELETE FROM users WHERE ref_id = ?', (student_id,))
    conn.commit()
    conn.close()
    
    flash('Student deleted', 'success')
    return redirect(url_for('teacher_dashboard'))

# ---------- FILE UPLOADS ----------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=app.config['DEBUG'])
