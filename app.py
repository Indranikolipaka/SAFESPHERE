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
app.config['DEBUG'] = True

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------- DATABASE ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_reset_token(conn, user_id):
    """Generate a new reset token for a user (valid for 24 hours)"""
    # Delete any existing tokens for this user
    conn.execute('DELETE FROM reset_tokens WHERE user_id = ?', (user_id,))
    # Create a new token that expires in 24 hours
    token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(hours=24)
    conn.execute('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                (user_id, token, expires))
    conn.commit()
    return token

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
            principal_id = conn.execute("INSERT INTO users (role, username, password, email) VALUES (?, ?, ?, ?)",
                         ('principal', 'principal', hashed, 'principal@rbvrr.edu')).lastrowid
            # Generate reset token for principal
            generate_reset_token(conn, principal_id)
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

def create_reset_token_for_user(conn, user_id, hours=24):
    """Create and store a reset token for given user_id. Returns (token, expires)."""
    token = secrets.token_urlsafe(16)
    expires = datetime.now() + timedelta(hours=hours)
    conn.execute('INSERT INTO reset_tokens (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)',
                 (user_id, token, expires))
    conn.commit()
    return token, expires

def is_logged_in():
    return 'user_id' in session

def require_login(f):
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('You must be logged in', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

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
        if user['role'] in ['teacher', 'student'] and not user['approved']:
            flash('Your account is pending approval', 'warning')
            return redirect(url_for('index'))
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
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        dob = request.form.get('dob')
        username = request.form.get('username')
        password = request.form.get('password')
        create_for = request.form.get('create_for', 'student')
        
        conn = get_db()
        # Check if username exists
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            flash('Username already exists', 'danger')
            conn.close()
            return redirect(url_for('signup'))
        
        hashed = generate_password_hash(password)
        try:
            if create_for == 'student':
                # Student self-signup (needs approval)
                user_id = conn.execute(
                    'INSERT INTO users (role, username, password, email, phone, dob, approved) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    ('student', username, hashed, email, phone, dob, 0)
                ).lastrowid
                code = generate_student_code(conn)
                conn.execute('INSERT INTO students (name, unique_code) VALUES (?, ?)', (fullname, code))
                conn.commit()
                # Generate reset token for new student
                token = generate_reset_token(conn, user_id)
                flash(f'✓ Account created! Your reset token: {token}. Awaiting teacher approval.', 'info')
            elif create_for == 'teacher':
                # Teacher self-signup (needs approval)
                user_id = conn.execute(
                    'INSERT INTO users (role, username, password, email, phone, dob, approved) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    ('teacher', username, hashed, email, phone, dob, 0)
                ).lastrowid
                code = f"RBVTCH{conn.execute('SELECT COUNT(*) as c FROM teachers').fetchone()['c']+1:04d}"
                conn.execute('INSERT INTO teachers (name, teacher_code) VALUES (?, ?)', (fullname, code))
                conn.commit()
                # Generate reset token for new teacher
                token = generate_reset_token(conn, user_id)
                flash(f'✓ Teacher account created! Your reset token: {token}. Awaiting principal approval.', 'info')
        except Exception as e:
            conn.rollback()
            flash(f'Error: {str(e)}', 'danger')
        finally:
            conn.close()
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier)).fetchone()
        if user:
            token = generate_reset_token(conn, user['id'])
            flash(f'✓ Reset token generated! Use this token to reset your password: {token}', 'success')
        else:
            flash('User not found. Please check your username or email.', 'warning')
        conn.close()
        return redirect(url_for('index'))
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    conn = get_db()
    reset = conn.execute('SELECT * FROM reset_tokens WHERE token = ? AND used = 0 AND expires_at > datetime("now")', (token,)).fetchone()
    if not reset:
        flash('Invalid or expired token', 'danger')
        conn.close()
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if new_password != confirm:
            flash('Passwords do not match', 'danger')
            conn.close()
            return redirect(url_for('reset_password', token=token))
        
        hashed = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, reset['user_id']))
        conn.execute('UPDATE reset_tokens SET used = 1 WHERE id = ?', (reset['id'],))
        conn.commit()
        flash('Password reset successfully', 'success')
        conn.close()
        return redirect(url_for('index'))
    
    conn.close()
    return render_template('reset_password.html')

@app.route('/change_password', methods=['GET','POST'])
def change_password():
    if not is_logged_in():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current = request.form.get('current_password')
        new_pw = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        
        if new_pw != confirm:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not check_password_hash(user['password'], current):
            flash('Current password is incorrect', 'danger')
            conn.close()
            return redirect(url_for('change_password'))
        
        hashed = generate_password_hash(new_pw)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user['id']))
        conn.commit()
        conn.close()
        flash('Password changed successfully', 'success')
        return redirect(url_for('student_dashboard' if session['role'] == 'student' else 'teacher_dashboard' if session['role'] == 'teacher' else 'principal_dashboard'))
    
    return render_template('change_password.html')

# --- DASHBOARDS ---
@app.route('/student_dashboard')
@require_login
def student_dashboard():
    if session.get('role') != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db()
    student = conn.execute('SELECT * FROM students WHERE id = (SELECT ref_id FROM users WHERE id = ?)', (session['user_id'],)).fetchone()
    if not student:
        flash('Student profile not found', 'danger')
        conn.close()
        return redirect(url_for('logout'))
    
    complaints = conn.execute('''
        SELECT c.*, t.name as teacher_name FROM complaints c
        LEFT JOIN teachers t ON c.teacher_id = t.id
        WHERE c.student_id = ?
        ORDER BY c.created_at DESC
    ''', (student['id'],)).fetchall()
    
    feedback_map = {}
    for fb in conn.execute('SELECT * FROM feedback').fetchall():
        feedback_map[fb['complaint_id']] = fb
    
    total = len(complaints)
    accepted = sum(1 for c in complaints if c['status'] == 'Accepted')
    rejected = sum(1 for c in complaints if c['status'] == 'Rejected')
    
    # find latest valid reset token for this user (if any)
    token_row = conn.execute('SELECT * FROM reset_tokens WHERE user_id = ? AND used = 0 AND expires_at > datetime("now") ORDER BY created_at DESC LIMIT 1', (session['user_id'],)).fetchone()
    token = token_row['token'] if token_row else None
    token_expires = token_row['expires_at'] if token_row else None
    conn.close()
    
    return render_template('student_dashboard.html', student=student, complaints=complaints, feedback_map=feedback_map, total=total, accepted=accepted, rejected=rejected, reset_token=token, reset_expires=token_expires)

@app.route('/teacher_dashboard')
@require_login
def teacher_dashboard():
    # Access control
    if session.get('role') != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))

    conn = get_db()

    # Fetch teacher profile (correct)
    teacher = conn.execute(
        '''
        SELECT * FROM teachers 
        WHERE id = (SELECT ref_id FROM users WHERE id = ?)
        ''',
        (session['user_id'],)
    ).fetchone()

    if not teacher:
        flash('Teacher profile not found', 'danger')
        conn.close()
        return redirect(url_for('logout'))

    teacher_id = teacher['id']

    # Fetch complaints assigned to this teacher
    complaints = conn.execute(
        '''
        SELECT c.*, s.name AS student_name
        FROM complaints c
        JOIN students s ON c.student_id = s.id
        WHERE c.teacher_id = ?
        ORDER BY c.created_at DESC
        ''',
        (teacher_id,)
    ).fetchall()

    # Complaint statistics
    accepted = sum(c['status'] == 'Accepted' for c in complaints)
    rejected = sum(c['status'] == 'Rejected' for c in complaints)

    # FIXED: pending student applicants query
    applicants = conn.execute(
        '''
        SELECT u.id AS user_id, u.username, u.email, st.name, st.unique_code
        FROM users u
        JOIN students st ON u.ref_id = st.id        -- FIXED JOIN
        WHERE u.approved = 0 AND u.role = 'student'
        '''
    ).fetchall()

    # Students created by this teacher
    my_students = conn.execute(
        '''
        SELECT * FROM students
        WHERE mentor_id = ?
        ORDER BY created_at DESC
        ''',
        (teacher_id,)
    ).fetchall()

    # Reset token for teacher (if exists)
    token_row = conn.execute(
        '''
        SELECT * FROM reset_tokens
        WHERE user_id = ?
        AND used = 0
        AND expires_at > datetime("now")
        ORDER BY created_at DESC
        LIMIT 1
        ''',
        (session['user_id'],)
    ).fetchone()

    token = token_row['token'] if token_row else None
    token_expires = token_row['expires_at'] if token_row else None

    conn.close()

    # Render dashboard
    return render_template(
        'teacher_dashboard.html',
        teacher=teacher,
        complaints=complaints,
        accepted=accepted,
        rejected=rejected,
        applicants=applicants,
        my_students=my_students,
        reset_token=token,
        reset_expires=token_expires
    )



@app.route('/principal_dashboard')
@require_login
def principal_dashboard():
    if session.get('role') != 'principal':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))

    conn = get_db()
    conn.row_factory = sqlite3.Row  # <--- important

    # Get all teachers with performance metrics
    teachers = conn.execute('''
        SELECT * FROM teachers ORDER BY name ASC
    ''').fetchall()

    # Complaint status pie chart data
    pc = conn.execute('''
        SELECT status, COUNT(*) as c FROM complaints GROUP BY status
    ''').fetchall()

    token_row = conn.execute('''
        SELECT * FROM reset_tokens 
        WHERE user_id = ? AND used = 0 AND expires_at > datetime("now")
        ORDER BY created_at DESC LIMIT 1
    ''', (session['user_id'],)).fetchone()
    
    token = token_row['token'] if token_row else None
    token_expires = token_row['expires_at'] if token_row else None
    conn.close()

    return render_template('principal_dashboard.html', teachers=teachers, pc=pc, reset_token=token, reset_expires=token_expires)


# --- COMPLAINTS ---
@app.route('/complaint/new', methods=['GET','POST'])
@require_login
def complaint_form():
    if session.get('role') != 'student':
        return redirect(url_for('index'))
    
    conn = get_db()
    student = conn.execute('SELECT * FROM students WHERE id = (SELECT ref_id FROM users WHERE id = ?)', (session['user_id'],)).fetchone()
    teachers = conn.execute('SELECT * FROM teachers ORDER BY name').fetchall()
    
    if request.method == 'POST':
        roll_no = request.form.get('roll_no')
        category = request.form.get('category')
        if category == 'other':
            category = request.form.get('other_category', 'Other')
        description = request.form.get('description')
        mentor_id = request.form.get('mentor')
        attachment_file = None
        
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                attachment_file = filename
        
        conn.execute('''
            INSERT INTO complaints (student_id, teacher_id, category, description, attachment, status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
        ''', (student['id'], mentor_id, category, description, attachment_file))
        conn.commit()
        flash('Complaint filed successfully', 'success')
        conn.close()
        return redirect(url_for('student_dashboard'))
    
    conn.close()
    return render_template('complaint_form.html', student=student, teachers=teachers)

@app.route('/complaint/feedback', methods=['POST'])
@require_login
def complaint_feedback():
    if session.get('role') != 'student':
        return redirect(url_for('index'))
    
    complaint_id = request.form.get('complaint_id')
    resolved = request.form.get('resolved')
    comment = request.form.get('comment', '')
    
    conn = get_db()
    existing = conn.execute('SELECT * FROM feedback WHERE complaint_id = ?', (complaint_id,)).fetchone()
    if not existing:
        conn.execute('INSERT INTO feedback (complaint_id, student_feedback) VALUES (?, ?)',
                    (complaint_id, f"Resolved: {resolved}. Comment: {comment}"))
        conn.commit()
    conn.close()
    flash('Feedback submitted', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/complaint/action', methods=['POST'])
@require_login
def complaint_action():
    if session.get('role') not in ['teacher', 'principal']:
        return jsonify({'error': 'Access denied'}), 403
    
    complaint_id = request.form.get('complaint_id')
    action = request.form.get('action')
    reason = request.form.get('reason', '')
    
    conn = get_db()
    if action == 'accept':
        conn.execute('UPDATE complaints SET status = ? WHERE id = ?', ('Accepted', complaint_id))
        conn.execute('UPDATE teachers SET performance_accepted = performance_accepted + 1 WHERE id = (SELECT teacher_id FROM complaints WHERE id = ?)', (complaint_id,))
    elif action == 'reject':
        conn.execute('UPDATE complaints SET status = ?, reason = ? WHERE id = ?', ('Rejected', reason, complaint_id))
        conn.execute('UPDATE teachers SET performance_rejected = performance_rejected + 1 WHERE id = (SELECT teacher_id FROM complaints WHERE id = ?)', (complaint_id,))
    elif action == 'forward':
        conn.execute('UPDATE complaints SET status = ?, reason = ? WHERE id = ?', ('Forwarded to Principal', reason, complaint_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/generate_token', methods=['POST'])
@require_login
def generate_token():
    """Generate a reset token for the currently logged-in user and show it via flash."""
    user_id = session.get('user_id')
    conn = get_db()
    try:
        token, expires = create_reset_token_for_user(conn, user_id, hours=24)
        flash(f'Reset token created: {token} (valid until {expires})', 'info')
    except Exception as e:
        flash(f'Could not create token: {e}', 'danger')
    finally:
        conn.close()

    # Redirect back to the appropriate dashboard
    role = session.get('role')
    if role == 'student':
        return redirect(url_for('student_dashboard'))
    if role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    return redirect(url_for('principal_dashboard'))

# --- ACCOUNT MANAGEMENT ---
@app.route('/approve_account', methods=['POST'])
@require_login
def approve_account():
    if session.get('role') != 'teacher':
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user and user['role'] == 'student':
        student = conn.execute('SELECT id FROM students WHERE id = ?', (user_id,)).fetchone()
        if student:
            # Link student to teacher as mentor
            conn.execute('UPDATE students SET mentor_id = (SELECT ref_id FROM users WHERE id = ?) WHERE id = ?',
                        (session['user_id'], user_id))
        conn.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
        conn.commit()
        flash('Account approved', 'success')
    conn.close()
    return redirect(url_for('teacher_dashboard'))

@app.route('/reject_account', methods=['POST'])
@require_login
def reject_account():
    if session.get('role') != 'teacher':
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        conn.execute('DELETE FROM students WHERE id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('Account rejected and removed', 'success')
    conn.close()
    return redirect(url_for('teacher_dashboard'))

# --- CREATION ROUTES ---
@app.route('/create_teacher', methods=['POST'])
@require_login
def create_teacher():
    if session.get('role') != 'principal':
        return redirect(url_for('index'))
    
    fullname = request.form.get('fullname')
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        flash('Username already exists', 'danger')
        conn.close()
        return redirect(url_for('principal_dashboard'))
    
    hashed = generate_password_hash(password)
    try:
        teacher_count = conn.execute('SELECT COUNT(*) as c FROM teachers').fetchone()['c']
        teacher_code = f"RBVTCH{teacher_count+1:04d}"
        user_id = conn.execute(
            'INSERT INTO users (role, username, password, email, phone, approved) VALUES (?, ?, ?, ?, ?, 1)',
            ('teacher', username, hashed, email, phone)
        ).lastrowid
        teacher_id = conn.execute('INSERT INTO teachers (name, teacher_code) VALUES (?, ?)', (fullname, teacher_code)).lastrowid
        conn.execute('UPDATE users SET ref_id = ? WHERE id = ?', (teacher_id, user_id))
        conn.commit()
        # Generate reset token for new teacher
        token = generate_reset_token(conn, user_id)
        flash(f'✓ Teacher {fullname} created! Reset token: {token}', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('principal_dashboard'))

@app.route('/create_student', methods=['POST'])
@require_login
def create_student():
    if session.get('role') != 'teacher':
        return redirect(url_for('index'))
    
    fullname = request.form.get('fullname')
    username = request.form.get('username')
    password = request.form.get('temp_password')  # FIXED
    roll_no = request.form.get('rollno')          # FIXED
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    conn = get_db()

    # Check existing username
    existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        flash('Username already exists', 'danger')
        conn.close()
        return redirect(url_for('teacher_dashboard'))

    # Get teacher's student table ID
    teacher = conn.execute('SELECT ref_id FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    teacher_id = teacher['ref_id']

    hashed = generate_password_hash(password)

    try:
        code = generate_student_code(conn)

        # Create user login
        user_id = conn.execute(
            '''INSERT INTO users (role, username, password, email, phone, approved)
               VALUES (?, ?, ?, ?, ?, 1)''',
            ('student', username, hashed, email, phone)
        ).lastrowid

        # Create student profile
        student_id = conn.execute(
            'INSERT INTO students (name, unique_code, mentor_id, roll_no) VALUES (?, ?, ?, ?)',
            (fullname, code, teacher_id, roll_no)
        ).lastrowid

        # Link user → student
        conn.execute('UPDATE users SET ref_id = ? WHERE id = ?', (student_id, user_id))
        conn.commit()

        # Create reset token
        token = generate_reset_token(conn, user_id)
        flash(f'✓ Student {fullname} created! Reset token: {token}', 'success')

    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')

    finally:
        conn.close()

    return redirect(url_for('teacher_dashboard'))

@app.route("/delete_student", methods=["POST"])
def delete_student():
    student_id = request.form.get("student_id")
    teacher_id = session.get("teacher_id")

    if not student_id or not teacher_id:
        return redirect("/teacher_dashboard")

    conn = sqlite3.connect("safesphere.db")
    cur = conn.cursor()

    # Ensure a teacher can delete only his/her own student
    cur.execute("DELETE FROM students WHERE id = ? AND mentor_id = ?", (student_id, teacher_id))
    conn.commit()
    conn.close()

    return redirect("/teacher_dashboard")


@app.route('/delete_teacher', methods=['POST'])
@require_login
def delete_teacher():
    if session.get('role') != 'principal':
        return redirect(url_for('index'))
    
    teacher_id = request.form.get('teacher_id')
    conn = get_db()
    
    conn.execute('DELETE FROM complaints WHERE teacher_id = ?', (teacher_id,))
    conn.execute('DELETE FROM teachers WHERE id = ?', (teacher_id,))
    conn.execute('DELETE FROM users WHERE ref_id = ?', (teacher_id,))
    conn.commit()
    conn.close()
    
    flash('Teacher deleted', 'success')
    return redirect(url_for('principal_dashboard'))

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


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Optional, allows dict-like access
    return conn


@app.route('/teacher/complaint/<int:id>/<action>', methods=['POST'])
def teacher_handle_complaint(id, action):
    conn = get_db_connection()
    cur = conn.cursor()
    
    complaint = cur.execute("SELECT * FROM complaints WHERE id=?", (id,)).fetchone()
    if not complaint:
        conn.close()
        return jsonify({'success': False, 'error': 'Complaint not found'})
    
    try:
        if action == 'accept':
            cur.execute("UPDATE complaints SET status='Accepted' WHERE id=?", (id,))
        elif action == 'reject':
            cur.execute("UPDATE complaints SET status='Rejected' WHERE id=?", (id,))
        elif action == 'forward':
            cur.execute("UPDATE complaints SET forwarded=1, status='Forwarded to Principal' WHERE id=?", (id,))
        elif action == 'delete':
            cur.execute("DELETE FROM complaints WHERE id=?", (id,))
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid action'})
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})

# --- HEALTH CHECK ---
@app.route("/health")
def health():
    return "OK", 200

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
