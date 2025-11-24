import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'safesphere.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

app = Flask(__name__)
app.secret_key = 'replace-with-secure-key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_PATH):
        with app.app_context():
            conn = get_db()
            with open(os.path.join(BASE_DIR, 'schema.sql'), 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
            # ensure reset_tokens table exists for password resets
            conn.execute('''
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    expires_at DATETIME NOT NULL,
                    used INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            conn.commit()
            # Seed principal account
            hashed = generate_password_hash('ChangeMe123!')
            try:
                conn.execute("INSERT INTO users (role, username, password, email) VALUES (?, ?, ?, ?)",
                             ('principal', 'principal', hashed, 'principal@rbvrr.edu'))
                conn.commit()
            except Exception:
                pass
            conn.close()

    # Ensure `approved` column exists on users table for account approval workflow
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 1")
        conn.commit()
    except Exception:
        # column probably already exists
        pass
    finally:
        try:
            # set existing NULL to 1
            conn.execute("UPDATE users SET approved = 1 WHERE approved IS NULL")
            conn.commit()
            conn.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def generate_student_code(conn):
    cur = conn.execute('SELECT COUNT(*) as c FROM students')
    count = cur.fetchone()['c'] or 0
    return f"RBVSTU{count+1:04d}"

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/signup', methods=['GET','POST'])
def signup():
    role = session.get('role')
    if request.method == 'GET':
        return render_template('signup.html', role=role)
    create_for = request.form.get('create_for')
    name = request.form.get('fullname')
    email = request.form.get('email')
    phone = request.form.get('phone')
    dob = request.form.get('dob')
    username = request.form.get('username')
    password = request.form.get('password')
    conn = get_db()
    cur = conn.cursor()
    exists = cur.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if exists:
        flash('Username already exists', 'danger')
        return redirect(url_for('signup'))
    if create_for == 'student':
        # teacher-driven creation (instant)
        if session.get('role') == 'teacher':
            c = cur.execute('SELECT COUNT(*) as c FROM students').fetchone()['c']
            if c >= 80:
                flash('Student limit reached (80)', 'danger')
                return redirect(url_for('signup'))
            unique_code = generate_student_code(conn)
            mentor_id = session.get('ref_teacher_id') or request.form.get('mentor_id')
            cur.execute('INSERT INTO students (name, unique_code, mentor_id, roll_no) VALUES (?,?,?,?)',
                        (name, unique_code, mentor_id, request.form.get('roll_no')))
            student_id = cur.lastrowid
            hashed = generate_password_hash(password)
            cur.execute('INSERT INTO users (role, username, password, email, phone, dob, ref_id, approved) VALUES (?,?,?,?,?,?,?,?)',
                        ('student', username, hashed, email, phone, dob, student_id, 1))
            conn.commit()
            flash(f'Student created with code {unique_code}', 'success')
            conn.close()
            return redirect(url_for('signup'))
        # public self-signup -> create an application (student record + user, approved=0)
        if not session.get('role'):
            c = cur.execute('SELECT COUNT(*) as c FROM students').fetchone()['c']
            if c >= 80:
                flash('Student limit reached (80)', 'danger')
                return redirect(url_for('signup'))
            unique_code = generate_student_code(conn)
            # create a student record without mentor
            cur.execute('INSERT INTO students (name, unique_code, mentor_id, roll_no) VALUES (?,?,?,?)',
                        (name, unique_code, None, request.form.get('roll_no')))
            student_id = cur.lastrowid
            hashed = generate_password_hash(password)
            # create user but mark as not approved
            cur.execute('INSERT INTO users (role, username, password, email, phone, dob, ref_id, approved) VALUES (?,?,?,?,?,?,?,?)',
                        ('student', username, hashed, email, phone, dob, student_id, 0))
            conn.commit()
            conn.close()
            flash('Signup submitted. Your account will be reviewed by a teacher or principal.', 'info')
            return redirect(url_for('index'))
        # other roles not allowed
        flash('Only teachers can create student accounts', 'danger')
        conn.close()
        return redirect(url_for('signup'))
    elif create_for == 'teacher':
        if session.get('role') != 'principal':
            flash('Only principal can create teacher accounts', 'danger')
            return redirect(url_for('signup'))
        teacher_code = f"RBVTEA{int(datetime.utcnow().timestamp())%100000}"
        cur.execute('INSERT INTO teachers (name, teacher_code) VALUES (?,?)', (name, teacher_code))
        teacher_id = cur.lastrowid
        hashed = generate_password_hash(password)
        cur.execute('INSERT INTO users (role, username, password, email, phone, dob, ref_id) VALUES (?,?,?,?,?,?,?)',
                    ('teacher', username, hashed, email, phone, dob, teacher_id))
        conn.commit()
        flash('Teacher created successfully', 'success')
        conn.close()
        return redirect(url_for('signup'))
    else:
        flash('Invalid creation type', 'danger')
        conn.close()
        return redirect(url_for('signup'))

@app.route('/forgot')
def forgot():
    if request.method == 'GET':
        return render_template('forgot.html')

    # POST: process reset request
    identifier = request.form.get('identifier', '').strip()
    if not identifier:
        flash('Please provide username or email', 'danger')
        return render_template('forgot.html')

    conn = get_db()
    cur = conn.cursor()
    user = cur.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier)).fetchone()
    if not user:
        # Don't reveal existence — show generic message
        flash('If an account exists for that identifier, a reset link has been sent.', 'info')
        conn.close()
        return render_template('forgot.html')

    # generate token
    token = secrets.token_urlsafe(24)
    expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    cur.execute('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?,?,?)', (user['id'], token, expires_at))
    conn.commit()
    conn.close()

    reset_url = url_for('reset_password', token=token, _external=True)
    # For development, show link in flash and write to a file. In production, send email.
    try:
        with open(os.path.join(BASE_DIR, 'last_reset_link.txt'), 'a', encoding='utf-8') as f:
            f.write(f"{datetime.utcnow().isoformat()} {user['username']} {reset_url}\n")
    except Exception:
        pass

    flash('If an account exists for that identifier, a reset link has been sent. (Check last_reset_link.txt in project folder during development)', 'info')
    flash(f'DEVELOPMENT RESET LINK: {reset_url}', 'warning')
    return render_template('forgot.html')

@app.route('/student_dashboard')
def student_dashboard():
    if session.get('role') != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    student = conn.execute('SELECT * FROM students WHERE id = ?', (user['ref_id'],)).fetchone()
    total = conn.execute('SELECT COUNT(*) as c FROM complaints WHERE student_id = ?', (student['id'],)).fetchone()['c']
    accepted = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE student_id = ? AND status='Accepted'", (student['id'],)).fetchone()['c']
    rejected = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE student_id = ? AND status='Rejected'", (student['id'],)).fetchone()['c']

    # fetch student's complaints and any feedback given
    complaints = conn.execute('SELECT c.*, t.name as teacher_name FROM complaints c LEFT JOIN teachers t ON c.teacher_id = t.id WHERE c.student_id = ? ORDER BY c.created_at DESC', (student['id'],)).fetchall()
    complaint_ids = [str(c['id']) for c in complaints]
    feedback_map = {}
    if complaint_ids:
        placeholders = ','.join(['?']*len(complaint_ids))
        rows = conn.execute(f'SELECT * FROM feedback WHERE complaint_id IN ({placeholders})', tuple(complaint_ids)).fetchall()
        for r in rows:
            feedback_map[r['complaint_id']] = r

    conn.close()
    return render_template('student_dashboard.html', student=student, user=user, total=total, accepted=accepted, rejected=rejected, complaints=complaints, feedback_map=feedback_map)

@app.route('/teacher_dashboard')
def teacher_dashboard():
    if session.get('role') != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    teacher = conn.execute('SELECT * FROM teachers WHERE id = ?', (user['ref_id'],)).fetchone()
    accepted = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ? AND status='Accepted'", (teacher['id'],)).fetchone()['c']
    rejected = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ? AND status='Rejected'", (teacher['id'],)).fetchone()['c']
    complaints = conn.execute('SELECT c.*, s.name as student_name FROM complaints c JOIN students s ON c.student_id = s.id WHERE c.teacher_id = ? ORDER BY c.created_at DESC', (teacher['id'],)).fetchall()
    # pending account applications (students who signed up themselves and are not approved yet)
    applicants = conn.execute("SELECT u.id as user_id, u.username, u.email, s.id as student_id, s.name, s.unique_code FROM users u JOIN students s ON u.ref_id = s.id WHERE u.role='student' AND (u.approved IS NULL OR u.approved = 0)").fetchall()

    # students mentored by this teacher
    my_students = conn.execute('SELECT * FROM students WHERE mentor_id = ? ORDER BY created_at DESC', (teacher['id'],)).fetchall()

    conn.close()
    return render_template('teacher_dashboard.html', teacher=teacher, user=user, accepted=accepted, rejected=rejected, complaints=complaints, applicants=applicants, my_students=my_students)

@app.route('/principal_dashboard')
def principal_dashboard():
    if session.get('role') != 'principal':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    pc = conn.execute("SELECT status, COUNT(*) as c FROM complaints GROUP BY status").fetchall()
    teachers = conn.execute('SELECT * FROM teachers').fetchall()
    complaints = conn.execute('SELECT * FROM complaints ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('principal_dashboard.html', pc=pc, teachers=teachers, complaints=complaints)

@app.route('/complaint/new', methods=['GET','POST'])
def complaint_form():
    if session.get('role') != 'student':
        flash('Only students can file complaints', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    student = conn.execute('SELECT * FROM students WHERE id = ?', (user['ref_id'],)).fetchone()
    teachers = conn.execute('SELECT * FROM teachers').fetchall()
    if request.method == 'GET':
        conn.close()
        return render_template('complaint_form.html', student=student, teachers=teachers)
    category = request.form.get('category')
    description = request.form.get('description')
    teacher_id = request.form.get('mentor')
    attachment = None
    file = request.files.get('attachment')
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        attachment = filename
    cur = conn.cursor()
    cur.execute('INSERT INTO complaints (student_id, teacher_id, category, description, attachment) VALUES (?,?,?,?,?)',
                (student['id'], teacher_id, category, description, attachment))
    conn.commit()
    conn.close()
    flash('Complaint filed successfully', 'success')
    return redirect(url_for('student_dashboard'))


@app.route('/complaint/feedback', methods=['POST'])
def complaint_feedback():
    # Only students may submit feedback on their complaints
    if session.get('role') != 'student':
        flash('Only students can submit feedback', 'danger')
        return redirect(url_for('index'))

    complaint_id = request.form.get('complaint_id')
    resolved = request.form.get('resolved')  # expected 'yes' or 'no'
    comment = request.form.get('comment', '').strip()

    if not complaint_id or resolved not in ('yes', 'no'):
        flash('Invalid feedback submission', 'danger')
        return redirect(url_for('student_dashboard'))

    conn = get_db()
    cur = conn.cursor()
    # Note: users.ref_id holds student id, so fetch student's id
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    student_id = user['ref_id'] if user else None
    c = conn.execute('SELECT * FROM complaints WHERE id = ? AND student_id = ?', (complaint_id, student_id)).fetchone()
    if not c:
        conn.close()
        flash('Complaint not found or access denied', 'danger')
        return redirect(url_for('student_dashboard'))

    # Store feedback
    fb_text = f"Resolved:{resolved.upper()}"
    if comment:
        fb_text += f" | {comment}"

    cur.execute('INSERT INTO feedback (complaint_id, student_feedback) VALUES (?,?)', (complaint_id, fb_text))

    # If resolved=yes, mark complaint closed
    if resolved == 'yes':
        cur.execute("UPDATE complaints SET status='Closed' WHERE id = ?", (complaint_id,))

    conn.commit()
    conn.close()
    flash('Thank you for the feedback', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/complaint/action', methods=['POST'])
def complaint_action():
    if session.get('role') != 'teacher':
        return jsonify({'error':'unauthorized'}), 403
    action = request.form.get('action')
    complaint_id = request.form.get('complaint_id')
    reason = request.form.get('reason')
    conn = get_db()
    c = conn.execute('SELECT * FROM complaints WHERE id = ?', (complaint_id,)).fetchone()
    if not c:
        conn.close()
        return jsonify({'error':'not found'}), 404
    cur = conn.cursor()
    if action == 'accept':
        cur.execute("UPDATE complaints SET status='Accepted' WHERE id = ?", (complaint_id,))
        cur.execute('UPDATE teachers SET performance_accepted = performance_accepted + 1 WHERE id = ?', (c['teacher_id'],))
    elif action == 'reject':
        cur.execute("UPDATE complaints SET status='Rejected', reason=? WHERE id = ?", (reason, complaint_id))
        cur.execute('UPDATE teachers SET performance_rejected = performance_rejected + 1 WHERE id = ?', (c['teacher_id'],))
    elif action == 'forward':
        cur.execute("UPDATE complaints SET status='Forwarded', reason=? WHERE id = ?", (reason, complaint_id))
    conn.commit()
    conn.close()
    return jsonify({'ok':True})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/charts/teacher/<int:teacher_id>')
def api_teacher_charts(teacher_id):
    conn = get_db()
    accepted = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ? AND status='Accepted'", (teacher_id,)).fetchone()['c']
    rejected = conn.execute("SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ? AND status='Rejected'", (teacher_id,)).fetchone()['c']
    conn.close()
    return jsonify({'accepted': accepted, 'rejected': rejected})


@app.route('/create_teacher', methods=['POST'])
def create_teacher():
    # Only principal may create teacher accounts
    if session.get('role') != 'principal':
        flash('Only principal can create teacher accounts', 'danger')
        return redirect(url_for('principal_dashboard'))

    name = request.form.get('fullname', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    email = request.form.get('email', '').strip() or None
    phone = request.form.get('phone', '').strip() or None

    if not name or not username or not password:
        flash('Full name, username and password are required', 'danger')
        return redirect(url_for('principal_dashboard'))

    conn = get_db()
    cur = conn.cursor()
    exists = cur.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if exists:
        conn.close()
        flash('Username already exists', 'danger')
        return redirect(url_for('principal_dashboard'))

    # create teacher record
    teacher_code = f"RBVTEA{int(datetime.utcnow().timestamp())%100000}"
    cur.execute('INSERT INTO teachers (name, teacher_code) VALUES (?,?)', (name, teacher_code))
    teacher_id = cur.lastrowid

    hashed = generate_password_hash(password)
    cur.execute('INSERT INTO users (role, username, password, email, phone, ref_id) VALUES (?,?,?,?,?,?)',
                ('teacher', username, hashed, email, phone, teacher_id))
    conn.commit()
    conn.close()

    flash('Teacher account created successfully. Teacher can change password after login.', 'success')
    return redirect(url_for('principal_dashboard'))


@app.route('/delete_teacher', methods=['POST'])
def delete_teacher():
    # Only principal may delete teacher accounts
    if session.get('role') != 'principal':
        flash('Only principal can delete teacher accounts', 'danger')
        return redirect(url_for('principal_dashboard'))

    teacher_id = request.form.get('teacher_id')
    if not teacher_id:
        flash('No teacher specified', 'danger')
        return redirect(url_for('principal_dashboard'))

    conn = get_db()
    cur = conn.cursor()
    t = cur.execute('SELECT * FROM teachers WHERE id = ?', (teacher_id,)).fetchone()
    if not t:
        conn.close()
        flash('Teacher not found', 'danger')
        return redirect(url_for('principal_dashboard'))

    # prevent deletion if teacher has complaints
    ccount = cur.execute('SELECT COUNT(*) as c FROM complaints WHERE teacher_id = ?', (teacher_id,)).fetchone()['c']
    if ccount > 0:
        conn.close()
        flash(f'Cannot delete teacher; {ccount} complaint(s) assigned. Reassign or resolve them first.', 'danger')
        return redirect(url_for('principal_dashboard'))

    # delete user row(s) referencing this teacher (role=teacher and ref_id)
    cur.execute('DELETE FROM users WHERE role = ? AND ref_id = ?', ('teacher', teacher_id))
    cur.execute('DELETE FROM teachers WHERE id = ?', (teacher_id,))
    conn.commit()
    conn.close()

    flash('Teacher deleted successfully', 'success')
    return redirect(url_for('principal_dashboard'))


@app.route('/create_student', methods=['POST'])
def create_student():
    # Only teachers may create student accounts
    if session.get('role') != 'teacher':
        flash('Only teachers can create student accounts', 'danger')
        return redirect(url_for('teacher_dashboard'))

    name = request.form.get('fullname', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    roll_no = request.form.get('roll_no', '').strip() or None
    email = request.form.get('email', '').strip() or None
    phone = request.form.get('phone', '').strip() or None

    if not name or not username or not password:
        flash('Full name, username and password are required', 'danger')
        return redirect(url_for('teacher_dashboard'))

    conn = get_db()
    cur = conn.cursor()
    exists = cur.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if exists:
        conn.close()
        flash('Username already exists', 'danger')
        return redirect(url_for('teacher_dashboard'))

    # enforce 80 student limit
    c = cur.execute('SELECT COUNT(*) as c FROM students').fetchone()['c']
    if c >= 80:
        conn.close()
        flash('Student limit reached (80)', 'danger')
        return redirect(url_for('teacher_dashboard'))

    # determine mentor (current teacher)
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    mentor_id = user['ref_id'] if user else None

    unique_code = generate_student_code(conn)
    cur.execute('INSERT INTO students (name, unique_code, mentor_id, roll_no) VALUES (?,?,?,?)',
                (name, unique_code, mentor_id, roll_no))
    student_id = cur.lastrowid

    hashed = generate_password_hash(password)
    cur.execute('INSERT INTO users (role, username, password, email, phone, dob, ref_id) VALUES (?,?,?,?,?,?,?)',
                ('student', username, hashed, email, phone, None, student_id))
    conn.commit()
    conn.close()

    flash(f'Student created with code {unique_code}', 'success')
    return redirect(url_for('teacher_dashboard'))


@app.route('/approve_account', methods=['POST'])
def approve_account():
    if session.get('role') not in ('teacher','principal'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('index'))
    user_id = request.form.get('user_id')
    if not user_id:
        flash('No application specified', 'danger')
        return redirect(url_for('teacher_dashboard'))
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute('SELECT * FROM users WHERE id = ? AND role = ?', (user_id, 'student')).fetchone()
    if not user:
        conn.close()
        flash('Application not found', 'danger')
        return redirect(url_for('teacher_dashboard'))

    # set approved and assign mentor if teacher approves
    cur.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
    # set mentor on students table if approver is a teacher
    approver_role = session.get('role')
    if approver_role == 'teacher':
        approver = cur.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        teacher = cur.execute('SELECT * FROM teachers WHERE id = ?', (approver['ref_id'],)).fetchone()
        if teacher:
            cur.execute('UPDATE students SET mentor_id = ? WHERE id = ?', (teacher['id'], user['ref_id']))

    conn.commit()
    conn.close()
    flash('Application approved', 'success')
    return redirect(url_for('teacher_dashboard'))


@app.route('/reject_account', methods=['POST'])
def reject_account():
    if session.get('role') not in ('teacher','principal'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('index'))
    user_id = request.form.get('user_id')
    if not user_id:
        flash('No application specified', 'danger')
        return redirect(url_for('teacher_dashboard'))
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute('SELECT * FROM users WHERE id = ? AND role = ?', (user_id, 'student')).fetchone()
    if not user:
        conn.close()
        flash('Application not found', 'danger')
        return redirect(url_for('teacher_dashboard'))
    # delete associated student record if exists
    student_id = user['ref_id']
    if student_id:
        cur.execute('DELETE FROM students WHERE id = ?', (student_id,))
    cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('Application rejected and removed', 'info')
    return redirect(url_for('teacher_dashboard'))


@app.route('/delete_student', methods=['POST'])
def delete_student():
    if session.get('role') != 'teacher':
        flash('Unauthorized', 'danger')
        return redirect(url_for('index'))
    student_id = request.form.get('student_id')
    if not student_id:
        flash('No student specified', 'danger')
        return redirect(url_for('teacher_dashboard'))
    conn = get_db()
    cur = conn.cursor()
    # verify student belongs to this teacher
    approver = cur.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    teacher = cur.execute('SELECT * FROM teachers WHERE id = ?', (approver['ref_id'],)).fetchone()
    s = cur.execute('SELECT * FROM students WHERE id = ? AND mentor_id = ?', (student_id, teacher['id'] if teacher else None)).fetchone()
    if not s:
        conn.close()
        flash('Student not found or not under your mentorship', 'danger')
        return redirect(url_for('teacher_dashboard'))
    # prevent deletion if complaints exist
    ccount = cur.execute('SELECT COUNT(*) as c FROM complaints WHERE student_id = ?', (student_id,)).fetchone()['c']
    if ccount > 0:
        conn.close()
        flash(f'Cannot delete student; {ccount} complaint(s) exist. Resolve or reassign them first.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    # delete user and student
    cur.execute('DELETE FROM users WHERE ref_id = ? AND role = ?', (student_id, 'student'))
    cur.execute('DELETE FROM students WHERE id = ?', (student_id,))
    conn.commit()
    conn.close()
    flash('Student deleted successfully', 'success')
    return redirect(url_for('teacher_dashboard'))


@app.route('/change_password', methods=['GET','POST'])
def change_password():
    # Allow principal and teachers (and students) to change their own password
    if 'username' not in session or session.get('role') not in ('principal', 'teacher', 'student'):
        return redirect(url_for('login'))

    username = session.get('username')

    if request.method == 'POST':
        current = request.form.get('current_password','').strip()
        new = request.form.get('new_password','').strip()
        confirm = request.form.get('confirm_password','').strip()

        if not current or not new or not confirm:
            flash('All fields are required.', 'danger')
            return render_template('change_password.html')

        if new != confirm:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('change_password.html')

        if len(new) < 8:
            flash('New password must be at least 8 characters.', 'danger')
            return render_template('change_password.html')

        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT password FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        if row is None:
            conn.close()
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

        stored_hash = row['password'] if isinstance(row, dict) and 'password' in row else row[0]
        if not check_password_hash(stored_hash, current):
            conn.close()
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        new_hash = generate_password_hash(new)
        cur.execute('UPDATE users SET password = ? WHERE username = ?', (new_hash, username))
        conn.commit()
        conn.close()

        flash('Password changed successfully.', 'success')
        # Redirect based on role
        role = session.get('role')
        if role == 'principal':
            return redirect(url_for('principal_dashboard'))
        elif role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))

    return render_template('change_password.html')


@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    conn = get_db()
    cur = conn.cursor()
    row = cur.execute('SELECT * FROM reset_tokens WHERE token = ? AND used = 0', (token,)).fetchone()
    if not row:
        conn.close()
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('index'))

    # check expiry
    try:
        expires = datetime.fromisoformat(row['expires_at'])
    except Exception:
        expires = None
    if not expires or datetime.utcnow() > expires:
        # mark used/expired
        cur.execute('UPDATE reset_tokens SET used = 1 WHERE id = ?', (row['id'],))
        conn.commit()
        conn.close()
        flash('Reset link has expired', 'danger')
        return redirect(url_for('forgot'))

    if request.method == 'GET':
        conn.close()
        return render_template('reset_password.html')

    # POST: set new password
    new = request.form.get('new_password','').strip()
    confirm = request.form.get('confirm_password','').strip()
    if not new or not confirm or new != confirm or len(new) < 8:
        flash('Passwords must match and be at least 8 characters', 'danger')
        conn.close()
        return render_template('reset_password.html')

    hashed = generate_password_hash(new)
    cur.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, row['user_id']))
    cur.execute('UPDATE reset_tokens SET used = 1 WHERE id = ?', (row['id'],))
    conn.commit()
    conn.close()

    flash('Password reset successful. You can now log in.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
