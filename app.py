from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import sqlite3
from datetime import datetime
import csv
from io import StringIO
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import os
import shutil
from functools import wraps
from fpdf import FPDF
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
socketio = SocketIO(app)

@contextmanager
def get_db_connection():
    conn = sqlite3.connect('attendance.db', timeout=10)
    try:
        yield conn
    finally:
        conn.close()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_role' not in session or session['user_role'] != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
    if user and check_password_hash(user[4], password):
        session['user_id'] = user[0]
        session['user_role'] = user[5]
        session['user_name'] = user[2]
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid credentials', 'danger')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        total_employees = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT rfid) FROM attendance WHERE date(timestamp) = date('now')")
        present_today = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM leave_requests WHERE status = 'Pending'")
        pending_leaves = cursor.fetchone()[0]

        cursor.execute('''
            SELECT users.department, COUNT(attendance.id) AS attendance_count
            FROM attendance
            JOIN users ON attendance.rfid = users.rfid
            GROUP BY users.department
        ''')
        department_wise_attendance = cursor.fetchall()

    return render_template('dashboard.html', total_employees=total_employees, present_today=present_today,
                           pending_leaves=pending_leaves, department_wise_attendance=department_wise_attendance)

@app.route('/attendance', methods=['POST'])
def attendance():
    rfid = request.form['rfid']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO attendance (rfid, timestamp) VALUES (?, ?)", (rfid, timestamp))
        conn.commit()
        cursor.execute("SELECT name FROM users WHERE rfid = ?", (rfid,))
        user = cursor.fetchone()
    if user:
        flash(f'Attendance recorded for {user[0]} at {timestamp}', 'success')
    else:
        flash('RFID not recognized!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/show_attendance')
def show_attendance():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attendance")
        records = cursor.fetchall()
    return render_template('attendance.html', records=records)

@app.route('/manage_users')
@admin_required
def manage_users():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        rfid = request.form['rfid']
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        department = request.form['department']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (rfid, name, email, password, role, department) VALUES (?, ?, ?, ?, ?, ?)", 
                            (rfid, name, email, password, role, department))
            cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                            (session['user_id'], f"Added user {name}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('manage_users'))
    return render_template('add_user.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            rfid = request.form['rfid']
            name = request.form['name']
            email = request.form['email']
            role = request.form['role']
            department = request.form['department']
            contact_details = request.form['contact_details']
            job_title = request.form['job_title']
            profile_picture = request.form['profile_picture']  # Handle file upload
            cursor.execute("UPDATE users SET rfid = ?, name = ?, email = ?, role = ?, department = ?, contact_details = ?, job_title = ?, profile_picture = ? WHERE id = ?", 
                            (rfid, name, email, role, department, contact_details, job_title, profile_picture, id))
            cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                            (session['user_id'], f"Edited user {name}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('manage_users'))
        cursor.execute("SELECT * FROM users WHERE id = ?", (id,))
        user = cursor.fetchone()
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>')
@admin_required
def delete_user(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM users WHERE id = ?", (id,))
        user = cursor.fetchone()
        cursor.execute("DELETE FROM users WHERE id = ?", (id,))
        cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                        (session['user_id'], f"Deleted user {user[0]}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/leave_requests')
def leave_requests():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if session['user_role'] == 'admin':
            cursor.execute("SELECT leave_requests.id, users.name, leave_requests.start_date, leave_requests.end_date, leave_requests.reason, leave_requests.status FROM leave_requests JOIN users ON leave_requests.user_id = users.id")
        else:
            cursor.execute("SELECT * FROM leave_requests WHERE user_id = ?", (session['user_id'],))
        requests = cursor.fetchall()
    return render_template('leave_requests.html', requests=requests)

@app.route('/add_leave', methods=['GET', 'POST'])
def add_leave():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        reason = request.form['reason']
        user_id = session['user_id']
        status = 'Pending'
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO leave_requests (user_id, start_date, end_date, reason, status) VALUES (?, ?, ?, ?, ?)", 
                            (user_id, start_date, end_date, reason, status))
            cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                            (session['user_id'], "Added leave request", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        flash('Leave request submitted successfully!', 'success')
        return redirect(url_for('leave_requests'))
    return render_template('add_leave.html')

@app.route('/approve_leave/<int:id>')
@admin_required
def approve_leave(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE leave_requests SET status = 'Approved' WHERE id = ?", (id,))
        cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                        (session['user_id'], f"Approved leave request {id}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    flash('Leave request approved!', 'success')
    return redirect(url_for('leave_requests'))

@app.route('/reject_leave/<int:id>')
@admin_required
def reject_leave(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE leave_requests SET status = 'Rejected' WHERE id = ?", (id,))
        cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                        (session['user_id'], f"Rejected leave request {id}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    flash('Leave request rejected!', 'success')
    return redirect(url_for('leave_requests'))

@app.route('/attendance_report')
@admin_required
def attendance_report():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT users.name, COUNT(attendance.id) FROM attendance JOIN users ON attendance.rfid = users.rfid GROUP BY users.name")
        report = cursor.fetchall()
    return render_template('attendance_report.html', report=report)

@app.route('/attendance_chart')
@admin_required
def attendance_chart():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT strftime('%Y-%m-%d', timestamp) as date, COUNT(*) FROM attendance GROUP BY date")
        data = cursor.fetchall()
    return render_template('attendance_chart.html', data=data)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            department = request.form['department']
            contact_details = request.form['contact_details']
            job_title = request.form['job_title']
            profile_picture = request.form['profile_picture']  # Handle file upload
            cursor.execute("UPDATE users SET name = ?, email = ?, department = ?, contact_details = ?, job_title = ?, profile_picture = ? WHERE id = ?", 
                            (name, email, department, contact_details, job_title, profile_picture, session['user_id']))
            cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                            (session['user_id'], "Updated profile", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = generate_password_hash(request.form['new_password'])
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
            current_password = cursor.fetchone()[0]
            if check_password_hash(current_password, old_password):
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, session['user_id']))
                cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                                (session['user_id'], "Changed password", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                conn.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Old password is incorrect!', 'danger')
    return render_template('change_password.html')

@app.route('/search_attendance', methods=['GET', 'POST'])
def search_attendance():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    records = []
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM attendance WHERE timestamp BETWEEN ? AND ?", (start_date, end_date))
            records = cursor.fetchall()
    return render_template('search_attendance.html', records=records)

@app.route('/export_attendance')
@admin_required
def export_attendance():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attendance")
        records = cursor.fetchall()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'RFID', 'Timestamp'])
    cw.writerows(records)
    output = si.getvalue()
    return send_file(StringIO(output), attachment_filename='attendance.csv', as_attachment=True)

@app.route('/export_leave_requests')
@admin_required
def export_leave_requests():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM leave_requests")
        records = cursor.fetchall()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'User ID', 'Start Date', 'End Date', 'Reason', 'Status'])
    cw.writerows(records)
    output = si.getvalue()
    return send_file(StringIO(output), attachment_filename='leave_requests.csv', as_attachment=True)

@app.route('/custom_reports', methods=['GET', 'POST'])
@admin_required
def custom_reports():
    records = []
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        department = request.form['department']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM attendance JOIN users ON attendance.rfid = users.rfid WHERE timestamp BETWEEN ? AND ? AND department = ?", 
                            (start_date, end_date, department))
            records = cursor.fetchall()
    return render_template('custom_reports.html', records=records)

@app.route('/attendance_summary')
@admin_required
def attendance_summary():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT users.name, users.department, COUNT(attendance.id) AS attendance_count, 
            MIN(attendance.timestamp) AS first_checkin, MAX(attendance.timestamp) AS last_checkout
            FROM attendance 
            JOIN users ON attendance.rfid = users.rfid 
            GROUP BY users.name, users.department
        ''')
        summary = cursor.fetchall()
    return render_template('attendance_summary.html', summary=summary)

@app.route('/onboard', methods=['GET', 'POST'])
@admin_required
def onboard():
    if request.method == 'POST':
        rfid = request.form['rfid']
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        department = request.form['department']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (rfid, name, email, password, role, department) VALUES (?, ?, ?, ?, ?, ?)", 
                            (rfid, name, email, password, role, department))
            cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                            (session['user_id'], f"Onboarded user {name}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        flash('Employee onboarded successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('onboard.html')

@app.route('/offboard/<int:id>')
@admin_required
def offboard(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM users WHERE id = ?", (id,))
        user = cursor.fetchone()
        cursor.execute("DELETE FROM users WHERE id = ?", (id,))
        cursor.execute("INSERT INTO audit_trail (user_id, action, timestamp) VALUES (?, ?, ?)", 
                        (session['user_id'], f"Offboarded user {user[0]}", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    flash('Employee offboarded successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/backup')
@admin_required
def backup():
    backup_dir = 'backup'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    shutil.copy('attendance.db', os.path.join(backup_dir, 'attendance_backup.db'))
    flash('Backup created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/restore')
@admin_required
def restore():
    backup_dir = 'backup'
    backup_file = os.path.join(backup_dir, 'attendance_backup.db')
    if os.path.exists(backup_file):
        shutil.copy(backup_file, 'attendance.db')
        flash('Backup restored successfully!', 'success')
    else:
        flash('No backup file found!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/export_to_pdf')
@admin_required
def export_to_pdf():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attendance")
        records = cursor.fetchall()

    pdf_file = 'attendance_report.pdf'
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Attendance Report', 0, 1, 'C')
    pdf.ln(10)

    pdf.set_font('Arial', 'B', 12)
    pdf.cell(40, 10, 'ID', 1)
    pdf.cell(60, 10, 'RFID', 1)
    pdf.cell(90, 10, 'Timestamp', 1)
    pdf.ln()

    pdf.set_font('Arial', '', 12)
    for record in records:
        pdf.cell(40, 10, str(record[0]), 1)
        pdf.cell(60, 10, record[1], 1)
        pdf.cell(90, 10, record[2], 1)
        pdf.ln()

    pdf.output(pdf_file)
    return send_file(pdf_file, as_attachment=True)

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/audit_trail')
@admin_required
def audit_trail():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT audit_trail.id, users.name, audit_trail.action, audit_trail.timestamp FROM audit_trail JOIN users ON audit_trail.user_id = users.id")
        logs = cursor.fetchall()
    return render_template('audit_trail.html', logs=logs)

@socketio.on('connect')
def handle_connect():
    emit('message', {'data': 'Connected'})

@socketio.on('request_live_data')
def handle_request_live_data():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attendance ORDER BY timestamp DESC LIMIT 10")
        records = cursor.fetchall()
    emit('live_data', {'records': records})

if __name__ == '__main__':
    socketio.run(app, debug=True)