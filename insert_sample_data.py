import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

def get_db_connection():
    conn = sqlite3.connect('attendance.db', timeout=10)
    return conn

def insert_sample_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert sample users
    users = [
        ('rfid1', 'John Doe', 'john@example.com', generate_password_hash('password123'), 'admin', 'HR', None, '123-456-7890', 'HR Manager'),
        ('rfid2', 'Jane Smith', 'jane@example.com', generate_password_hash('password123'), 'user', 'Engineering', None, '098-765-4321', 'Software Engineer'),
        ('rfid3', 'Alice Johnson', 'alice@example.com', generate_password_hash('password123'), 'user', 'Sales', None, '555-555-5555', 'Sales Representative'),
        ('rfid4', 'Bob Brown', 'bob@example.com', generate_password_hash('password123'), 'user', 'Marketing', None, '666-666-6666', 'Marketing Specialist')
    ]
    cursor.executemany("INSERT INTO users (rfid, name, email, password, role, department, profile_picture, contact_details, job_title) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", users)

    # Insert sample attendance records
    now = datetime.now()
    attendance_records = [
        ('rfid1', now.strftime('%Y-%m-%d %H:%M:%S')),
        ('rfid2', (now - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')),
        ('rfid3', (now - timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S')),
        ('rfid4', (now - timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S'))
    ]
    cursor.executemany("INSERT INTO attendance (rfid, timestamp) VALUES (?, ?)", attendance_records)

    # Insert sample leave requests
    leave_requests = [
        (1, (now - timedelta(days=5)).strftime('%Y-%m-%d'), (now - timedelta(days=4)).strftime('%Y-%m-%d'), 'Sick leave', 'Approved'),
        (2, (now - timedelta(days=10)).strftime('%Y-%m-%d'), (now - timedelta(days=9)).strftime('%Y-%m-%d'), 'Vacation', 'Pending'),
        (3, (now - timedelta(days=15)).strftime('%Y-%m-%d'), (now - timedelta(days=14)).strftime('%Y-%m-%d'), 'Personal', 'Rejected')
    ]
    cursor.executemany("INSERT INTO leave_requests (user_id, start_date, end_date, reason, status) VALUES (?, ?, ?, ?, ?)", leave_requests)

    conn.commit()
    conn.close()

if __name__ == '__main__':
    insert_sample_data()