from flask import Flask, request, jsonify, render_template
import sqlite3
import os
import xml.etree.ElementTree as ET
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, template_folder='templates')
DB_NAME = 'students.db'

# Secret key for JWT - change this to a secure random key in production
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            age INTEGER NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# JWT Token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            conn = get_db_connection()
            current_user = conn.execute(
                'SELECT * FROM users WHERE id = ?',
                (data['user_id'],)
            ).fetchone()
            conn.close()
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/')

def index():
    return render_template('index.html')


@app.route('/auth')

def auth():
    return render_template('auth.html')
# ==================== AUTH ROUTES ====================

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate password length
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db_connection()
        
        # Check if user already exists
        existing_user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if existing_user:
            conn.close()
            return jsonify({'error': 'Username or email already exists'}), 409
        
        # Hash password
        hashed_password = generate_password_hash(password)
        
        # Insert new user
        cursor = conn.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            (username, email, hashed_password)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user_id,
                'username': username,
                'email': email
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'error': 'Missing username or password'}), 400
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check password
        if not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify-token', methods=['GET'])
@token_required
def verify_token(current_user):
    return jsonify({
        'message': 'Token is valid',
        'user': {
            'id': current_user['id'],
            'username': current_user['username'],
            'email': current_user['email']
        }
    }), 200

# ==================== PROTECTED STUDENT ROUTES ====================

@app.route('/add-student', methods=['POST'])
@token_required
def add_student(current_user):
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        age = data.get('age')
        
        if not all([name, email, age]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        conn = get_db_connection()
        cursor = conn.execute(
            'INSERT INTO students (name, email, age) VALUES (?, ?, ?)',
            (name, email, age)
        )
        conn.commit()
        student_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'message': 'Student added successfully',
            'id': student_id
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get-student', methods=['GET'])
@token_required
def get_student(current_user):
    try:
        student_id = request.args.get('id')
        conn = get_db_connection()
        
        if student_id:
            student = conn.execute(
                'SELECT * FROM students WHERE id = ?',
                (student_id,)
            ).fetchone()
            conn.close()
            
            if student:
                return jsonify(dict(student)), 200
            else:
                return jsonify({'error': 'Student not found'}), 404
        else:
            students = conn.execute('SELECT * FROM students').fetchall()
            conn.close()
            
            return jsonify([dict(row) for row in students]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update-student', methods=['PUT'])
@token_required
def update_student(current_user):
    try:
        data = request.get_json()
        student_id = data.get('id')
        name = data.get('name')
        email = data.get('email')
        age = data.get('age')
        
        if not student_id:
            return jsonify({'error': 'Student ID is required'}), 400
        
        conn = get_db_connection()
        
        # Check if student exists
        student = conn.execute(
            'SELECT * FROM students WHERE id = ?',
            (student_id,)
        ).fetchone()
        
        if not student:
            conn.close()
            return jsonify({'error': 'Student not found'}), 404
        
        # Build update query dynamically
        update_fields = []
        values = []
        
        if name:
            update_fields.append('name = ?')
            values.append(name)
        if email:
            update_fields.append('email = ?')
            values.append(email)
        if age:
            update_fields.append('age = ?')
            values.append(age)
        
        if not update_fields:
            conn.close()
            return jsonify({'error': 'No fields to update'}), 400
        
        values.append(student_id)
        query = f"UPDATE students SET {', '.join(update_fields)} WHERE id = ?"
        
        conn.execute(query, values)
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Student updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete-student', methods=['DELETE'])
@token_required
def delete_student(current_user):
    try:
        data = request.get_json()
        student_id = data.get('id')
        
        if not student_id:
            return jsonify({'error': 'Student ID is required'}), 400
        
        conn = get_db_connection()
        
        # Check if student exists
        student = conn.execute(
            'SELECT * FROM students WHERE id = ?',
            (student_id,)
        ).fetchone()
        
        if not student:
            conn.close()
            return jsonify({'error': 'Student not found'}), 404
        
        conn.execute('DELETE FROM students WHERE id = ?', (student_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Student deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/add-xml-student', methods=['POST'])
@token_required
def add_xml_student(current_user):
    try:
        # Get raw XML data
        xml_data = request.data

        if not xml_data:
            return jsonify({'error': 'No XML data provided'}), 400

        # Parse XML
        root = ET.fromstring(xml_data)

        name = root.findtext('name')
        email = root.findtext('email')
        age = root.findtext('age')

        if not all([name, email, age]):
            return jsonify({'error': 'Missing required fields in XML'}), 400

        conn = get_db_connection()
        cursor = conn.execute(
            'INSERT INTO students (name, email, age) VALUES (?, ?, ?)',
            (name, email, int(age))
        )
        conn.commit()
        student_id = cursor.lastrowid
        conn.close()

        return jsonify({
            'message': 'Student added successfully via XML',
            'id': student_id
        }), 201

    except ET.ParseError:
        return jsonify({'error': 'Invalid XML format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    init_db()
    app.run(debug=True)