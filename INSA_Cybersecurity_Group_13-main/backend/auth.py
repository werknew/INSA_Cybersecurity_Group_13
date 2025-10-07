from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

# In-memory user storage (replace with database in production)
users_db = {
    'admin': {
        'id': 1,
        'email': 'admin@security.com',
        'password': bcrypt.generate_password_hash('admin123').decode('utf-8'),
        'role': 'admin',
        'created_at': datetime.datetime.now().isoformat(),
        'last_login': None
    },
    'user': {
        'id': 2, 
        'email': 'user@security.com',
        'password': bcrypt.generate_password_hash('user123').decode('utf-8'),
        'role': 'user',
        'created_at': datetime.datetime.now().isoformat(),
        'last_login': None
    }
}

JWT_SECRET = os.getenv('JWT_SECRET', 'your-super-secret-jwt-key')
JWT_ALGORITHM = 'HS256'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user = users_db.get(data['email'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = users_db.get(email)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Update last login
        user['last_login'] = datetime.datetime.now().isoformat()
        
        # Generate JWT token
        token_payload = {
            'email': user['email'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return jsonify({
            'token': token,
            'user': {
                'email': user['email'],
                'role': user['role'],
                'last_login': user['last_login']
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({
        'user': {
            'email': current_user['email'],
            'role': current_user['role'],
            'last_login': current_user['last_login']
        }
    })

@auth_bp.route('/api/auth/users', methods=['POST'])
@token_required
@admin_required
def create_user(current_user):
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'user')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if email in users_db:
            return jsonify({'error': 'User already exists'}), 400
        
        if role not in ['admin', 'user', 'viewer']:
            return jsonify({'error': 'Invalid role'}), 400
        
        users_db[email] = {
            'id': len(users_db) + 1,
            'email': email,
            'password': bcrypt.generate_password_hash(password).decode('utf-8'),
            'role': role,
            'created_at': datetime.datetime.now().isoformat(),
            'last_login': None
        }
        
        return jsonify({'message': 'User created successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500