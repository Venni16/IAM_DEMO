from flask import Flask, request, jsonify, session, redirect, url_for, render_template, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import datetime
import os
import ipaddress
from sqlalchemy.sql import func
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key ='your-secret-key-here'  # In production, use a fixed secret key

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iam.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Define database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def is_locked(self):
        if self.locked_until is None:
            return False
        return self.locked_until > datetime.now()
    
    def get_lockout_remaining(self):
        if not self.is_locked():
            return 0
        
        delta = self.locked_until - datetime.now()
        return int(delta.total_seconds())
    
    def increment_failed_attempts(self, max_attempts=5, lockout_minutes=15):
        self.failed_login_attempts += 1
        
        # Lock account if max attempts reached
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.now() + timedelta(minutes=lockout_minutes)
            log_security_event(f"Account locked for user: {self.username} due to too many failed attempts", "warning")
        
        db.session.commit()
    
    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=func.now())
    success = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<LoginAttempt {self.username} from {self.ip_address}>'

class IPBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True)
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    expires_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<IPBlacklist {self.ip_address}>'
    
    def is_expired(self):
        if self.expires_at is None:
            return False
        return self.expires_at < datetime.now()
    
    def get_expiry_remaining(self):
        if self.is_expired():
            return 0
        if self.expires_at is None:
            return -1  # Permanent blacklist
        
        delta = self.expires_at - datetime.now()
        return int(delta.total_seconds())
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_expired': self.is_expired(),
            'expiry_remaining': self.get_expiry_remaining()
        }

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=func.now())
    message = db.Column(db.String(255), nullable=False)
    level = db.Column(db.String(20), nullable=False, default='info')
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'message': self.message,
            'level': self.level
        }

# IP Blacklist middleware
@app.before_request
def check_ip_blacklist():
    # Skip blacklist check for static files
    if request.path.startswith('/static/'):
        return
    
    ip_address = request.remote_addr
    
    # Check if IP is blacklisted
    blacklist_entry = IPBlacklist.query.filter_by(ip_address=ip_address).first()
    
    if blacklist_entry:
        # Check if blacklist has expired
        if blacklist_entry.is_expired():
            # Remove expired entry
            db.session.delete(blacklist_entry)
            db.session.commit()
            return
        
        # Log blocked request
        log_security_event(f"Blocked request from blacklisted IP: {ip_address}", "warning")
        
        # Return 403 Forbidden for blacklisted IPs
        return jsonify({
            "error": "Access denied. Your IP address has been blacklisted due to suspicious activity.",
            "blacklisted": True
        }), 403

# Decorator for requiring login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Decorator for requiring admin role
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Authentication required"}), 401
        user = User.query.filter_by(username=session['username']).first()
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Initialize database with default users
@app.before_first_request
def create_tables_and_defaults():
    with app.app_context():
        db.create_all()
    
    # Check if we need to create default users
    if User.query.count() == 0:
        # Create admin user
        admin = User(
            username='admin',
            password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            role='admin',
            name='Admin User'
        )
        
        # Create regular user
        user = User(
            username='user',
            password=bcrypt.generate_password_hash('user123').decode('utf-8'),
            role='user',
            name='Regular User'
        )
        
        # Add users to database
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()
        
        # Log the creation of default users
        log_security_event("Default users created", "info")

# Record login attempt
def record_login_attempt(username, success=False):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    attempt = LoginAttempt(
        username=username,
        ip_address=ip,
        user_agent=user_agent,
        success=success
    )
    
    db.session.add(attempt)
    db.session.commit()
    
    # Check for suspicious activity
    check_suspicious_activity(username, ip)

# Check for suspicious login patterns
def check_suspicious_activity(username, ip_address):
    # Check for multiple failed attempts from different usernames but same IP
    recent_time = datetime.now() - timedelta(hours=1)
    ip_attempts = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp > recent_time,
        LoginAttempt.success == False
    ).count()
    
    # Check for distributed attempts on same username from different IPs
    username_attempts = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.timestamp > recent_time,
        LoginAttempt.success == False
    ).with_entities(LoginAttempt.ip_address).distinct().count()
    
    # Blacklist IP if too many failed attempts
    if ip_attempts >= 15:  # Threshold for blacklisting
        blacklist_ip(ip_address, f"Automatic blacklist: {ip_attempts} failed login attempts within 1 hour", hours=24)
    elif ip_attempts >= 10:
        log_security_event(f"Suspicious activity detected from IP: {ip_address} - multiple failed attempts", "warning")
    
    if username_attempts >= 5:
        log_security_event(f"Suspicious activity detected for user: {username} - attempts from multiple IPs", "warning")

# Blacklist an IP address
def blacklist_ip(ip_address, reason, hours=None):
    # Check if IP is already blacklisted
    existing = IPBlacklist.query.filter_by(ip_address=ip_address).first()
    if existing:
        # Update existing blacklist entry
        existing.reason = reason
        if hours:
            existing.expires_at = datetime.now() + timedelta(hours=hours)
        db.session.commit()
        log_security_event(f"Updated blacklist for IP: {ip_address}, reason: {reason}", "warning")
        return existing
    
    # Create new blacklist entry
    expires_at = datetime.now() + timedelta(hours=hours) if hours else None
    blacklist_entry = IPBlacklist(
        ip_address=ip_address,
        reason=reason,
        expires_at=expires_at
    )
    
    db.session.add(blacklist_entry)
    db.session.commit()
    
    log_security_event(f"Blacklisted IP: {ip_address}, reason: {reason}", "warning")
    return blacklist_entry

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    print("Login attempt received")  # Debug
    data = request.get_json()
    print("Received data:", data)  # Debug
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        print("Missing credentials")  # Debug
        log_security_event("Login attempt with missing credentials", "warning")
        return jsonify({"error": "Username and password are required"}), 400
    
    user = User.query.filter_by(username=username).first()
    print("User found:", user)  # Debug
    
    # Check if user exists
    if not user:
        record_login_attempt(username, success=False)  # Only record failure after we know user doesn't exist
        log_security_event(f"Failed login attempt for non-existent user: {username}", "warning")
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Check if account is locked
    if user.is_locked():
        record_login_attempt(username, success=False)  # Record failed attempt due to lock
        lockout_remaining = user.get_lockout_remaining()
        log_security_event(f"Login attempt on locked account: {username}", "warning")
        return jsonify({
            "error": "Account is temporarily locked due to too many failed login attempts",
            "locked": True,
            "lockout_remaining": lockout_remaining
        }), 403
    
    # Validate password
    if not bcrypt.check_password_hash(user.password, password):
        record_login_attempt(username, success=False)  # Record failed password attempt
        log_security_event(f"Failed login attempt for user: {username}", "warning")
        user.increment_failed_attempts()
        
        if user.is_locked():
            return jsonify({
                "error": "Account is temporarily locked due to too many failed login attempts",
                "locked": True,
                "lockout_remaining": user.get_lockout_remaining()
            }), 403
        
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Successful login
    session['username'] = username
    record_login_attempt(username, success=True)  # Only record success if all checks pass
    log_security_event(f"Successful login for user: {username}", "info")
    
    # Reset failed attempts counter
    user.reset_failed_attempts()
    
    return jsonify({
        "message": "Login successful",
        "user": {
            "username": username,
            "role": user.role,
            "name": user.name
        }
    })

@app.route('/logout', methods=['POST'])
def logout():
    if 'username' in session:
        log_security_event(f"User logged out: {session['username']}", "info")
        session.pop('username', None)
    return jsonify({"message": "Logged out successfully"})

@app.route('/user/profile', methods=['GET'])
@login_required
def user_profile():
    username = session['username']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "username": username,
        "role": user.role,
        "name": user.name
    })

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    users = User.query.all()
    user_list = [{
        "username": user.username, 
        "role": user.role, 
        "name": user.name,
        "locked": user.is_locked(),
        "failed_attempts": user.failed_login_attempts,
        "lockout_remaining": user.get_lockout_remaining() if user.is_locked() else 0
    } for user in users]
    return jsonify({"users": user_list})

# Add these new routes after the existing '/admin/users' GET route

@app.route('/admin/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'password', 'name', 'role']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Field '{field}' is required"}), 400
    
    # Check if username already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 409
    
    # Validate role
    if data['role'] not in ['admin', 'user']:
        return jsonify({"error": "Role must be 'admin' or 'user'"}), 400
    
    # Create new user
    new_user = User(
        username=data['username'],
        password=bcrypt.generate_password_hash(data['password']).decode('utf-8'),
        name=data['name'],
        role=data['role']
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        log_security_event(f"User created: {data['username']} with role {data['role']}", "info")
        
        return jsonify({
            "message": "User created successfully",
            "user": {
                "username": new_user.username,
                "name": new_user.name,
                "role": new_user.role
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        log_security_event(f"Failed to create user: {str(e)}", "error")
        return jsonify({"error": "Failed to create user"}), 500

@app.route('/admin/users/<username>', methods=['PUT'])
@admin_required
def update_user(username):
    data = request.get_json()
    
    # Find the user
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Prevent self-demotion from admin
    if username == session['username'] and user.role == 'admin' and data.get('role') == 'user':
        return jsonify({"error": "Admins cannot demote themselves"}), 403
    
    # Update user fields
    if 'name' in data and data['name']:
        user.name = data['name']
    
    if 'role' in data and data['role'] in ['admin', 'user']:
        user.role = data['role']
    
    if 'password' in data and data['password']:
        user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Handle account lockout status
    if 'unlock' in data and data['unlock'] and user.is_locked():
        user.reset_failed_attempts()
        log_security_event(f"Account manually unlocked for user: {username} by admin: {session['username']}", "info")
    
    try:
        db.session.commit()
        log_security_event(f"User updated: {username}", "info")
        
        return jsonify({
            "message": "User updated successfully",
            "user": {
                "username": user.username,
                "name": user.name,
                "role": user.role,
                "locked": user.is_locked(),
                "failed_attempts": user.failed_login_attempts,
                "lockout_remaining": user.get_lockout_remaining() if user.is_locked() else 0
            }
        })
    except Exception as e:
        db.session.rollback()
        log_security_event(f"Failed to update user: {str(e)}", "error")
        return jsonify({"error": "Failed to update user"}), 500

@app.route('/admin/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    # Find the user
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Prevent self-deletion
    if username == session['username']:
        return jsonify({"error": "Users cannot delete themselves"}), 403
    
    try:
        db.session.delete(user)
        db.session.commit()
        log_security_event(f"User deleted: {username}", "info")
        
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        db.session.rollback()
        log_security_event(f"Failed to delete user: {str(e)}", "error")
        return jsonify({"error": "Failed to delete user"}), 500

@app.route('/admin/logs', methods=['GET'])
@admin_required
def admin_logs():
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(100).all()
    log_list = [log.to_dict() for log in logs]
    return jsonify({"logs": log_list})

@app.route('/admin/login-attempts', methods=['GET'])
@admin_required
def admin_login_attempts():
    # Get query parameters
    username = request.args.get('username')
    ip_address = request.args.get('ip')
    success = request.args.get('success')
    limit = min(int(request.args.get('limit', 100)), 500)  # Limit to 500 max
    
    # Build query
    query = LoginAttempt.query
    
    if username:
        query = query.filter(LoginAttempt.username == username)
    
    if ip_address:
        query = query.filter(LoginAttempt.ip_address == ip_address)
    
    if success is not None:
        success_bool = success.lower() == 'true'
        query = query.filter(LoginAttempt.success == success_bool)
    
    # Get results
    attempts = query.order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
    
    # Format results
    result = [{
        'id': attempt.id,
        'username': attempt.username,
        'ip_address': attempt.ip_address,
        'user_agent': attempt.user_agent,
        'timestamp': attempt.timestamp.isoformat(),
        'success': attempt.success
    } for attempt in attempts]
    
    return jsonify({"login_attempts": result})

@app.route('/admin/unlock-user/<username>', methods=['POST'])
@admin_required
def unlock_user(username):
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if not user.is_locked():
        return jsonify({"message": "User account is not locked"}), 400
    
    user.reset_failed_attempts()
    log_security_event(f"Account manually unlocked for user: {username} by admin: {session['username']}", "info")
    
    return jsonify({
        "message": "User account unlocked successfully",
        "user": {
            "username": user.username,
            "name": user.name,
            "role": user.role,
            "locked": False,
            "failed_attempts": 0
        }
    })

@app.route('/admin/blacklist', methods=['GET'])
@admin_required
def get_blacklist():
    # Get all non-expired blacklist entries
    blacklist = IPBlacklist.query.all()
    
    # Format results
    result = []
    for entry in blacklist:
        if entry.is_expired():
            # Remove expired entries
            db.session.delete(entry)
            continue
        result.append(entry.to_dict())
    
    # Commit any deletions
    if len(result) < len(blacklist):
        db.session.commit()
    
    return jsonify({"blacklist": result})

@app.route('/admin/blacklist', methods=['POST'])
@admin_required
def add_to_blacklist():
    data = request.get_json()
    
    # Validate required fields
    if not data.get('ip_address') or not data.get('reason'):
        return jsonify({"error": "IP address and reason are required"}), 400
    
    # Validate IP address format
    try:
        ipaddress.ip_address(data['ip_address'])
    except ValueError:
        return jsonify({"error": "Invalid IP address format"}), 400
    
    # Get expiration time
    hours = data.get('hours')
    if hours is not None:
        try:
            hours = int(hours)
            if hours < 0:
                raise ValueError("Hours must be positive")
        except ValueError:
            return jsonify({"error": "Hours must be a positive integer"}), 400
    
    # Add IP to blacklist
    try:
        blacklist_entry = blacklist_ip(data['ip_address'], data['reason'], hours)
        
        return jsonify({
            "message": "IP address blacklisted successfully",
            "blacklist_entry": blacklist_entry.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        log_security_event(f"Failed to blacklist IP: {str(e)}", "error")
        return jsonify({"error": "Failed to blacklist IP address"}), 500

@app.route('/admin/blacklist/<int:blacklist_id>', methods=['DELETE'])
@admin_required
def remove_from_blacklist(blacklist_id):
    # Find the blacklist entry
    entry = IPBlacklist.query.get(blacklist_id)
    if not entry:
        return jsonify({"error": "Blacklist entry not found"}), 404
    
    ip_address = entry.ip_address
    
    try:
        db.session.delete(entry)
        db.session.commit()
        log_security_event(f"IP address removed from blacklist: {ip_address} by admin: {session['username']}", "info")
        
        return jsonify({"message": "IP address removed from blacklist successfully"})
    except Exception as e:
        db.session.rollback()
        log_security_event(f"Failed to remove IP from blacklist: {str(e)}", "error")
        return jsonify({"error": "Failed to remove IP from blacklist"}), 500

def log_security_event(message, level="info"):
    log = SecurityLog(message=message, level=level)
    db.session.add(log)
    db.session.commit()

if __name__ == '__main__':
     app.run(host='0.0.0.0', port=5000, debug=True)