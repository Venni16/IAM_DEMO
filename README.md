## Identity and Access Management (IAM) System.

# Overview:

This is a comprehensive Identity and Access Management (IAM) system built with Flask (Python backend) and vanilla JavaScript (frontend). The system provides secure user authentication, role-based access control, and security monitoring features.

## Key Features
    -User Authentication: Secure login/logout functionality with session management

   -Role-Based Access Control: Different permissions for admin and regular users

   -Account Lockout: Automatic lockout after multiple failed login attempts

   -IP Blacklisting: Protection against brute force attacks with IP blacklisting

   -Security Logging: Detailed logging of all security-related events

   -User Management: Admin panel for managing users (create, update, delete)

   -Login Attempt Monitoring: Tracking and visualization of login attempts

## System Components:

 # Backend (Flask)

   -User authentication with bcrypt password hashing

   -Rate limiting with Flask-Limiter

   -SQLAlchemy for database operations

   -Middleware for IP blacklist checking

   -Comprehensive API endpoints for all functionality

# Frontend (JavaScript)

   -Responsive UI with login and dashboard interfaces

   -Dynamic content loading based on user role

   -Modal-based forms for user and blacklist management

   -Real-time notifications and error handling

# Database Models

   -User: Stores user credentials, roles, and login attempt data

   -LoginAttempt: Records all login attempts (successful and failed)

   -IPBlacklist: Tracks blacklisted IP addresses with expiration times

   -SecurityLog: Stores security events for auditing purposes

## Installation

 # Prerequisites:

   -Python 3.7+

   -pip

   -SQLite (for development)



## Setup Steps

 1.Clone the repository:
   git clone https://github.com/yourusername/iam.git
   cd iam

 2.Create and activate a virtual environment:
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate

 3.Install dependencies:
   pip install -r requirements.txt

 4.Initialize the database:
   python app.py (This will create the SQLite database with default admin and user accounts)

 5.Access the application at: http://localhost:5000


## Default Credentials:

Admin: username=admin, password=admin123

Regular User: username=user, password=user123


## Author

Vennilavan Manoharen – for academic submission.
