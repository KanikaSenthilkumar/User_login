import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static')
app.secret_key = "Kanika2629*"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Kanika2926*@localhost/login'
db = SQLAlchemy(app)

class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
with app.app_context():
    db.create_all()
def validate_password(password):
    error_messages = []

    if len(password) < 8:
        error_messages.append("Password must be at least 8 characters long.")
    if not re.search(r'[a-z]', password):
        error_messages.append("Password must contain at least one lowercase letter.")
    if not re.search(r'[A-Z]', password):
        error_messages.append("Password must contain at least one uppercase letter.")
    if not re.search(r'\d', password):
        error_messages.append("Password must contain at least one digit.")
    if not re.search(r'[\W_]', password): 
        error_messages.append("Password must contain at least one special character.")
    
    if error_messages:
        return False, " ".join(error_messages)
    return True, "Password is valid."

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Both username and password are required!', 'danger')
            return redirect(url_for('login'))
        
        User = user.query.filter_by(username=username).first() 
        
        if User and check_password_hash(User.password, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        
        else:
            flash('Invalid credentials. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('signup'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('signup'))
        existing_user = user.query.filter((user.username == username) | (user.email == email)).first()
        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = user(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)