from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pymysql, random
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://shri:1234@localhost/kisan'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use Gmail's SMTP server
app.config['MAIL_PORT'] = 587  # Use port 587 for TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'ainewshub89@gmail.com'  # Updated email
app.config['MAIL_PASSWORD'] = 'xldaufoufokehnjl'  # Updated password
app.config['MAIL_DEFAULT_SENDER'] = 'ainewshub89@gmail.com'  # Updated sender email

mail = Mail(app)
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    user_type = db.Column(db.String(10), nullable=False)  # 'customer' or 'farmer'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    otp = db.Column(db.String(6))
    is_verified = db.Column(db.Boolean, default=False)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Ensure this route matches the URL in the signup form
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        user_type = request.form['user_type']  # 'customer' or 'farmer'

        # Check if the email is already registered
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('signup'))

        # Generate OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

        # Create a new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            phone=phone,
            user_type=user_type,
            otp=otp,
            is_verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        # Send OTP email
        try:
            msg = Message('Your OTP for Kisansetu Registration',
                          sender='your-email@example.com',
                          recipients=[email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            flash('OTP sent to your email. Please verify your account.')
        except Exception as e:
            print(f"Error sending email: {e}")
            flash('Failed to send OTP. Please try again.')
            return redirect(url_for('signup'))

        # Set session and redirect to OTP verification
        session['temp_user_id'] = new_user.id
        session['user_type'] = user_type
        return redirect(url_for('otp_verification'))

    return render_template('signup.html')

@app.route('/otp-verification', methods=['GET', 'POST'])
def otp_verification():
    # Ensure this route matches the URL in the OTP verification form
    if request.method == 'POST':
        otp = request.form['otp']
        user_id = session.get('temp_user_id')

        user = User.query.get(user_id)
        if user and user.otp == otp:
            user.is_verified = True
            user.otp = None  # Clear OTP after verification
            db.session.commit()
            session['user_id'] = user.id
            flash('Account verified successfully!')

            # Redirect to the appropriate dashboard
            if user.user_type == 'customer':
                return redirect(url_for('customer_dashboard'))
            elif user.user_type == 'farmer':
                return redirect(url_for('farmer_dashboard'))

        flash('Invalid OTP. Please try again.')
        return redirect(url_for('otp_verification'))

    return render_template('otp_verification.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Ensure this route matches the URL in the login form
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email first.')
                return redirect(url_for('login'))

            # Set session variables
            session['user_id'] = user.id
            session['user_type'] = user.user_type

            # Redirect to the appropriate dashboard
            if user.user_type == 'customer':
                return redirect(url_for('customer_dashboard'))
            elif user.user_type == 'farmer':
                return redirect(url_for('farmer_dashboard'))  # Ensure this is correct

        flash('Invalid email or password.')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/farmer/dashboard')
def farmer_dashboard():
    # Ensure this route matches the redirection for farmer users
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        flash('Please log in as a farmer to access the dashboard.')
        return redirect(url_for('login'))
    return render_template('farmer_dashboard.html')

@app.route('/customer/dashboard')
def customer_dashboard():
    # Ensure this route matches the redirection for customer users
    if 'user_id' not in session or session.get('user_type') != 'customer':
        flash('Please log in as a customer to access the dashboard.')
        return redirect(url_for('login'))
    return render_template('customer_dashboard.html')

if __name__ == '__main__':
    with app.app_context():
        pymysql.install_as_MySQLdb()
        db.create_all()
    app.run(debug=True)
