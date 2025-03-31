from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pymysql, random
from flask_mail import Mail, Message
import os
from werkzeug.utils import secure_filename
from functools import wraps
from sqlalchemy import text
import time  # Add this import at the top with other imports

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

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'e:/kisansetu/static/product_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

mail = Mail(app)
db = SQLAlchemy(app)

def init_db():
    with app.app_context():
        try:
            # Check if tables exist
            existing_tables = db.engine.table_names()
            
            if not existing_tables:
                # Create all tables if they don't exist
                db.create_all()
                print("Created all database tables")
            else:
                # Add missing columns to existing tables
                with db.engine.connect() as conn:
                    try:
                        conn.execute(text("ALTER TABLE user ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT FALSE"))
                        conn.execute(text("ALTER TABLE user ADD COLUMN IF NOT EXISTS profile_pic VARCHAR(255)"))
                        conn.commit()
                        print("Added is_approved and profile_pic columns to user table")
                    except Exception as e:
                        print(f"Note: is_approved or profile_pic column might already exist: {e}")
                        db.session.rollback()
        except Exception as e:
            print(f"Database initialization error: {e}")
            db.session.rollback()

def add_profile_pic_column():
    with app.app_context():
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN IF NOT EXISTS profile_pic VARCHAR(255)"))
                conn.commit()
                print("Profile picture column added successfully")
        except Exception as e:
            print(f"Error adding profile_pic column: {e}")
            db.session.rollback()

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
    is_approved = db.Column(db.Boolean, default=False)  # Add this line for farmer approval
    profile_pic = db.Column(db.String(255), nullable=True)  # Match the new column

# Product Model
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)  # Changed to decimal
    stock = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.Text)
    farmer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_approved = db.Column(db.Boolean, default=False)
    is_rejected = db.Column(db.Boolean, default=False)  # Add this line
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Admin Model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp = db.Column(db.String(6))
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Add this with your other models
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    delivery_fee = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(50), default='Pending')  # Pending, Confirmed, Delivered, Cancelled
    payment_method = db.Column(db.String(50), nullable=False)
    payment_status = db.Column(db.String(50), default='Pending')  # Pending, Paid, Failed
    delivery_details = db.Column(db.JSON, nullable=False)
    items = db.Column(db.JSON, nullable=False)
    tracking_number = db.Column(db.String(100))
    delivery_date = db.Column(db.DateTime)
    cancelled_date = db.Column(db.DateTime)
    cancel_reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship with User model
    user = db.relationship('User', backref=db.backref('orders', lazy=True))

# Add this after other models
class Wishlist(db.Model):
    __tablename__ = 'wishlists'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref=db.backref('wishlists', lazy=True))
    product = db.relationship('Product', backref=db.backref('wishlists', lazy=True))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

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

        # Set is_approved based on user type
        if user_type == 'farmer':
            new_user.is_approved = False
            db.session.commit()
            
            # Send email to admin about new farmer registration
            try:
                admin_msg = Message('New Farmer Registration - Action Required',
                                 recipients=['admin@kisansetu.com'])  # Change to admin email
                admin_msg.body = f'''New farmer registration:
                Name: {name}
                Email: {email}
                Phone: {phone}
                
                Please review and approve/reject from admin dashboard.
                '''
                mail.send(admin_msg)
            except Exception as e:
                print(f"Error sending admin notification: {e}")
        else:
            new_user.is_approved = True  # Customers don't need approval
        
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

            # Send admin notification for farmer registration
            if user.user_type == 'farmer':
                try:
                    msg = Message('New Farmer Registration - Action Required',
                                recipients=['ainewshub89@gmail.com'])  # Replace with admin email
                    msg.body = f'''New farmer registration requires approval:
                    Name: {user.name}
                    Email: {user.email}
                    Phone: {user.phone}
                    
                    Please review and approve from admin dashboard.
                    '''
                    mail.send(msg)
                    flash('Your account has been verified. Please wait for admin approval to login.')
                except Exception as e:
                    print(f"Error sending admin notification: {e}")
                return redirect(url_for('login'))
            else:
                return redirect(url_for('customer_dashboard'))

        flash('Invalid OTP. Please try again.')
        return redirect(url_for('otp_verification'))

    return render_template('otp_verification.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email first.')
                return redirect(url_for('login'))
                
            # Check for farmer approval
            if user.user_type == 'farmer':
                if not user.is_approved:
                    flash('Your farmer account is pending admin approval.')
                    return redirect(url_for('login'))

            # Store user info in session
            session['user_id'] = user.id
            session['user_type'] = user.user_type
            session['user_name'] = user.name
            session['user_email'] = user.email
            session['user_phone'] = user.phone

            # Redirect based on user type
            if user.user_type == 'farmer':
                return redirect(url_for('farmer_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))

        flash('Invalid email or password.')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

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

@app.route('/navbar')
def navbar():
    return render_template('navbar.html')

@app.route('/footer')
def footer():
    return render_template('footer.html')

@app.route('/add_product', methods=['POST'])
def add_product():
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        return {'error': 'Unauthorized'}, 401

    try:
        print("Received product data:", request.form)  # Debug log
        
        # Create new product
        new_product = Product(
            name=request.form['name'],
            category=request.form['category'],
            price=float(request.form['price']),
            stock=int(request.form['stock']),
            description=request.form.get('description', ''),
            image_url=request.form.get('image_url', ''),
            farmer_id=session['user_id'],
            is_approved=False  # Ensure products start as unapproved
        )
        
        db.session.add(new_product)
        db.session.commit()
        print(f"Product added successfully: ID={new_product.id}")  # Debug log
        
        return jsonify({'message': 'Product added successfully', 'product_id': new_product.id}), 200
    except Exception as e:
        print(f"Error adding product: {str(e)}")  # Debug log
        db.session.rollback()
        return {'error': str(e)}, 400

@app.route('/farmer/add_product', methods=['GET', 'POST'])
def add_product_form():
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        flash('Please log in as a farmer to access this page.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Create upload folder if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Handle image upload
            image_url = ''
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    image_url = f'/static/product_images/{filename}'

            # Create new product with decimal price
            new_product = Product(
                name=request.form['name'],
                category=request.form['category'],
                price=float(request.form['price']),  # Will be converted to Decimal
                stock=int(request.form['stock']),
                description=request.form.get('description', ''),
                image_url=image_url,
                farmer_id=session['user_id'],
                is_approved=False
            )
            
            db.session.add(new_product)
            db.session.commit()
            
            flash('Product added successfully! Waiting for admin approval.')
            return redirect(url_for('farmer_dashboard'))
            
        except Exception as e:
            print(f"Error adding product: {str(e)}")  # Debug log
            db.session.rollback()
            flash(f'Error adding product: {str(e)}')
            return redirect(url_for('add_product_form'))
    
    return render_template('farmer_product_form.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            if not admin.is_verified:
                # Generate and send OTP
                otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                admin.otp = otp
                db.session.commit()
                
                # Send OTP email
                try:
                    msg = Message('Admin Login OTP - KisanSetu',
                              recipients=[email])
                    msg.body = f'Your OTP for admin login is: {otp}'
                    mail.send(msg)
                    session['temp_admin_id'] = admin.id
                    return redirect(url_for('admin_otp_verification'))
                except Exception as e:
                    flash('Error sending OTP.')
                    return redirect(url_for('admin_login'))
            
            session['admin_id'] = admin.id
            session['admin_name'] = admin.name
            return redirect(url_for('admin_dashboard'))
            
        flash('Invalid email or password')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')

@app.route('/admin-otp-verification', methods=['GET', 'POST'])
def admin_otp_verification():
    if 'temp_admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    if request.method == 'POST':
        admin = Admin.query.get(session['temp_admin_id'])
        if admin and admin.otp == request.form['otp']:
            admin.is_verified = True
            admin.otp = None
            db.session.commit()
            
            session['admin_id'] = admin.id
            session['admin_name'] = admin.name
            return redirect(url_for('admin_dashboard'))
            
        flash('Invalid OTP')
        return redirect(url_for('admin_otp_verification'))
        
    return render_template('admin_otp_verification.html')

@app.route('/admin')
def admin_redirect():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        admin_key = request.form['admin_key']

        # Verify admin key
        if admin_key != '1234':  # Replace with secure key
            flash('Invalid admin key')
            return redirect(url_for('admin_signup'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('admin_signup'))

        # Check if email already exists
        if Admin.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('admin_signup'))

        try:
            # Create new admin
            hashed_password = generate_password_hash(password)
            new_admin = Admin(
                name=name,
                email=email,
                password=hashed_password,
                is_verified=False
            )
            db.session.add(new_admin)
            db.session.commit()

            # Generate and send OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            new_admin.otp = otp
            db.session.commit()

            msg = Message('Admin Registration OTP - KisanSetu',
                         recipients=[email])
            msg.body = f'Your OTP for admin registration is: {otp}'
            mail.send(msg)

            session['temp_admin_id'] = new_admin.id
            return redirect(url_for('admin_otp_verification'))

        except Exception as e:
            db.session.rollback()
            flash('Error creating admin account')
            return redirect(url_for('admin_signup'))

    return render_template('admin_signup.html')

@app.route('/get_pending_products')
@admin_required
def get_pending_products():
    try:
        print("Fetching pending products...")  # Debug log
        # Modified query to exclude rejected products
        products = Product.query.filter_by(is_approved=False, is_rejected=False).all()
        print(f"Found {len(products)} pending products")  # Debug log
        
        result = [{
            'id': p.id,
            'name': p.name,
            'category': p.category,
            'price': p.price,
            'stock': p.stock,
            'description': p.description or '',
            'image_url': p.image_url or '',
            'farmer_id': p.farmer_id,
            'created_at': p.created_at.isoformat()
        } for p in products]
        
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching pending products: {e}")  # Debug log
        return jsonify({'error': str(e)}), 500

@app.route('/approve_product/<int:product_id>', methods=['POST'])
@admin_required
def approve_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_approved = True
    db.session.commit()
    return jsonify({'message': 'Product approved successfully'})

@app.route('/revoke_product/<int:product_id>', methods=['POST'])
@admin_required
def revoke_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        product.is_approved = False
        db.session.commit()
        return jsonify({'message': 'Product approval revoked successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        return jsonify({'message': 'Product deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/reject_product/<int:product_id>', methods=['POST'])
@admin_required
def reject_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        product.is_approved = False
        product.is_rejected = True  # Set rejected status
        db.session.commit()
        return jsonify({'message': 'Product rejected successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/get_rejected_products')
@admin_required
def get_rejected_products():
    try:
        # Only get products that are explicitly rejected
        products = db.session.query(Product, User).join(User, Product.farmer_id == User.id)\
            .filter(Product.is_rejected == True).all()
        
        return jsonify([{
            'id': p.id,
            'name': p.name,
            'category': p.category,
            'price': p.price,
            'stock': p.stock,
            'description': p.description or '',
            'image_url': p.image_url or '',
            'farmer_id': p.farmer_id,
            'farmerName': u.name,
            'created_at': p.created_at.isoformat()
        } for p, u in products])
    except Exception as e:
        print(f"Error fetching rejected products: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_approved_products')
def get_approved_products():
    try:
        print("Fetching approved products...") # Debug log
        products = db.session.query(Product, User).join(
            User, Product.farmer_id == User.id
        ).filter(
            Product.is_approved == True,
            Product.is_rejected == False
        ).all()
        
        print(f"Found {len(products)} approved products") # Debug log
        
        if not products:
            print("No approved products found") # Debug log
            return jsonify([])
            
        result = [{
            'id': str(product.id),  # Convert to string to avoid JS integer issues
            'name': product.name,
            'category': product.category,
            'price': float(product.price),
            'stock': product.stock,
            'description': product.description or '',
            'image_url': product.image_url or '',
            'farmer_id': product.farmer_id,
            'farmerName': user.name,
            'rating': float(getattr(product, 'rating', 3.5)),
            'created_at': product.created_at.isoformat() if product.created_at else None
        } for product, user in products]
        
        print(f"Returning {len(result)} products") # Debug log
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching approved products: {e}") # Debug log
        return jsonify({'error': str(e)}), 500

# Add dummy data generation function
def generateDummyProducts():
    dummy_products = []
    categories = ['vegetables', 'fruits', 'grains', 'pulses']
    
    for i in range(20):  # Generate 20 dummy products
        category = random.choice(categories)
        price = round(random.uniform(20, 500), 2)
        dummy_products.append({
            'id': i + 1,
            'name': f'Sample {category.capitalize()} {i+1}',
            'category': category,
            'price': price,
            'stock': random.randint(10, 100),
            'description': f'Fresh {category} from local farmers',
            'image_url': f'https://picsum.photos/200?random={i}',
            'farmer_id': 1,
            'farmerName': 'Sample Farmer',
            'rating': round(random.uniform(3.0, 5.0), 1),
            'created_at': datetime.now().isoformat()
        })
    
    return dummy_products

@app.route('/get_farmer_products/<int:farmer_id>')
def get_farmer_products(farmer_id):
    products = Product.query.filter_by(farmer_id=farmer_id).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'category': p.category,
        'price': p.price,
        'stock': p.stock,
        'description': p.description,
        'image_url': p.image_url if p.image_url else f'https://via.placeholder.com/200x200?text={p.name}',
        'is_approved': p.is_approved,
        'created_at': p.created_at.isoformat()
    } for p in products])

@app.route('/approve_farmer/<int:farmer_id>', methods=['POST'])
@admin_required
def approve_farmer(farmer_id):
    try:
        farmer = User.query.get_or_404(farmer_id)
        if farmer.user_type != 'farmer':
            return jsonify({'error': 'User is not a farmer'}), 400
            
        farmer.is_approved = True
        db.session.commit()
        
        # Send approval email to farmer
        try:
            msg = Message('Your KisanSetu Application is Approved!',
                         recipients=[farmer.email])
            msg.body = '''Congratulations! Your farmer application has been approved.
            You can now login to your account and start listing your products.
            
            Thank you for joining KisanSetu!
            '''
            mail.send(msg)
        except Exception as e:
            print(f"Error sending approval email: {e}")
            
        return jsonify({'message': 'Farmer approved successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/get_pending_farmers')
@admin_required
def get_pending_farmers():
    try:
        pending_farmers = User.query.filter_by(user_type='farmer', is_approved=False).all()
        return jsonify([{
            'id': f.id,
            'name': f.name,
            'email': f.email,
            'phone': f.phone,
            'created_at': f.created_at.isoformat(),
            'is_verified': f.is_verified,
            'is_approved': f.is_approved
        } for f in pending_farmers])
    except Exception as e:
        print(f"Error fetching pending farmers: {e}")
        return jsonify([])

@app.route('/get_registered_farmers')
@admin_required
def get_registered_farmers():
    try:
        farmers = User.query.filter_by(user_type='farmer').all()
        return jsonify([{
            'id': f.id,
            'name': f.name,
            'email': f.email,
            'phone': f.phone,
            'created_at': f.created_at.isoformat(),
            'is_verified': f.is_verified,
            'is_approved': f.is_approved
        } for f in farmers])
    except Exception as e:
        print(f"Error fetching registered farmers: {e}")
        return jsonify([])

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('cart.html')

@app.route('/checkout')
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user details for pre-filling the form
    user = User.query.get(session['user_id'])
    return render_template('checkout.html', user=user)

# Update the place_order route
@app.route('/place_order', methods=['POST'])
def place_order():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
        
    try:
        data = request.json
        
        # Create new order
        order = Order(
            user_id=session['user_id'],
            total_amount=data['total_amount'],
            delivery_fee=data['delivery_fee'],
            payment_method=data['payment_method'],
            delivery_details=data['delivery_details'],
            items=data['items'],
            status='Pending'
        )
        
        # Add to database
        db.session.add(order)
        db.session.commit()
        
        # Generate order ID
        order_id = f"KS{order.id:06d}"
        
        try:
            # Send order confirmation email
            msg = Message('Order Confirmation - KisanSetu',
                        recipients=[session.get('user_email')])
            msg.body = f'''
            Thank you for your order!
            
            Order ID: {order_id}
            Total Amount: ₹{data['total_amount']}
            Delivery Address: {data['delivery_details']['address']}
            
            Your order will be delivered soon.
            '''
            mail.send(msg)
        except Exception as e:
            print(f"Error sending confirmation email: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Order placed successfully',
            'orderId': order_id
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error placing order: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('orders.html')

@app.route('/get_user_orders')
def get_user_orders():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        # Get status filter from query parameters
        status_filter = request.args.get('status', 'all')
        
        # Base query
        query = Order.query.filter_by(user_id=session['user_id'])
        
        # Apply status filter if not 'all'
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        # Get orders ordered by date
        orders = query.order_by(Order.order_date.desc()).all()

        # Get all product IDs from orders
        product_ids = set()
        for order in orders:
            for item in order.items:
                product_ids.add(item.get('id'))

        # Get product details including images
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        product_details = {str(p.id): {
            'image_url': p.image_url,
            'description': p.description
        } for p in products}

        return jsonify([{
            'id': order.id,
            'order_date': order.order_date.isoformat(),
            'total_amount': float(order.total_amount),
            'delivery_fee': float(order.delivery_fee),
            'status': order.status,
            'payment_method': order.payment_method,
            'payment_status': order.payment_status,
            'delivery_details': order.delivery_details,
            'items': [{
                **item,
                'image_url': product_details.get(str(item['id']), {}).get('image_url'),
                'description': product_details.get(str(item['id']), {}).get('description')
            } for item in order.items],
            'tracking_number': order.tracking_number,
            'delivery_date': order.delivery_date.isoformat() if order.delivery_date else None,
            'cancelled_date': order.cancelled_date.isoformat() if order.cancelled_date else None,
            'cancel_reason': order.cancel_reason
        } for order in orders])
    except Exception as e:
        print(f"Error fetching orders: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        order = Order.query.get_or_404(order_id)
        if order.user_id != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
            
        if order.status != 'Pending':
            return jsonify({'error': 'Can only cancel pending orders'}), 400
            
        order.status = 'Cancelled'
        order.cancelled_date = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Order cancelled successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/wishlist')
def wishlist():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('wishlist.html')

@app.route('/get_wishlist')
def get_wishlist():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        wishlist_items = db.session.query(Wishlist, Product)\
            .join(Product, Wishlist.product_id == Product.id)\
            .filter(Wishlist.user_id == session['user_id'])\
            .all()
            
        return jsonify([{
            'id': item.Product.id,
            'name': item.Product.name,
            'price': float(item.Product.price),
            'category': item.Product.category,
            'image_url': item.Product.image_url,
            'description': item.Product.description,
            'stock': item.Product.stock,
            'added_on': item.Wishlist.created_at.isoformat()
        } for item in wishlist_items])
    except Exception as e:
        print(f"Error fetching wishlist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
def add_to_wishlist(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        # Check if already in wishlist
        existing = Wishlist.query.filter_by(
            user_id=session['user_id'], 
            product_id=product_id
        ).first()
        
        if existing:
            return jsonify({'success': True, 'message': 'Already in wishlist'})
            
        wishlist_item = Wishlist(
            user_id=session['user_id'],
            product_id=product_id
        )
        db.session.add(wishlist_item)
        db.session.commit()
        
        # Get updated count
        count = Wishlist.query.filter_by(user_id=session['user_id']).count()
        
        return jsonify({
            'success': True, 
            'message': 'Added to wishlist',
            'count': count
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/remove_from_wishlist/<int:product_id>', methods=['POST'])
def remove_from_wishlist(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        Wishlist.query.filter_by(
            user_id=session['user_id'],
            product_id=product_id
        ).delete()
        db.session.commit()
        
        # Get updated count
        count = Wishlist.query.filter_by(user_id=session['user_id']).count()
        
        return jsonify({
            'success': True, 
            'message': 'Removed from wishlist',
            'count': count
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html')

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.json
        user = User.query.get(session['user_id'])
        user.name = data['name']
        user.phone = data['phone']
        db.session.commit()
        
        # Update session data
        session['user_name'] = user.name
        session['user_phone'] = user.phone
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/update_profile_picture', methods=['POST'])
def update_profile_picture():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        if 'profile_pic' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['profile_pic']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if file and allowed_file(file.filename):
            # Create profile_pics directory if it doesn't exist
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics')
            os.makedirs(upload_folder, exist_ok=True)
            
            # Generate unique filename with timestamp
            filename = secure_filename(f"user_{session['user_id']}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(upload_folder, filename)
            
            # Save file
            file.save(filepath)
            
            # Update user profile picture path in database
            user = User.query.get(session['user_id'])
            user.profile_pic = f"/static/product_images/profile_pics/{filename}"
            db.session.commit()
            
            # Update session
            session['user_profile_pic'] = user.profile_pic
            
            return jsonify({
                'success': True,
                'profile_pic_url': user.profile_pic
            })
            
        return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        print(f"Error updating profile picture: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    pymysql.install_as_MySQLdb()
    init_db()
    add_profile_pic_column()  # Add this line
    app.run(debug=True)
