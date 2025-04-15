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
    user = db.relationship('User', backref=db.backref('wishlists', lazy=True))  # Fixed missing parenthesis
    product = db.relationship('Product', backref=db.backref('wishlists', lazy=True))  # Fixed missing parenthesis

# Cart Model
class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Add KYC Model after other models
class KYC(db.Model):
    __tablename__ = 'kyc'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fruit_id = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    document_type = db.Column(db.String(20), nullable=False)  # 'aadhar' or 'pan'
    document_number = db.Column(db.String(20), nullable=False)
    document_image = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected

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

            # Different messages for farmer and customer
            if user.user_type == 'farmer':
                flash('Account verified! Your KYC approval application has been submitted.')
                return redirect(url_for('kyc_verification'))
            else:
                flash('Account verified successfully!')
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
            session['user_profile_pic'] = user.profile_pic or f"https://ui-avatars.com/api/?name={user.name}&background=random"
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

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

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
        products = db.session.query(Product, User).join(
            User, Product.farmer_id == User.id
        ).filter(
            Product.is_approved == True,
            Product.is_rejected == False
        ).all()
        
        result = [{
            'id': str(product.id),
            'name': product.name,
            'category': product.category,
            'price': float(product.price),
            'stock': product.stock,
            'stock_status': 'out_of_stock' if product.stock == 0 else 'low_stock' if product.stock <= 5 else 'in_stock',
            'description': product.description or '',
            'image_url': product.image_url or '',
            'farmer_id': product.farmer_id,
            'farmerName': user.name,
            'created_at': product.created_at.isoformat() if product.created_at else None
        } for product, user in products]
        
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching approved products: {e}")
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
        'price': float(p.price),
        'stock': p.stock,
        'description': p.description,
        'image_url': p.image_url if p.image_url else f'https://via.placeholder.com/200x200?text={p.name}',
        'is_approved': p.is_approved,
        'is_rejected': p.is_rejected,  # Add this field
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
        flash('Please log in to proceed to checkout.')
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    try:
        # Get cart items with a single query
        cart_items = db.session.query(Cart, Product)\
            .join(Product, Cart.product_id == Product.id)\
            .filter(Cart.user_id == session['user_id'])\
            .all()
        
        if not cart_items:
            flash('Your cart is empty. Add items to proceed to checkout.')
            return redirect(url_for('cart'))  # Redirect to cart if empty
        
        # Get user details
        user = User.query.get(session['user_id'])
        if not user:
            flash('User not found. Please log in again.')
            return redirect(url_for('login'))  # Redirect to login if user not found
        
        # Calculate totals
        subtotal = sum(float(item.Product.price) * item.Cart.quantity for item in cart_items)
        delivery_fee = 40  # Fixed delivery fee
        total = subtotal + delivery_fee
        
        # Format cart items for display
        formatted_items = [{
            'id': item.Cart.id,
            'product_id': item.Product.id,
            'name': item.Product.name,
            'price': float(item.Product.price),
            'quantity': item.Cart.quantity,
            'subtotal': float(item.Product.price * item.Cart.quantity)
        } for item in cart_items]
        
        return render_template('checkout.html', 
                               user=user,
                               cart_items=formatted_items,
                               subtotal=subtotal,
                               delivery_fee=delivery_fee,
                               total=total)
    except Exception as e:
        print(f"Error loading checkout page: {e}")
        flash('An error occurred while loading the checkout page. Please try again.')
        return redirect(url_for('cart'))  # Redirect to cart on error

@app.route('/check_stock', methods=['POST'])
def check_stock():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        data = request.json
        items = data.get('items', [])
        out_of_stock_items = []
        
        for item in items:
            product = Product.query.get(item.get('product_id'))
            if not product:
                return jsonify({
                    'success': False,
                    'message': f'Product {item.get("name")} not found'
                })
            
            if product.stock == 0:
                out_of_stock_items.append(product.name)
            elif product.stock < item.get('quantity', 0):
                return jsonify({
                    'success': False,
                    'message': f'Not enough stock for {product.name}. Available: {product.stock}',
                    'available_stock': product.stock
                })
        
        if out_of_stock_items:
            return jsonify({
                'success': False,
                'message': f'The following items are out of stock: {", ".join(out_of_stock_items)}',
                'outOfStock': True
            })
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error checking stock: {e}")
        return jsonify({
            'success': False,
            'message': 'Error checking stock availability'
        }), 500

@app.route('/update_order_status', methods=['POST'])
def update_order_status():
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        data = request.json
        order_id = data.get('order_id')
        new_status = data.get('status')
        
        # Find the order
        order = Order.query.get_or_404(order_id)
        
        # Verify the order contains products from this farmer
        order_items = order.items
        farmer_id = session['user_id']
        has_farmer_products = False
        
        for item in order_items:
            product = db.session.get(Product, item.get('product_id'))
            if product and product.farmer_id == farmer_id:
                has_farmer_products = True
                break
        
        if not has_farmer_products:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Update order status
        order.status = new_status
        if new_status == 'Delivered':
            order.delivery_date = datetime.utcnow()
        
        db.session.commit()
        
        # Send email notification to customer
        try:
            msg = Message('Order Status Update - KisanSetu',
                        recipients=[order.user.email])
            msg.body = f'''
            Your order #{order.id} has been marked as {new_status}.
            
            Thank you for shopping with KisanSetu!
            '''
            mail.send(msg)
        except Exception as e:
            print(f"Error sending email notification: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Order status updated to {new_status}'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating order status: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/place_order', methods=['POST'])
def place_order():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
        
    try:
        data = request.json
        items = data.get('items', [])
        
        # Check stock availability again before placing order
        for item in items:
            product = db.session.get(Product, item.get('product_id'))
            if not product:
                return jsonify({
                    'success': False,
                    'message': f'Product {item.get("name")} not found'
                })
            
            if product.stock < item.get('quantity', 0):
                return jsonify({
                    'success': False,
                    'message': f'Not enough stock for {product.name}. Available: {product.stock}'
                })
            
            # Update stock
            product.stock -= item.get('quantity', 0)
        
        # Create new order
        order = Order(
            user_id=session['user_id'],
            total_amount=data['total_amount'],
            delivery_fee=data['delivery_fee'],
            payment_method=data['payment_method'],
            delivery_details=data['delivery_details'],
            items=items,
            status='Pending'
        )
        
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

        # Format orders for response
        result = [{
            'id': order.id,
            'order_date': order.order_date.isoformat(),
            'total_amount': float(order.total_amount),
            'delivery_fee': float(order.delivery_fee),
            'status': order.status,
            'payment_method': order.payment_method,
            'payment_status': order.payment_status,
            'delivery_details': order.delivery_details,
            'items': order.items,
            'tracking_number': order.tracking_number,
            'delivery_date': order.delivery_date.isoformat() if order.delivery_date else None,
            'cancelled_date': order.cancelled_date.isoformat() if order.cancelled_date else None,
            'cancel_reason': order.cancel_reason
        } for order in orders]

        return jsonify(result)
    except Exception as e:
        print(f"Error fetching orders: {e}")
        return jsonify({'error': 'Failed to load orders'}), 500

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
        # Verify product exists first
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
            
        # Check if already in wishlist
        existing = Wishlist.query.filter_by(
            user_id=session['user_id'], 
            product_id=product_id
        ).first()
        
        if existing:
            return jsonify({'success': True, 'message': 'Already in wishlist'})
            
        # Create new wishlist item with explicit product_id
        wishlist_item = Wishlist(
            user_id=session['user_id'],
            product_id=product_id  # Ensure product_id is not None
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
        print(f"Error adding to wishlist: {e}")  # Add logging
        return jsonify({'error': str(e)}), 500

@app.route('/remove_from_wishlist/<int:product_id>', methods=['POST'])
def remove_from_wishlist(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        # Find the specific wishlist item to remove
        wishlist_item = Wishlist.query.filter_by(
            user_id=session['user_id'],
            product_id=product_id
        ).first()
        
        if not wishlist_item:
            return jsonify({'error': 'Item not found in wishlist'}), 404
            
        # Delete the specific item
        db.session.delete(wishlist_item)
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
        print(f"Error removing from wishlist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')
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

@app.route('/verify_fruit_id/<fruit_id>')
def verify_fruit_id(fruit_id):
    try:
        # Query the fruit table
        with db.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT farm_size, farm_location, soil_type, irrigation_type, 
                       certification_type, owner_name, owner_contact, 
                       registration_authority, is_active 
                FROM fruit 
                WHERE id = :fruit_id
            """), {"fruit_id": fruit_id})
            fruit = result.fetchone()
            
            if fruit and fruit.is_active:
                return jsonify({
                    'success': True,
                    'data': {
                        'farm_size': float(fruit.farm_size),
                        'farm_location': fruit.farm_location,
                        'soil_type': fruit.soil_type,
                        'irrigation_type': fruit.irrigation_type,
                        'certification_type': fruit.certification_type,
                        'owner_name': fruit.owner_name,
                        'owner_contact': fruit.owner_contact,
                        'registration_authority': fruit.registration_authority
                    }
                })
            return jsonify({
                'success': False, 
                'message': 'Invalid or inactive Fruit ID'
            })
    except Exception as e:
        print(f"Error verifying fruit ID: {e}")
        return jsonify({
            'success': False, 
            'error': 'Failed to verify Fruit ID'
        }), 500



# Add new route for deleting farmer products
@app.route('/farmer/product/<product_id>/delete', methods=['POST'])
def delete_farmer_product(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get farmer ID from session
        farmer_id = session['user_id']
        
        # Connect to database
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Check if product belongs to the farmer
        cursor.execute('''
            SELECT * FROM products 
            WHERE id = %s AND farmer_id = %s
        ''', (product_id, farmer_id))
        
        product = cursor.fetchone()
        
        if not product:
            return jsonify({'error': 'Product not found or unauthorized'}), 404
        
        # Delete the product
        cursor.execute('DELETE FROM products WHERE id = %s', (product_id,))
        connection.commit()
        
        # Clean up
        cursor.close()
        connection.close()
        
        return jsonify({'success': True, 'message': 'Product deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting product: {e}")
        return jsonify({'error': 'Failed to delete product'}), 500

@app.route('/get_farmer_sales_summary/<int:farmer_id>')
def get_farmer_sales_summary(farmer_id):
    try:
        # Verify farmer access
        if 'user_id' not in session or int(session['user_id']) != farmer_id:
            return jsonify({'error': 'Unauthorized'}), 401

        # Get all products count
        products_count = Product.query.filter_by(farmer_id=farmer_id).count()

        # Get all orders containing farmer's products
        total_earnings = 0
        active_orders = []
        delivered_count = 0
        
        # Query all orders
        orders = Order.query.all()
        for order in orders:
            farmer_total = 0
            farmer_items = []
            
            # Check each item in the order
            for item in order.items:
                product = Product.query.get(item.get('product_id'))
                if product and product.farmer_id == farmer_id:
                    item_total = float(item.get('price', 0)) * int(item.get('quantity', 0))
                    farmer_total += item_total
                    farmer_items.append(item)
            
            if farmer_items:
                # Track earnings from delivered orders
                if order.status == 'Delivered':
                    total_earnings += farmer_total
                    delivered_count += 1
                
                # Track active orders
                if order.status in ['Pending', 'Confirmed']:
                    active_orders.append({
                        'id': order.id,
                        'status': order.status,
                        'items': farmer_items,
                        'total_amount': farmer_total
                    })

        return jsonify({
            'success': True,
            'total_earnings': total_earnings,
            'active_orders': len(active_orders),
            'delivered_orders': delivered_count,
            'products_count': products_count,
            'active_orders_details': active_orders
        })

    except Exception as e:
        print(f"Error getting sales summary: {e}")
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@app.route('/reapply_product/<int:product_id>', methods=['POST'])
def reapply_product(product_id):
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        product = Product.query.get_or_404(product_id)
        
        # Verify the product belongs to the farmer
        if product.farmer_id != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Reset approval status
        product.is_approved = False
        product.is_rejected = False
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Product resubmitted for approval'
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error reapplying product: {e}")
        return jsonify({'error': str(e)}), 500

# Add KYC submission route
@app.route('/submit_kyc', methods=['POST'])
def submit_kyc():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        # Handle document upload
        if 'document_image' not in request.files:
            return jsonify({'error': 'No document uploaded'}), 400
            
        file = request.files['document_image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if file and allowed_file(file.filename):
            # Create kyc_docs directory if it doesn't exist
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'kyc_docs')
            os.makedirs(upload_folder, exist_ok=True)
            
            # Generate unique filename
            filename = secure_filename(f"kyc_{session['user_id']}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(upload_folder, filename)
            
            # Save file
            file.save(filepath)
            
            # Create KYC record
            kyc = KYC(
                user_id=session['user_id'],
                fruit_id=request.form['fruit_id'],
                city=request.form['city'],
                state=request.form['state'],
                country=request.form['country'],
                document_type=request.form['document_type'],
                document_number=request.form['document_number'],
                document_image=f"/static/product_images/kyc_docs/{filename}"
            )
            
            db.session.add(kyc)
            db.session.commit()

            # Send confirmation email to farmer
            user = User.query.get(session['user_id'])
            try:
                msg = Message('KYC Application Submitted - KisanSetu',
                             recipients=[user.email])
                msg.body = f'''
                Dear {user.name},

                Your KYC application has been submitted successfully!

                Application Details:
                - Document Type: {request.form['document_type']}
                - Fruit ID: {request.form['fruit_id']}
                - Submission Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}

                Your application is now pending admin approval. You will receive another email 
                once your application is processed.

                Thank you for choosing KisanSetu!

                Best regards,
                KisanSetu Team
                '''
                mail.send(msg)
            except Exception as e:
                print(f"Error sending confirmation email: {e}")

            # Send email to admin
            try:
                msg = Message('New Farmer KYC Submission - Action Required',
                            recipients=['ainewshub89@gmail.com'])  # Replace with admin email
                msg.body = f'''
                New farmer KYC submission requires approval:
                Name: {user.name}
                Email: {user.email}
                Phone: {user.phone}
                Fruit ID: {request.form['fruit_id']}
                Document Type: {request.form['document_type']}
                
                Please review the documents in the admin dashboard.
                '''
                mail.send(msg)
            except Exception as e:
                print(f"Error sending admin notification: {e}")
            
            return jsonify({'success': True, 'message': 'KYC submitted successfully'})
            
        return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/farmer/remove_product/<product_id>', methods=['POST', 'DELETE'])
def remove_farmer_product(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get farmer ID from session
        farmer_id = session['user_id']
        
        # Get product and verify ownership
        product = Product.query.filter_by(id=product_id, farmer_id=farmer_id).first()
        
        if not product:
            return jsonify({'error': 'Product not found or unauthorized'}), 404
        
        # Delete the product
        db.session.delete(product)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Product deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting product: {e}")
        return jsonify({'error': 'Failed to delete product'}), 500

@app.route('/kyc-verification')
def kyc_verification():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('kyc.html')

@app.route('/admin/pending-kyc')
@admin_required
def get_pending_kyc():
    try:
        # Join KYC with User and get pending verifications where user is not approved
        kyc_data = db.session.query(KYC, User)\
            .join(User)\
            .filter(KYC.status == 'pending')\
            .filter(User.is_approved == False)\
            .filter(User.user_type == 'farmer')\
            .all()
        
        result = []
        for kyc, user in kyc_data:
            # Get fruit details
            with db.engine.connect() as conn:
                fruit_result = conn.execute(text("""
                    SELECT * FROM fruit WHERE id = :fruit_id
                """), {"fruit_id": kyc.fruit_id}).fetchone()
                
                if fruit_result:
                    result.append({
                        'id': kyc.id,
                        'user_id': user.id,
                        'fruit_id': kyc.fruit_id,
                        'user_name': user.name,
                        'user_email': user.email,
                        'user_phone': user.phone,
                        'registration_date': user.created_at.isoformat(),
                        'document_type': kyc.document_type,
                        'document_number': kyc.document_number,
                        'document_image': kyc.document_image,
                        'fruit_data': {
                            'farm_location': fruit_result.farm_location,
                            'owner_name': fruit_result.owner_name,
                            'owner_contact': fruit_result.owner_contact,
                            'certification_type': fruit_result.certification_type
                        }
                    })
        
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching pending approvals: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/approve-farmer/<int:kyc_id>', methods=['POST'])
@admin_required
def approve_farmer_kyc(kyc_id):
    try:
        kyc = KYC.query.get_or_404(kyc_id)
        user = User.query.get(kyc.user_id)
        
        # Update both KYC and farmer status
        kyc.status = 'approved'
        user.is_approved = True
        db.session.commit()
        
        # Send combined approval email
        try:
            msg = Message('Farmer Registration & KYC Approved - KisanSetu',
                         recipients=[user.email])
            msg.body = f'''
            Dear {user.name},

            Congratulations! Your farmer registration and KYC verification have been approved.
            You can now login to KisanSetu and start listing your products.

            Your Details:
            Fruit ID: {kyc.fruit_id}
            Document Type: {kyc.document_type}
            Document Number: {kyc.document_number}

            Thank you for choosing KisanSetu!
            '''
            mail.send(msg)
        except Exception as e:
            print(f"Error sending approval email: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Farmer registration and KYC approved successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reject-kyc/<int:kyc_id>', methods=['POST'])
@admin_required
def reject_kyc(kyc_id):
    try:
        data = request.json
        kyc = KYC.query.get_or_404(kyc_id)
        user = User.query.get(kyc.user_id)
        
        # Update KYC status
        kyc.status = 'rejected'
        db.session.commit()
        
        # Send rejection email
        try:
            msg = Message('KYC Verification Rejected - KisanSetu',
                         recipients=[user.email])
            msg.body = f'''
            Dear {user.name},

            Your KYC verification has been rejected for the following reason:
            {data.get('reason', 'No reason provided')}

            Please update your KYC information and try again.

            If you have any questions, please contact support.

            Thank you for your understanding.
            '''
            mail.send(msg)
        except Exception as e:
            print(f"Error sending rejection email: {e}")
        
        return jsonify({
            'success': True,
            'message': 'KYC rejected successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)

        # Get product and check stock
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'}), 404

        # Get current cart item if exists
        cart_item = Cart.query.filter_by(
            user_id=session['user_id'],
            product_id=product_id
        ).first()

        # Calculate total requested quantity
        current_quantity = cart_item.quantity if cart_item else 0
        new_total_quantity = current_quantity + quantity

        # Check if product is out of stock
        if product.stock == 0:
            return jsonify({
                'success': False,
                'message': 'Product is out of stock',
                'available_stock': 0
            }), 400

        # Check if enough stock is available
        if new_total_quantity > product.stock:
            return jsonify({
                'success': False,
                'message': f'Cannot add more. Only {product.stock - current_quantity} more items available',
                'available_stock': product.stock,
                'current_cart_quantity': current_quantity,
                'remaining_available': product.stock - current_quantity
            }), 400

        # Update or create cart item
        if cart_item:
            cart_item.quantity = new_total_quantity
        else:
            cart_item = Cart(
                user_id=session['user_id'],
                product_id=product_id,
                quantity=quantity
            )
            db.session.add(cart_item)

        db.session.commit()

        # Get updated cart count
        cart_count = Cart.query.filter_by(user_id=session['user_id']).count()

        return jsonify({
            'success': True,
            'message': 'Product added to cart successfully',
            'cartCount': cart_count,
            'current_quantity': new_total_quantity,
            'available_stock': product.stock,
            'remaining_stock': product.stock - new_total_quantity
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error adding to cart: {e}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/cart/items')
def get_cart_items():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        # Get cart items with product details
        cart_items = db.session.query(Cart, Product)\
            .join(Product, Cart.product_id == Product.id)\
            .filter(Cart.user_id == session['user_id'])\
            .all()
            
        return jsonify([{
            'id': item.Cart.id,
            'product_id': item.Product.id,
            'name': item.Product.name,
            'price': float(item.Product.price),
            'quantity': item.Cart.quantity,
            'stock': item.Product.stock,
            'image_url': item.Product.image_url,
            'subtotal': float(item.Product.price * item.Cart.quantity)
        } for item in cart_items])
    except Exception as e:
        print(f"Error fetching cart items: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cart/update', methods=['POST'])
def update_cart():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 0)
        
        # Get product to check stock
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
            
        # Check if enough stock available
        if quantity > product.stock:
            return jsonify({
                'error': f'Only {product.stock} items available'
            }), 400
            
        # Update cart item
        cart_item = Cart.query.filter_by(
            user_id=session['user_id'],
            product_id=product_id
        ).first()
        
        if cart_item:
            cart_item.quantity = quantity
            db.session.commit()
            
        return jsonify({
            'success': True,
            'message': 'Cart updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/cart/remove/<int:product_id>', methods=['DELETE'])
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        Cart.query.filter_by(
            user_id=session['user_id'],
            product_id=product_id
        ).delete()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Item removed from cart'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/refill_stock/<int:product_id>', methods=['POST'])
def refill_stock(product_id):
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        new_stock = data.get('stock')

        if not new_stock or new_stock <= 0:
            return jsonify({'error': 'Invalid stock quantity'}), 400

        product = Product.query.filter_by(id=product_id, farmer_id=session['user_id']).first()
        if not product:
            return jsonify({'error': 'Product not found or unauthorized'}), 404

        product.stock = new_stock
        db.session.commit()

        return jsonify({'success': True, 'message': 'Stock refilled successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error refilling stock: {e}")
        return jsonify({'error': 'Failed to refill stock'}), 500

if __name__ == '__main__':
    pymysql.install_as_MySQLdb()
    init_db()
    add_profile_pic_column()  # Add this line
    app.run(debug=True)
