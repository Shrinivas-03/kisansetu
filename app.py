from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from supabase import create_client
from flask_mail import Mail, Message
import os, random, time
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Supabase Configuration
supabase = create_client(
    "https://cuzdmgynxhmtkxujyjey.supabase.co",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN1emRtZ3lueGhtdGt4dWp5amV5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDI4MjM2NTMsImV4cCI6MjA1ODM5OTY1M30.vjRAA-FKgfjFU9v4LoxfM1_BuzFZg1GkUEJKSxstHyU"
)

# Mail and file upload configs remain the same
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use Gmail's SMTP server
app.config['MAIL_PORT'] = 587  # Use port 587 for TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'ainewshub89@gmail.com'  # Updated email
app.config['MAIL_PASSWORD'] = 'xldaufoufokehnjl'  # Updated password
app.config['MAIL_DEFAULT_SENDER'] = 'ainewshub89@gmail.com'  # Updated sender email

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'N:\kisansetu\static\product_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif','webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Admin key configuration
app.config['ADMIN_REGISTRATION_KEY'] = os.environ.get('ADMIN_KEY', '1234')  # Use env var or default key
ADMIN_KEY_EMAIL = 'nadager990@gmail.com'  # Admin contact email

mail = Mail(app)

def init_db():
    try:
        # Tables are already created in Supabase
        print("Connected to Supabase successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

def get_user_by_email(email):
    try:
        response = supabase.table('users').select('*').eq('email', email).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

def create_user(user_data):
    try:
        response = supabase.table('users').insert(user_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None

def get_admin_by_email(email):
    try:
        response = supabase.table('admins').select('*').eq('email', email).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error fetching admin: {e}")
        return None

def create_admin(admin_data):
    try:
        # Validate admin data
        required_fields = ['name', 'email', 'password']
        if not all(admin_data.get(field) for field in required_fields):
            print("Missing required fields in admin data")
            return None

        # Insert admin record
        response = supabase.table('admins').insert({
            'name': admin_data['name'],
            'email': admin_data['email'].lower(),  # Normalize email
            'password': admin_data['password'],
            'phone': admin_data.get('phone', ''),
            'is_verified': admin_data.get('is_verified', False),
            'otp': admin_data.get('otp'),
            'created_at': datetime.utcnow().isoformat()
        }).execute()

        if not response.data:
            print("No data returned from admin creation")
            return None

        print(f"Admin created successfully: {response.data[0]}")
        return response.data[0]

    except Exception as e:
        print(f"Error creating admin: {str(e)}")
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if admin is logged in via session
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

class User:
    def __init__(self, data):
        self.id = data.get('id')
        self.name = data.get('name')
        self.email = data.get('email')
        self.phone = data.get('phone')
        self.user_type = data.get('user_type')
        self.is_verified = data.get('is_verified', False)
        self.is_approved = data.get('is_approved', False)
        self.created_at = data.get('created_at')
        self.otp = data.get('otp')

    @staticmethod
    def query():
        return UserQuery()

class UserQuery:
    @staticmethod
    def get(user_id):
        try:
            response = supabase.table('users').select('*').eq('id', user_id).execute()
            return User(response.data[0]) if response.data else None
        except Exception as e:
            print(f"Error in get: {e}")
            return None
    
    @staticmethod
    def filter_by(**kwargs):
        try:
            response = supabase.table('users').select('*')
            for key, value in kwargs.items():
                response = response.eq(key, value)
            result = response.execute()
            return [User(user) for user in result.data]
        except Exception as e:
            print(f"Error in filter_by: {e}")
            return []

class Product:
    def __init__(self, data):
        self.id = data.get('id')
        self.name = data.get('name')
        self.category = data.get('category')
        self.price = data.get('price')
        self.stock = data.get('stock', 0)
        self.description = data.get('description')
        self.image_url = data.get('image_url')
        self.farmer_id = data.get('farmer_id')
        self.is_approved = data.get('is_approved', False)
        self.is_rejected = data.get('is_rejected', False)
        self.created_at = data.get('created_at')

    @staticmethod
    def query():
        return ProductQuery()

class ProductQuery:
    @staticmethod
    def get(product_id):
        try:
            response = supabase.table('products').select('*').eq('id', product_id).execute()
            return Product(response.data[0]) if response.data else None
        except Exception as e:
            print(f"Error in get: {e}")
            return None

    @staticmethod
    def filter_by(**kwargs):
        try:
            response = supabase.table('products').select('*')
            for key, value in kwargs.items():
                response = response.eq(key, value)
            result = response.execute()
            return [Product(product) for product in result.data]
        except Exception as e:
            print(f"Error in filter_by: {e}")
            return []

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        user_type = request.form['user_type']  # 'customer' or 'farmer'

        # Check if email exists
        if check_existing_user(email):
            flash('Email already registered.')
            return redirect(url_for('signup'))

        # Generate OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Create user data
        user_data = {
            'name': name,
            'email': email,
            'password': generate_password_hash(password),
            'phone': phone,
            'user_type': user_type,
            'otp': otp,
            'is_verified': False,
            'is_approved': user_type != 'farmer'  # Only farmers need approval
        }

        # Create new user in Supabase
        try:
            response = supabase.table('users').insert(user_data).execute()
            new_user = response.data[0]
            
            if user_type == 'farmer':
                # Send admin notification
                try:
                    admin_msg = Message('New Farmer Registration - Action Required',
                                    recipients=['admin@kisansetu.com'])
                    admin_msg.body = f'''New farmer registration:
                    Name: {name}
                    Email: {email}
                    Phone: {phone}
                    
                    Please review and approve/reject from admin dashboard.
                    '''
                    mail.send(admin_msg)
                except Exception as e:
                    print(f"Error sending admin notification: {e}")

            # Send OTP email
            try:
                msg = Message('Your OTP for Kisansetu Registration',
                            sender=app.config['MAIL_DEFAULT_SENDER'],
                            recipients=[email])
                msg.body = f'Your OTP is: {otp}'
                mail.send(msg)
                flash('OTP sent to your email. Please verify your account.')
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Failed to send OTP. Please try again.')
                return redirect(url_for('signup'))

            # Set session
            session['temp_user_id'] = new_user['id']
            session['user_type'] = user_type
            return redirect(url_for('otp_verification'))

        except Exception as e:
            print(f"Error creating user: {e}")
            flash('Error creating account. Please try again.')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/otp-verification', methods=['GET', 'POST'])
def otp_verification():
    if request.method == 'POST':
        otp = request.form['otp']
        user_id = session.get('temp_user_id')

        # Use Supabase to get user
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        user = User(response.data[0]) if response.data else None

        if user and user.otp == otp:
            # Update user verification status
            supabase.table('users').update({
                'is_verified': True,
                'otp': None
            }).eq('id', user.id).execute()
            
            session['user_id'] = user.id
            
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

        # Get user from Supabase
        response = supabase.table('users').select('*').eq('email', email).execute()
        user = response.data[0] if response.data else None

        if user and check_password_hash(user['password'], password):
            if not user['is_verified']:
                flash('Please verify your email first.')
                return redirect(url_for('login'))

            if user['user_type'] == 'farmer' and not user['is_approved']:
                flash('Your farmer account is pending admin approval.')
                return redirect(url_for('login'))

            # Store user info in session
            session['user_id'] = user['id']
            session['user_type'] = user['user_type']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['user_phone'] = user['phone']
            session['user_profile_pic'] = user.get('profile_pic') or f"https://ui-avatars.com/api/?name={user['name']}&background=random"

            return redirect(url_for('farmer_dashboard' if user['user_type'] == 'farmer' else 'customer_dashboard'))

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

            # Prepare product data for Supabase
            product_data = {
                'name': request.form['name'],
                'category': request.form['category'],
                'price': float(request.form['price']),
                'stock': int(request.form['stock']),
                'description': request.form.get('description', ''),
                'image_url': image_url,
                'farmer_id': session['user_id'],
                'is_approved': False,
                'is_rejected': False,
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Insert product into Supabase
            response = supabase.table('products').insert(product_data).execute()
            if not response.data:
                flash('Error adding product. Please try again.')
                return redirect(url_for('add_product_form'))
            
            flash('Product added successfully! Waiting for admin approval.')
            return redirect(url_for('farmer_dashboard'))
            
        except Exception as e:
            print(f"Error adding product: {str(e)}")  # Debug log
            flash(f'Error adding product: {str(e)}')
            return redirect(url_for('add_product_form'))
    
    return render_template('farmer_product_form.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        admin = get_admin_by_email(email)
        if admin and check_password_hash(admin['password'], password):
            if not admin['is_verified']:
                # Generate and send OTP
                otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                
                # Update admin OTP in Supabase
                supabase.table('admins').update({'otp': otp}).eq('id', admin['id']).execute()
                
                # Send OTP email
                try:
                    msg = Message('Admin Login OTP - KisanSetu', recipients=[email])
                    msg.body = f'Your OTP for admin login is: {otp}'
                    mail.send(msg)
                    session['temp_admin_id'] = admin['id']
                    return redirect(url_for('admin_otp_verification'))
                except Exception as e:
                    flash('Error sending OTP.')
                    return redirect(url_for('admin_login'))
            
            session['admin_id'] = admin['id']
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid email or password')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')

@app.route('/admin-otp-verification', methods=['GET', 'POST'])
def admin_otp_verification():
    if 'temp_admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    if request.method == 'POST':
        response = supabase.table('admins').select('*').eq('id', session['temp_admin_id']).execute()
        admin = response.data[0] if response.data else None
        
        if admin and admin['otp'] == request.form['otp']:
            # Update admin verification status
            supabase.table('admins').update({
                'is_verified': True,
                'otp': None
            }).eq('id', admin['id']).execute()
            
            session['admin_id'] = admin['id']
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
            
        flash('Invalid OTP')
        return redirect(url_for('admin_otp_verification'))
        
    return render_template('admin_otp_verification.html')

@app.route('/admin')
def admin_redirect():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('admin_login'))

@app.route('/admin/signup')
def admin_signup():
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/get_pending_products')
@admin_required
def get_pending_products():
    try:
        print("Fetching pending products...")  # Debug log
        # Use ProductQuery to filter by is_approved=False, is_rejected=False
        products = ProductQuery.filter_by(is_approved=False, is_rejected=False)
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
            'created_at': p.created_at if p.created_at else None
        } for p in products]

        return jsonify(result)
    except Exception as e:
        print(f"Error fetching pending products: {e}")  # Debug log
        return jsonify({'error': str(e)}), 500

@app.route('/approve_product/<int:product_id>', methods=['POST'])
@admin_required
def approve_product(product_id):
    # Fetch product from Supabase
    resp = supabase.table('products').select('*').eq('id', product_id).execute()
    product = resp.data[0] if resp.data else None
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    # Update approval status
    supabase.table('products').update({'is_approved': True, 'is_rejected': False}).eq('id', product_id).execute()
    return jsonify({'message': 'Product approved successfully'})

@app.route('/revoke_product/<int:product_id>', methods=['POST'])
@admin_required
def revoke_product(product_id):
    try:
        resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        supabase.table('products').update({'is_approved': False}).eq('id', product_id).execute()
        return jsonify({'message': 'Product approval revoked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    try:
        resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        supabase.table('products').delete().eq('id', product_id).execute()
        return jsonify({'message': 'Product deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/reject_product/<int:product_id>', methods=['POST'])
@admin_required
def reject_product(product_id):
    try:
        resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        supabase.table('products').update({'is_approved': False, 'is_rejected': True}).eq('id', product_id).execute()
        return jsonify({'message': 'Product rejected successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/get_rejected_products')
@admin_required
def get_rejected_products():
    try:
        # Get rejected products and their farmers
        products = ProductQuery.filter_by(is_rejected=True)
        result = []
        for p in products:
            farmer = UserQuery.get(p.farmer_id)
            result.append({
                'id': p.id,
                'name': p.name,
                'category': p.category,
                'price': p.price,
                'stock': p.stock,
                'description': p.description or '',
                'image_url': p.image_url or '',
                'farmer_id': p.farmer_id,
                'farmerName': farmer.name if farmer else '',
                'created_at': p.created_at if p.created_at else None
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching rejected products: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_approved_products')
def get_approved_products():
    try:
        # Get approved products and their farmers
        products = ProductQuery.filter_by(is_approved=True, is_rejected=False)
        result = []
        for p in products:
            farmer = UserQuery.get(p.farmer_id)
            result.append({
                'id': str(p.id),
                'name': p.name,
                'category': p.category,
                'price': float(p.price),
                'stock': p.stock,
                'stock_status': 'out_of_stock' if p.stock == 0 else 'low_stock' if p.stock <= 5 else 'in_stock',
                'description': p.description or '',
                'image_url': p.image_url or '',
                'farmer_id': p.farmer_id,
                'farmerName': farmer.name if farmer else '',
                'created_at': p.created_at if p.created_at else None
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching approved products: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_registered_farmers')
@admin_required
def get_registered_farmers():
    try:
        # Use UserQuery to get all farmers
        farmers = UserQuery.filter_by(user_type='farmer')
        return jsonify([{
            'id': f.id,
            'name': f.name,
            'email': f.email,
            'phone': f.phone,
            # Remove .isoformat() since created_at is already a string
            'created_at': f.created_at if f.created_at else None,
            'is_verified': f.is_verified,
            'is_approved': f.is_approved
        } for f in farmers])
    except Exception as e:
        print(f"Error fetching registered farmers: {e}")
        return jsonify([])

@app.route('/get_pending_farmers')
@admin_required
def get_pending_farmers():
    try:
        # Use UserQuery to get all pending farmers
        pending_farmers = UserQuery.filter_by(user_type='farmer', is_approved=False)
        return jsonify([{
            'id': f.id,
            'name': f.name,
            'email': f.email,
            'phone': f.phone,
            'created_at': f.created_at.isoformat() if f.created_at else None,
            'is_verified': f.is_verified,
            'is_approved': f.is_approved
        } for f in pending_farmers])
    except Exception as e:
        print(f"Error fetching pending farmers: {e}")
        return jsonify([])

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_route():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Get admin from Supabase
        response = supabase.table('admins').select('*').eq('email', email).execute()
        admin = response.data[0] if response.data else None

        if admin and check_password_hash(admin['password'], password):
            if not admin['is_verified']:
                # Generate and send OTP
                otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                
                # Update admin OTP in Supabase
                supabase.table('admins').update({'otp': otp}).eq('id', admin['id']).execute()
                
                # Send OTP email
                try:
                    msg = Message('Admin Login OTP - KisanSetu', recipients=[email])
                    msg.body = f'Your OTP for admin login is: {otp}'
                    mail.send(msg)
                    session['temp_admin_id'] = admin['id']
                    return redirect(url_for('admin_otp_verification'))
                except Exception as e:
                    flash('Error sending OTP.')
                    return redirect(url_for('admin_login'))

            session['admin_id'] = admin['id']
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid email or password')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')

@app.route('/admin/otp-verification', methods=['GET', 'POST'])
def admin_otp_verification_route():
    if 'temp_admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    if request.method == 'POST':
        response = supabase.table('admins').select('*').eq('id', session['temp_admin_id']).execute()
        admin = response.data[0] if response.data else None
        
        if admin and admin['otp'] == request.form['otp']:
            # Update admin verification status
            supabase.table('admins').update({
                'is_verified': True,
                'otp': None
            }).eq('id', admin['id']).execute()
            
            session['admin_id'] = admin['id']
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
            
        flash('Invalid OTP')
        return redirect(url_for('admin_otp_verification'))
        
    return render_template('admin_otp_verification.html')

@app.route('/admin')
def admin_redirect_route():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard_route():
    return render_template('admin_dashboard.html')

@app.route('/get_pending_products')
@admin_required
def get_pending_products_route():
    try:
        print("Fetching pending products...")  # Debug log
        # Use ProductQuery to filter by is_approved=False, is_rejected=False
        products = ProductQuery.filter_by(is_approved=False, is_rejected=False)
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
            'created_at': p.created_at if p.created_at else None
        } for p in products]

        return jsonify(result)
    except Exception as e:
        print(f"Error fetching pending products: {e}")  # Debug log
        return jsonify({'error': str(e)}), 500

@app.route('/approve_product/<int:product_id>', methods=['POST'])
@admin_required
def approve_product_route(product_id):
    # Fetch product from Supabase
    resp = supabase.table('products').select('*').eq('id', product_id).execute()
    product = resp.data[0] if resp.data else None
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    # Update approval status
    supabase.table('products').update({'is_approved': True, 'is_rejected': False}).eq('id', product_id).execute()
    return jsonify({'message': 'Product approved successfully'})

@app.route('/revoke_product/<int:product_id>', methods=['POST'])
@admin_required
def revoke_product_route(product_id):
    try:
        resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        supabase.table('products').update({'is_approved': False}).eq('id', product_id).execute()
        return jsonify({'message': 'Product approval revoked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product_route(product_id):
    try:
        resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        supabase.table('products').delete().eq('id', product_id).execute()
        return jsonify({'message': 'Product deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/reject_product/<int:product_id>', methods=['POST'])
@admin_required
def reject_product_route(product_id):
    try:
        resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        supabase.table('products').update({'is_approved': False, 'is_rejected': True}).eq('id', product_id).execute()
        return jsonify({'message': 'Product rejected successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/get_rejected_products')
@admin_required
def get_rejected_products_route():
    try:
        # Get rejected products and their farmers
        products = ProductQuery.filter_by(is_rejected=True)
        result = []
        for p in products:
            farmer = UserQuery.get(p.farmer_id)
            result.append({
                'id': p.id,
                'name': p.name,
                'category': p.category,
                'price': p.price,
                'stock': p.stock,
                'description': p.description or '',
                'image_url': p.image_url or '',
                'farmer_id': p.farmer_id,
                'farmerName': farmer.name if farmer else '',
                'created_at': p.created_at if p.created_at else None
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching rejected products: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_approved_products')
def get_approved_products_route():
    try:
        # Get approved products and their farmers
        products = ProductQuery.filter_by(is_approved=True, is_rejected=False)
        result = []
        for p in products:
            farmer = UserQuery.get(p.farmer_id)
            result.append({
                'id': str(p.id),
                'name': p.name,
                'category': p.category,
                'price': float(p.price),
                'stock': p.stock,
                'stock_status': 'out_of_stock' if p.stock == 0 else 'low_stock' if p.stock <= 5 else 'in_stock',
                'description': p.description or '',
                'image_url': p.image_url or '',
                'farmer_id': p.farmer_id,
                'farmerName': farmer.name if farmer else '',
                'created_at': p.created_at if p.created_at else None
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching approved products: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_registered_farmers')
@admin_required
def get_registered_farmers_route():
    try:
        # Use UserQuery to get all farmers
        farmers = UserQuery.filter_by(user_type='farmer')
        return jsonify([{
            'id': f.id,
            'name': f.name,
            'email': f.email,
            'phone': f.phone,
            # Remove .isoformat() since created_at is already a string
            'created_at': f.created_at if f.created_at else None,
            'is_verified': f.is_verified,
            'is_approved': f.is_approved
        } for f in farmers])
    except Exception as e:
        print(f"Error fetching registered farmers: {e}")
        return jsonify([])

@app.route('/get_pending_farmers')
@admin_required
def get_pending_farmers_route():
    try:
        # Use UserQuery to get all pending farmers
        pending_farmers = UserQuery.filter_by(user_type='farmer', is_approved=False)
        return jsonify([{
            'id': f.id,
            'name': f.name,
            'email': f.email,
            'phone': f.phone,
            'created_at': f.created_at.isoformat() if f.created_at else None,
            'is_verified': f.is_verified,
            'is_approved': f.is_approved
        } for f in pending_farmers])
    except Exception as e:
        print(f"Error fetching pending farmers: {e}")
        return jsonify([])

@app.route('/admin/pending-kyc')
@admin_required
def get_pending_kyc_route():
    try:
        # Fetch pending KYC records from Supabase
        kyc_response = supabase.table('kyc').select('*').eq('status', 'pending').execute()
        kyc_data = kyc_response.data if kyc_response.data else []
        result = []
        for kyc in kyc_data:
            user = UserQuery.get(kyc['user_id'])
            # Fetch fruit details from Supabase
            fruit_resp = supabase.table('fruit').select('*').eq('id', kyc['fruit_id']).execute()
            fruit = fruit_resp.data[0] if fruit_resp.data else None
            result.append({
                'id': kyc['id'],
                'user_id': kyc['user_id'],
                'fruit_id': kyc['fruit_id'],
                'user_name': user.name if user else '',
                'user_email': user.email if user else '',
                'user_phone': user.phone if user else '',
                # Use the string value directly, don't call .isoformat()
                'registration_date': user.created_at if user and user.created_at else None,
                'document_type': kyc['document_type'],
                'document_number': kyc['document_number'],
                'document_image': kyc['document_image'],
                'fruit_data': {
                    'farm_location': fruit['farm_location'] if fruit else '',
                    'owner_name': fruit['owner_name'] if fruit else '',
                    'owner_contact': fruit['owner_contact'] if fruit else '',
                    'certification_type': fruit['certification_type'] if fruit else ''
                }
            })
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching pending approvals: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/approve-farmer/<int:kyc_id>', methods=['POST'])
@admin_required
def approve_farmer_kyc_route(kyc_id):
    try:
        # Fetch KYC record from Supabase
        kyc_resp = supabase.table('kyc').select('*').eq('id', kyc_id).execute()
        kyc = kyc_resp.data[0] if kyc_resp.data else None
        if not kyc:
            return jsonify({'error': 'KYC record not found'}), 404

        user = UserQuery.get(kyc['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Update both KYC and farmer status in Supabase
        supabase.table('kyc').update({'status': 'approved'}).eq('id', kyc_id).execute()
        supabase.table('users').update({'is_approved': True}).eq('id', user.id).execute()

        # Send combined approval email
        try:
            msg = Message('Farmer Registration & KYC Approved - KisanSetu',
                         recipients=[user.email])
            msg.body = f'''
            Dear {user.name},

            Congratulations! Your farmer registration and KYC verification have been approved.
            You can now login to KisanSetu and start listing your products.

            Your Details:
            Fruit ID: {kyc['fruit_id']}
            Document Type: {kyc['document_type']}
            Document Number: {kyc['document_number']}

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
        print(f"Error in approve_farmer_kyc_route: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reject-kyc/<int:kyc_id>', methods=['POST'])
@admin_required
def reject_kyc_route(kyc_id):
    try:
        data = request.json
        # Fetch KYC record from Supabase
        kyc_resp = supabase.table('kyc').select('*').eq('id', kyc_id).execute()
        kyc = kyc_resp.data[0] if kyc_resp.data else None
        if not kyc:
            return jsonify({'error': 'KYC record not found'}), 404

        user = UserQuery.get(kyc['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Update KYC status in Supabase
        supabase.table('kyc').update({'status': 'rejected'}).eq('id', kyc_id).execute()

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
        print(f"Error in reject_kyc_route: {e}")
        return jsonify({'error': str(e)}), 500

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
        # Get cart items from Supabase
        cart_resp = supabase.table('cart').select('*').eq('user_id', session['user_id']).execute()
        cart_items = cart_resp.data if cart_resp.data else []
        
        if not cart_items:
            flash('Your cart is empty. Add items to proceed to checkout.')
            return redirect(url_for('cart'))
        
        # Get product details for cart items
        product_ids = [item['product_id'] for item in cart_items]
        products_resp = supabase.table('products').select('*').in_('id', product_ids).execute()
        products = {str(p['id']): p for p in (products_resp.data or [])}
        
        # Format cart items with product details
        formatted_items = []
        subtotal = 0
        for item in cart_items:
            product = products.get(str(item['product_id']))
            if product:
                item_subtotal = float(product['price']) * item['quantity']
                formatted_items.append({
                    'id': item['id'],
                    'product_id': product['id'],
                    'name': product['name'],
                    'price': float(product['price']),
                    'quantity': item['quantity'],
                    'subtotal': item_subtotal
                })
                subtotal += item_subtotal
        
        # Get user details from Supabase
        user_resp = supabase.table('users').select('*').eq('id', session['user_id']).execute()
        user = user_resp.data[0] if user_resp.data else None
        
        if not user:
            flash('User not found. Please log in again.')
            return redirect(url_for('login'))
        
        delivery_fee = 40  # Fixed delivery fee
        total = subtotal + delivery_fee
        
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
            product_resp = supabase.table('products').select('*').eq('id', item.get('product_id')).execute()
            product = product_resp.data[0] if product_resp.data else None
            
            if not product:
                return jsonify({
                    'success': False,
                    'message': f'Product not found'
                })
            
            if product['stock'] < item.get('quantity', 0):
                return jsonify({
                    'success': False,
                    'message': f'Not enough stock for {product["name"]}. Available: {product["stock"]}'
                })
            
            # Update stock in Supabase
            new_stock = product['stock'] - item.get('quantity', 0)
            supabase.table('products').update({'stock': new_stock}).eq('id', product['id']).execute()
        
        # Create new order in Supabase
        order_data = {
            'user_id': session['user_id'],
            'total_amount': data['total_amount'],
            'delivery_fee': data['delivery_fee'],
            'payment_method': data['payment_method'],
            'delivery_details': data['delivery_details'],
            'items': items,
            'status': 'Pending',
            'created_at': datetime.utcnow().isoformat(),
            'payment_status': 'Pending'
        }
        
        order_resp = supabase.table('orders').insert(order_data).execute()
        new_order = order_resp.data[0] if order_resp.data else None
        
        if not new_order:
            return jsonify({'error': 'Failed to create order'}), 500
        
        # Clear user's cart
        supabase.table('cart').delete().eq('user_id', session['user_id']).execute()
        
        # Generate order ID
        order_id = f"KS{new_order['id']:06d}"
        
        # Send order confirmation email
        try:
            user_resp = supabase.table('users').select('*').eq('id', session['user_id']).execute()
            user = user_resp.data[0] if user_resp.data else None
            
            if user and user.get('email'):
                msg = Message('Order Confirmation - KisanSetu',
                            recipients=[user['email']])
                msg.body = f'''
                Thank you for your order!
                
                Order ID: {order_id}
                Total Amount: ₹{data['total_amount']}
                Delivery Address: {data['delivery_details'].get('address', '')}
                
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
        # Fetch wishlist items from Supabase
        wishlist_resp = supabase.table('wishlists').select('*').eq('user_id', session['user_id']).execute()
        wishlist_items = wishlist_resp.data if wishlist_resp.data else []

        # Fetch all product IDs in wishlist
        product_ids = [item['product_id'] for item in wishlist_items]
        products = []
        if product_ids:
            products_resp = supabase.table('products').select('*').in_('id', product_ids).execute()
            products = products_resp.data if products_resp.data else []

        # Map product_id to product details
        product_map = {p['id']: p for p in products}

        # Build wishlist response
        result = []
        for item in wishlist_items:
            product = product_map.get(item['product_id'])
            if product:
                result.append({
                    'id': product['id'],
                    'name': product['name'],
                    'price': float(product['price']),
                    'category': product['category'],
                    'image_url': product.get('image_url', ''),
                    'description': product.get('description', ''),
                    'stock': product.get('stock', 0),
                    'added_on': item['created_at']
                })
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching wishlist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
def add_to_wishlist(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        # Check if product exists
        product_resp = supabase.table('products').select('id').eq('id', product_id).execute()
        if not product_resp.data:
            return jsonify({'error': 'Product not found'}), 404

        # Check if already in wishlist
        existing = supabase.table('wishlists').select('id').eq('user_id', session['user_id']).eq('product_id', product_id).execute()
        if existing.data:
            return jsonify({'success': True, 'message': 'Already in wishlist'})

        # Add to wishlist
        supabase.table('wishlists').insert({
            'user_id': session['user_id'],
            'product_id': product_id
        }).execute()

        # Get updated count
        count_resp = supabase.table('wishlists').select('id').eq('user_id', session['user_id']).execute()
        count = len(count_resp.data) if count_resp.data else 0

        return jsonify({
            'success': True,
            'message': 'Added to wishlist',
            'count': count
        })
    except Exception as e:
        print(f"Error adding to wishlist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/remove_from_wishlist/<int:product_id>', methods=['POST'])
def remove_from_wishlist(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        # Find the wishlist item
        existing = supabase.table('wishlists').select('id').eq('user_id', session['user_id']).eq('product_id', product_id).execute()
        if not existing.data:
            return jsonify({'error': 'Item not found in wishlist'}), 404

        wishlist_id = existing.data[0]['id']
        supabase.table('wishlists').delete().eq('id', wishlist_id).execute()

        # Get updated count
        count_resp = supabase.table('wishlists').select('id').eq('user_id', session['user_id']).execute()
        count = len(count_resp.data) if count_resp.data else 0

        return jsonify({
            'success': True,
            'message': 'Removed from wishlist',
            'count': count
        })
    except Exception as e:
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
        # Query the fruit table using Supabase
        response = supabase.table('fruit').select(
            'farm_size, farm_location, soil_type, irrigation_type, certification_type, owner_name, owner_contact, registration_authority, is_active'
        ).eq('id', fruit_id).execute()
        fruit = response.data[0] if response.data else None

        if fruit and fruit.get('is_active'):
            return jsonify({
                'success': True,
                'data': {
                    'farm_size': float(fruit['farm_size']),
                    'farm_location': fruit['farm_location'],
                    'soil_type': fruit['soil_type'],
                    'irrigation_type': fruit['irrigation_type'],
                    'certification_type': fruit['certification_type'],
                    'owner_name': fruit['owner_name'],
                    'owner_contact': fruit['owner_contact'],
                    'registration_authority': fruit['registration_authority']
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

@app.route('/get_farmer_sales_summary/<farmer_id>')
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
            farmer_total = 0;
            farmer_items = []
            
            # Check each item in the order
            for item in order.items:
                product = db.session.get(Product, item.get('product_id'))
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

            # Save KYC record to Supabase
            kyc_data = {
                'user_id': session['user_id'],
                'fruit_id': request.form['fruit_id'],
                'city': request.form['city'],
                'state': request.form['state'],
                'country': request.form['country'],
                'document_type': request.form['document_type'],
                'document_number': request.form['document_number'],
                'document_image': f"/static/product_images/kyc_docs/{filename}",
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
            kyc_response = supabase.table('kyc').insert(kyc_data).execute()
            kyc_record = kyc_response.data[0] if kyc_response.data else None
            if not kyc_record:
                print("Failed to insert KYC record in Supabase")
                return jsonify({'error': 'Failed to submit KYC. Please try again.'}), 500

            # Send confirmation email to farmer
            user = UserQuery.get(session['user_id'])
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
        print(f"Error submitting KYC: {e}")
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

def check_existing_user(email):
    """Check if a user with the given email already exists in Supabase."""
    try:
        response = supabase.table('users').select('id').eq('email', email).execute()
        return bool(response.data)
    except Exception as e:
        print(f"Error checking existing user: {e}")
        return False

@app.route('/cart/add', methods=['POST'])
def add_to_cart_route():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
        
    try:
        data = request.json
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))

        # Get current UTC time
        current_time = datetime.now(timezone.utc)

        # Validate product existence and stock
        product_resp = supabase.table('products').select('*').eq('id', product_id).execute()
        product = product_resp.data[0] if product_resp.data else None
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
            
        if product['stock'] < quantity:
            return jsonify({'error': 'Not enough stock available'}), 400

        # Check if product already in cart
        cart_resp = supabase.table('cart').select('*').eq('user_id', session['user_id']).eq('product_id', product_id).execute()
        existing_item = cart_resp.data[0] if cart_resp.data else None

        if existing_item:
            # Update quantity if already in cart
            new_quantity = existing_item['quantity'] + quantity
            supabase.table('cart').update({
                'quantity': new_quantity,
                'updated_at': current_time.isoformat()
            }).eq('id', existing_item['id']).execute()
        else:
            # Add new cart item
            supabase.table('cart').insert({
                'user_id': session['user_id'],
                'product_id': product_id,
                'quantity': quantity,
                'created_at': current_time.isoformat(),
                'updated_at': current_time.isoformat()
            }).execute()

        # Get updated cart count - fixed to use len() instead of count
        count_resp = supabase.table('cart').select('*').eq('user_id', session['user_id']).execute()
        cart_count = len(count_resp.data) if count_resp.data else 0

        return jsonify({
            'message': 'Product added to cart successfully',
            'cart_count': cart_count
        })

    except Exception as e:
        print(f"Error adding to cart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cart/items')
def get_cart_items():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
        
    try:
        # Get cart items with product details
        cart_resp = supabase.table('cart').select('*').eq('user_id', session['user_id']).execute()
        cart_items = cart_resp.data if cart_resp.data else []
        
        if not cart_items:
            return jsonify([])
            
        # Get all product IDs in cart
        product_ids = [item['product_id'] for item in cart_items]
        
        # Fetch products in a single query
        products_resp = supabase.table('products').select('*').in_('id', product_ids).execute()
        products = products_resp.data if products_resp.data else []
        
        # Create product lookup map
        product_map = {p['id']: p for p in products}
        
        # Build response with product details
        result = []
        for item in cart_items:
            product = product_map.get(item['product_id'])
            if product:
                result.append({
                    'cart_id': item['id'],
                    'product_id': product['id'],
                    'name': product['name'],
                    'price': float(product['price']),
                    'quantity': item['quantity'],
                    'stock': product['stock'],
                    'image_url': product.get('image_url', ''),
                    'description': product.get('description', ''),
                    'category': product['category'],
                    'subtotal': float(product['price']) * item['quantity']
                })
        
        return jsonify(result)

    except Exception as e:
        print(f"Error fetching cart items: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cart/remove/<int:cart_id>', methods=['POST'])
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        # First verify the cart item belongs to the user and get it
        cart_resp = supabase.table('cart').select('*').eq('id', cart_id).eq('user_id', session['user_id']).execute()
        if not cart_resp.data:
            return jsonify({'error': 'Cart item not found or unauthorized'}), 404

        # Delete the cart item
        supabase.table('cart').delete().eq('id', cart_id).execute()

        # Get updated cart count - get all remaining cart items for
        remaining_cart_resp = supabase.table('cart').select('*').eq('user_id', session['user_id']).execute()
        cart_count = len(remaining_cart_resp.data) if remaining_cart_resp.data else 0

        return jsonify({
            'success': True,
            'message': 'Item removed from cart',
            'cart_count': cart_count
        })

    except Exception as e:
        print(f"Error removing from cart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cart/update/<int:cart_id>', methods=['POST'])
def update_cart_quantity(cart_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        data = request.json
        change = data.get('change', 0)  # Can be 1 or -1
        
        # Get current cart item
        cart_resp = supabase.table('cart').select('*').eq('id', cart_id).eq('user_id', session['user_id']).execute()
        cart_item = cart_resp.data[0] if cart_resp.data else None
        
        if not cart_item:
            # Get product ID from data or cart history
            product_id = data.get('product_id')
            if not product_id:
                # Try to get the last cart item's product ID
                last_cart = supabase.table('cart').select('product_id').eq('user_id', session['user_id']).order('created_at', desc=True).limit(1).execute()
                product_id = last_cart.data[0]['product_id'] if last_cart.data else None
            
            if product_id:
                product_resp = supabase.table('products').select('*').eq('id', product_id).execute()
                product = product_resp.data[0] if product_resp.data else None
                
                if product:
                    # Create new cart item with quantity 1
                    new_cart_item = {
                        'user_id': session['user_id'],
                        'product_id': product_id,
                        'quantity': 1,
                        'created_at': datetime.now(timezone.utc).isoformat(),
                        'updated_at': datetime.now(timezone.utc).isoformat()
                    }
                    
                    cart_resp = supabase.table('cart').insert(new_cart_item).execute()
                    cart_item = cart_resp.data[0]
                    
                    return jsonify({
                        'success': True,
                        'message': 'Item added to cart',
                        'quantity': 1,
                        'subtotal': float(product['price']),
                        'unit_price': float(product['price']),
                        'cart_id': cart_item['id']
                    })

        # Calculate new quantity
        new_quantity = cart_item['quantity'] + change

        if new_quantity < 1:
            return jsonify({'error': 'Quantity cannot be less than 1'}), 400

        # Get product details to check stock
        product_resp = supabase.table('products').select('*').eq('id', cart_item['product_id']).execute()
        product = product_resp.data[0] if product_resp.data else None
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        if product['stock'] < new_quantity:
            return jsonify({
                'error': 'Not enough stock available',
                'available_stock': product['stock']
            }), 400

        # Update cart item quantity
        supabase.table('cart').update({
            'quantity': new_quantity,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }).eq('id', cart_id).execute()

        # Calculate new subtotal
        subtotal = float(product['price']) * new_quantity

        return jsonify({
            'success': True,
            'message': 'Quantity updated successfully',
            'quantity': new_quantity,
            'subtotal': subtotal,
            'unit_price': float(product['price'])
        })

    except Exception as e:
        print(f"Error updating cart quantity: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/test-email')
def test_email():
    try:
        msg = Message('Test Email from KisanSetu',
                     recipients=['your_email@example.com'])  # Replace with your email
        msg.body = 'This is a test email from the KisanSetu application.'
        mail.send(msg)
        return 'Test email sent successfully!'
    except Exception as e:
        return f'Error sending test email: {str(e)}'

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)


