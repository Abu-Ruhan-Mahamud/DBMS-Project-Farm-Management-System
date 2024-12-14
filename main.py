from flask import Flask,render_template,session,request,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager
from flask_login import login_required,current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import jsonify
from sqlalchemy.sql import func
from collections import defaultdict
import re
import os


#db connection
local_server= True
app = Flask(__name__)
app.secret_key='ruhan'


#unique user access
login_manager=LoginManager(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

UPLOAD_FOLDER = 'static/uploads/profile_pictures'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size 16MB


# app.config['SQLALCHEMY_DATABASE_URL']='mysql://username:password@localhost/databas_table_name'
app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:@localhost/project'
db=SQLAlchemy(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#db models
class Test(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(100))



class Trig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.String(100))
    action = db.Column(db.String(100))
    timestamp = db.Column(db.String(100))
    message = db.Column(db.String(255))  # Add message column
    entity_type = db.Column(db.String(50))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(1000))
    role = db.Column(db.String(50), default="customer")  # Add this line



class Register(db.Model):
    rid = db.Column(db.Integer, primary_key=True)
    farmername = db.Column(db.String(50))
    number = db.Column(db.String(50))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(50))
    phonenumber = db.Column(db.String(50))
    address = db.Column(db.String(50))
    profile_picture = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))  # Add ondelete
    products = db.relationship('Addagroproducts', backref='owner_farmer', cascade='all, delete-orphan')  # Changed backref to 'owner_farmer'


class Addagroproducts(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(50))
    productname = db.Column(db.String(100))
    productdesc = db.Column(db.String(300))
    price = db.Column(db.Integer)
    farmer_id = db.Column(db.Integer, db.ForeignKey('register.rid', ondelete='CASCADE'))  # Foreign key to Register
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))  # Foreign key to User
    farming = db.Column(db.String(50))  # Add the farming type column here

    # Relationship with User and Register models
    user = db.relationship('User', backref='user_products')  # Changed backref to 'user_products'
    farmer = db.relationship('Register', backref='owner_farmer')  # 'owner_farmer' remains unchanged



@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/farmerdetails', methods=['GET'])
@login_required
def farmerdetails():
    if current_user.role != 'farmer':
        flash("Register as a farmer first", "danger")
        return redirect(url_for('register'))
    
    # Fetch unique divisions from the database
    divisions = db.session.query(Register.address).distinct().all()
    divisions = [d[0] for d in divisions]

    # Get the selected division from query parameters
    selected_division = request.args.get('division')

    if selected_division:
        # Filter farmers based on the selected division
        query = Register.query.filter_by(address=selected_division).all()
    else:
        # Fetch all farmers if no division is selected
        query = Register.query.all()

    return render_template('farmerdetails.html', query=query, divisions=divisions)


@app.route('/agroproducts', methods=['GET'])
@login_required
def agroproducts():
    # Get the current user (assuming you use Flask-Login)
    user = current_user

    # Fetch all unique farming types from the database
    farming_types = db.session.query(Addagroproducts.farming).distinct().all()
    farming_types = [f[0] for f in farming_types]

    # Get the selected farming type from query parameters
    selected_farming_type = request.args.get('farming', '')

    # Retrieve products based on the selected farming type
    if selected_farming_type:
        products = Addagroproducts.query.filter_by(farming=selected_farming_type).all()
    else:
        products = Addagroproducts.query.all()

    product_details = []
    user_products = {}  # Dictionary to track products added by the current user

    for product in products:
        farmer = Register.query.filter_by(rid=product.farmer_id).first()
        if farmer:
            product_details.append({
                'product': product,
                'address': farmer.address  # Include the farmer's address
            })

            # Track whether the product belongs to the current user
            if product.user_id == user.id:
                user_products[product.pid] = True  # This product was added by the current user
            else:
                user_products[product.pid] = False  # This product was not added by the current user

    # Pass farming types, selected type, product details, and user_products to the template
    return render_template(
        'agroproducts.html',
        farming_types=farming_types,
        selected_farming_type=selected_farming_type,
        product_details=product_details,
        user_products=user_products
    )




@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in before editing
def edit_profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if password is provided (for update)
        if password:
            hashed_password = generate_password_hash(password)
        else:
            hashed_password = current_user.password  # Keep old password if not updated

        current_user.username = username
        current_user.email = email
        current_user.password = hashed_password

        db.session.commit()  # Save changes to database

        flash("Profile updated successfully!", "success")
        return redirect(url_for('edit_profile'))  # Redirect to the same page to show updated data

    # For GET request, just render the profile edit form
    return render_template('edit_profile.html', user=current_user)



@app.route('/addagroproduct', methods=['POST', 'GET'])
@login_required
def addagroproduct():
    if current_user.role != 'farmer':
        flash("Only farmers can add products", "danger")
        return redirect(url_for('index'))

    farmer = Register.query.filter_by(user_id=current_user.id).first()
    if not farmer:
        flash("Please complete your farmer registration first.", "warning")
        return redirect(url_for('register'))

    if request.method == "POST":
        productname = request.form.get('productname')
        productdesc = request.form.get('productdesc')
        price = request.form.get('price')
        farming_type = request.form.get('farming')

        if not price.isdigit() or int(price) <= 0 or int(price) > 5000:
            flash("Price must be a positive value and less than or equal to 5000.", "warning")
            return render_template('addagroproducts.html', farmer=farmer, user_email=current_user.email)

        product = Addagroproducts(
            username=farmer.farmername,
            email=current_user.email,
            productname=productname,
            productdesc=productdesc,
            price=int(price),
            farmer_id=farmer.rid,
            user_id=current_user.id,
            farming=farming_type
        )
        db.session.add(product)
        db.session.commit()

        # Log product addition
        log_action(user_id=current_user.id, farmer_id=farmer.rid, product_id=product.pid, action="CREATE", message=f"Farmer {farmer.farmername} added product {productname}.")

        flash("Product Added", "info")
        return redirect('/agroproducts')

    return render_template('addagroproducts.html', farmer=farmer, user_email=current_user.email)




@app.route("/delete/<string:rid>",methods=['POST','GET'])
@login_required
def delete(rid):
    # db.engine.execute(f"DELETE FROM `register` WHERE `register`.`rid`={rid}")
    post=Register.query.filter_by(rid=rid).first()
    if post.user_id != current_user.id:
        flash("You are not authorized to delete this farmer profile.", "danger")
        return redirect('/farmerdetails')
    db.session.delete(post)
    db.session.commit()
    log_action(user_id=current_user.id, farmer_id=post.rid, action="DELETE", message=f"User {current_user.username} deleted farmer profile.")
    flash("Slot Deleted Successful","warning")
    return redirect('/farmerdetails')

@app.route('/edit_farmer_profile/<int:rid>', methods=['POST', 'GET'])
@login_required
def edit_farmer_profile(rid):
    # Fetch the farmer details from the database
    farmer = Register.query.get_or_404(rid)

    # Ensure the current user is authorized to edit this profile
    if farmer.user_id != current_user.id:
        flash("You are not authorized to edit this farmer profile.", "danger")
        return redirect('/farmerdetails')

    if request.method == "POST":
        # Get updated farmer details from the form
        farmername = request.form.get('farmername')
        number = request.form.get('number')
        age = request.form.get('age')
        gender = request.form.get('gender')
        phonenumber = request.form.get('phonenumber')
        address = request.form.get('address')
        file = request.files.get('profile_picture')  # Get the uploaded file

        # Update the farmer details
        farmer.farmername = farmername
        farmer.number = number
        farmer.age = int(age)
        farmer.gender = gender
        farmer.phonenumber = phonenumber
        farmer.address = address

        # Handle profile picture upload
        if file and allowed_file(file.filename):
            # Delete the old profile picture if it exists
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], farmer.profile_picture)
            if farmer.profile_picture and os.path.exists(old_file_path):
                os.remove(old_file_path)

            # Save the new file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Update the profile picture in the database
            farmer.profile_picture = filename

        db.session.commit()  # Commit changes to the database

        # Log the action
        log_action(
            user_id=current_user.id,
            farmer_id=farmer.rid,
            action="UPDATE",
            message=f"User {current_user.username} updated farmer profile."
        )

        flash("Farmer profile updated successfully.", "success")
        return redirect('/farmerdetails')

    return render_template('edit_farmer_profile.html', farmer=farmer)




@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Email validation regex
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash("Invalid email format. Please enter a valid email address.", "warning")
            return render_template('signup.html')

        # Check if email already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email Already Exists", "warning")
            return render_template('signup.html')

        encpassword = generate_password_hash(password)
        new_user = User(username=username, email=email, password=encpassword)
        db.session.add(new_user)
        db.session.commit()

        # Log registration
        log_action(user_id=new_user.id, action="CREATE", message=f"User {username} signed up successfully.")

        flash("Signup Success, Please Login", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')





@app.route('/login',methods=['POST','GET'])
def login():
    if request.method == "POST":
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password,password):
            login_user(user)

            log_action(user_id=user.id, action="LOGIN", message=f"User {user.username} logged in.")
            flash("Login Success","primary")
            return redirect(url_for('index'))
        else:
            flash("invalid credentials","warning")
            return render_template('login.html')    

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    log_action(user_id=current_user.id, action="LOGOUT", message=f"User {current_user.username} logged out.")
    logout_user()
    flash("Logout SuccessFul","warning")
    return redirect(url_for('login'))





@app.route('/register', methods=['POST', 'GET'])
@login_required
def register():
    existing_farmer = Register.query.filter_by(user_id=current_user.id).first()

    if existing_farmer:
        flash("You have already registered as a farmer.", "warning")
        return redirect('/farmerdetails')

    if request.method == "POST":
        # Get form data
        farmername = request.form.get('farmername')
        number = request.form.get('number')
        age = request.form.get('age')
        gender = request.form.get('gender')
        phonenumber = request.form.get('phonenumber')
        address = request.form.get('address')
        file = request.files['profile_picture']  # Get the uploaded file

        # Validate the file
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)  # Save the file
        else:
            flash("Invalid file type. Only images are allowed.", "danger")
            return render_template('register.html')

        # Update the farmer details
        current_user.role = 'farmer'
        db.session.commit()

        query = Register(
            farmername=farmername,
            number=number,
            age=int(age),
            gender=gender,
            phonenumber=phonenumber,
            address=address,
            profile_picture=filename,  # Save the filename in the database
            user_id=current_user.id
        )
        db.session.add(query)
        db.session.commit()

        log_action(user_id=current_user.id, farmer_id=query.rid, action="REGISTER", message=f"User {current_user.username} registered as a farmer.")
        flash("Farmer details added, you can now add products.", "success")
        return redirect('/farmerdetails')

    return render_template('register.html')





@app.route('/delete_product/<int:pid>', methods=['POST'])
@login_required
def delete_product(pid):
    product = Addagroproducts.query.filter_by(pid=pid).first()
    if product:
        # Retrieve the current user's farmer details
        farmer = Register.query.filter_by(user_id=current_user.id).first()

        # Check ownership by comparing the farmer_id of the product with the current user's farmer_id
        if product.farmer_id == farmer.rid:
            db.session.delete(product)
            db.session.commit()
            log_action(user_id=current_user.id, farmer_id=farmer.rid, product_id=product.pid, action="DELETE", message=f"Farmer {farmer.farmername} deleted product {product.productname}.")
            flash("Product deleted successfully.", "success")
        else:
            flash("You are not authorized to delete this product.", "danger")
    else:
        flash("Product not found.", "warning")
    return redirect(url_for('agroproducts'))



@app.route('/test')
def test():
    try:
        Test.query.all()
        return 'My database is Connected'
    except:
        return 'My db is not Connected'
    

@app.route('/myproducts', methods=['GET', 'POST'])
@login_required
def myproducts():
    # Check if the current user has a farmer registration
    farmer = Register.query.filter_by(user_id=current_user.id).first()
    if not farmer:
        flash("You need to register as a farmer first to manage your products.", "warning")
        return redirect(url_for('register'))  # Redirect to the registration page if not a farmer

    # Query products added by the current user based on their farmer ID
    user_products = Addagroproducts.query.filter_by(farmer_id=farmer.rid).all()

    if request.method == 'POST':
        # Get the data from the form
        productname = request.form.get('productname')
        productdesc = request.form.get('productdesc')
        price = request.form.get('price')
        farming_type = request.form.get('farming')

        # Validate price
        if not price.isdigit() or int(price) <= 0 or int(price) > 5000:
            flash("Price must be a positive value and less than or equal to 5000.", "warning")
            return render_template('myproducts.html', products=user_products)

        # Add the new product
        new_product = Addagroproducts(
            username=farmer.farmername,  # Use farmer's name
            email=current_user.email,  # Use the logged-in user's email
            productname=productname,
            productdesc=productdesc,
            price=int(price),
            farmer_id=farmer.rid,
            user_id=current_user.id,
            farming=farming_type
        )

        db.session.add(new_product)
        db.session.commit()
        flash("New Product Added", "success")
        return redirect(url_for('myproducts'))  # Redirect to reload the page and show the new product

    return render_template('myproducts.html', products=user_products)





@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user  # Access the logged-in user directly with current_user
    if not user:
        flash('You are not logged in. Please log in to delete your account.', 'danger')
        return redirect(url_for('login'))  # Ensure the user is logged in
     

    log_action(user_id=user.id, action="DELETE", message=f"User {user.username} deleted their profile.")

    # Check if the user has a related farmer profile
    related_farmer = Register.query.filter_by(user_id=user.id).first()

    # Delete associated agro-products if they exist
    if related_farmer:
        Addagroproducts.query.filter_by(user_id=user.id).delete()  # Delete products linked to the user
        db.session.delete(related_farmer)  # Delete the farmer record

    # Log the action (optional, but can help track the deletion)
    log_action(user.id, "DELETE", f"User {user.username} deleted their profile.")

    # Now delete the user account
    db.session.delete(user)
    db.session.commit()

    # Log the user out and notify them
    logout_user()
    flash("Your profile and related data have been deleted.", "success")

    # Redirect to the login page (or sign-up page if you prefer)
    return redirect(url_for('login'))


@app.route('/my_farmer_profile')
@login_required
def my_farmer_profile():
    # Query the current user's farmer profile
    farmer = Register.query.filter_by(user_id=current_user.id).first()
    return render_template('myfarmerprofile.html', farmer=farmer)



@app.route("/edit_product/<int:pid>", methods=['POST', 'GET'])
@login_required
def edit_product(pid):
    product = Addagroproducts.query.filter_by(pid=pid).first()

    if request.method == "POST":
        productname = request.form.get('productname')
        productdesc = request.form.get('productdesc')
        price = request.form.get('price')
        farming = request.form.get('farming')

        if not price.isdigit() or int(price) < 0 or int(price) > 5000:
            flash("Price must be a number between 0 and 5000.", "warning")
            return render_template('edit_product.html', product=product)

        product.productname = productname
        product.productdesc = productdesc
        product.price = int(price)
        product.farming = farming
        db.session.commit()

        # Log product update
        log_action(user_id=current_user.id, farmer_id=product.rid, product_id=product.pid, action="UPDATE", message=f"Farmer {product.farmername} updated product {product.productname}.")

        flash("Product updated successfully.", "success")
        return redirect(url_for('myproducts'))

    return render_template('edit_product.html', product=product)


def log_action(user_id=None, farmer_id=None, product_id=None, action=None, message=None):
    """Logs an action to the Trig table."""
    timestamp = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p') 
    log_entry = Trig(
        fid=str(farmer_id) if farmer_id else str(user_id),  # If farmer_id exists, log it, else use user_id
        action=action,
        timestamp=timestamp,  # Current timestamp
        message=message
    )
    db.session.add(log_entry)
    db.session.commit()



@app.route('/logs')
@login_required
def view_logs():
    logs = Trig.query.filter_by(fid=current_user.id).order_by(Trig.timestamp.desc()).all()
    print(logs)
    return render_template('logs.html', logs=logs)









@app.route('/farmer_by_division')
def farmers_by_division():
    # Fetch all unique addresses from the Register table
    all_addresses = db.session.query(Register.address).distinct().all()

    # Example: List of all possible divisions you want to display
    # (this could be a list from another source if needed)
    all_possible_divisions = ['Chittagong', 'Dhaka', 'Barisal', 'Sylhet', 'Mymensingh', 'Rangpur', 'Rajshahi', 'Khulna']  # Example list of divisions

    # Initialize a defaultdict to count farmers in each division
    division_counts = defaultdict(int)

    # Count the number of farmers in each division (including those with zero farmers)
    for address in all_possible_divisions:
        division_counts[address] = db.session.query(Register).filter(Register.address == address).count()

    # Find the max and min division by farmer count
    max_division = max(division_counts.items(), key=lambda x: x[1], default=(None, 0))
    min_division = min(division_counts.items(), key=lambda x: x[1], default=(None, 0))

    return render_template('farmer_by_division.html', 
                           division_counts=division_counts, 
                           max_division=max_division, 
                           min_division=min_division)


@app.route('/products_by_farming_type')
def products_by_farming_type():
    # Fetch all unique farming types
    farming_types = db.session.query(Addagroproducts.farming).distinct().all()
    farming_types = [f[0] for f in farming_types]

    # Count products for each farming type
    product_counts = {}
    for farming_type in farming_types:
        count = Addagroproducts.query.filter_by(farming=farming_type).count()
        product_counts[farming_type] = count

    # Find the farming type with max and min products
    if product_counts:
        max_farming_type = max(product_counts.items(), key=lambda x: x[1])
        min_farming_type = min(product_counts.items(), key=lambda x: x[1])
    else:
        max_farming_type = (None, 0)
        min_farming_type = (None, 0)

    return render_template('products_by_farming_type.html', 
                           product_counts=product_counts, 
                           max_farming_type=max_farming_type, 
                           min_farming_type=min_farming_type)

    


app.run(debug=True)    
