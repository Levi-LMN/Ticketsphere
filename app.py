from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import uuid
from sqlalchemy.exc import IntegrityError
from flask import request
from flask_wtf import FlaskForm
from wtforms import StringField, DateTimeField, SelectField, SubmitField
from wtforms import StringField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional
from flask import render_template, url_for
from flask import render_template, make_response
import pdfkit
from wtforms import StringField, DateTimeField, SelectField, FloatField, SubmitField
from wtforms.validators import DataRequired, Optional
# Import necessary modules
from flask import send_file
import random
import string
from datetime import datetime
from flask import render_template, flash, redirect, url_for, request

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'retailsysx@gmail.com'
app.config['MAIL_PASSWORD'] = 'qecs yhcc gkeq nlee'
app.config['MAIL_DEFAULT_SENDER'] = 'retailsysx@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

app.config['SECRET_KEY'] = '@#@$@#'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    token = db.Column(db.String(100), unique=True)
    is_verified = db.Column(db.Boolean, default=False)
    driver_license = db.Column(db.String(20))  # Add driver-specific information
    sacco_role = db.Column(db.String(20))  # Add Sacco admin-specific information
    sacco_id = db.Column(db.Integer, db.ForeignKey('sacco.id'))  # ForeignKey to associate user with a Sacco

    def booked_tickets(self):
        return Ticket.query.filter_by(user=self).all()


# Sacco model
class Sacco(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    admins = db.relationship('User', backref='sacco', lazy=True)  # Relationship to associate Sacco with admins
    vehicles = db.relationship('Vehicle', backref='sacco', lazy=True)


# Vehicle model
class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    registration_plate = db.Column(db.String(20), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    sacco_id = db.Column(db.Integer, db.ForeignKey('sacco.id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Make the driver relationship nullable
    driver = db.relationship('User', backref='vehicles', lazy=True)  # Add the relationship definition


# Travel schedule model
class TravelSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    departure_location = db.Column(db.String(255), nullable=False)
    destination = db.Column(db.String(255), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    price = db.Column(db.Float, nullable=False)  # Add the price field
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    vehicle = db.relationship('Vehicle', backref='travel_schedules', lazy=True)


# Ticket model
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)  # Add this line for the ticket number field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tickets', lazy=True)
    travel_schedule_id = db.Column(db.Integer, db.ForeignKey('travel_schedule.id'), nullable=False)
    travel_schedule = db.relationship('TravelSchedule', backref='tickets', lazy=True)
    booking_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    seat_number = db.Column(db.String(20), nullable=True)
    price = db.Column(db.Float, nullable=True)
    # Add any other additional fields you want to store for a ticket

    def __repr__(self):
        return f"Ticket(id={self.id}, ticket_number={self.ticket_number}, user={self.user}, " \
               f"travel_schedule={self.travel_schedule}, booking_time={self.booking_time}, " \
               f"seat_number={self.seat_number}, price={self.price})"



# Admin registration form
class AdminRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'), ('sacco_admin', 'Sacco Admin'), ('driver', 'Driver'),
                                        ('admin', 'Admin')],
                       validators=[DataRequired()])
    submit = SubmitField('Register')


# User registration form
class UserRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


# Driver registration form
class DriverRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    driver_license = StringField('Driver License', validators=[Length(max=20)])
    submit = SubmitField('Register')


# Sacco admin registration form
class SaccoAdminRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    sacco_role = SelectField('Sacco Role', choices=[('admin', 'Sacco Admin'), ('employee', 'Sacco Employee')],
                             validators=[DataRequired()])
    submit = SubmitField('Register')


# Login flask form for all user
class UniversalLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# flask form to add sacco's
class SaccoForm(FlaskForm):
    name = StringField('Sacco Name', validators=[DataRequired()])
    admin = SelectField('Sacco Admin', coerce=int)  # Add this line for the admin field
    submit = SubmitField('Update Sacco')


# flask form to edit sacco info
class ManageSaccoForm(FlaskForm):
    sacco_id = StringField('Sacco ID', validators=[DataRequired()])
    sacco_name = StringField('Sacco Name', validators=[DataRequired()])
    admin_id = SelectField('Admin', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Update Sacco')


# flask form to add schedules
class TravelScheduleForm(FlaskForm):
    departure_location = StringField('Departure Location', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    departure_time = DateTimeField('Departure Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])  # Add the price field
    vehicle_id = SelectField('Select Vehicle', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Schedule')


# flask form to add vehicles
class VehicleForm(FlaskForm):
    make = StringField('Make', validators=[DataRequired()])
    model = StringField('Model', validators=[DataRequired()])
    registration_plate = StringField('Registration Plate', validators=[DataRequired()])
    capacity = IntegerField('Capacity', validators=[DataRequired()])
    driver_id = SelectField('Select Driver', coerce=int, validators=[Optional()])  # Use Optional instead of allow_blank
    submit = SubmitField('Add Vehicle')


class BookTicketForm(FlaskForm):
    seat_number = SelectField('Select Seat', coerce=int)
    submit = SubmitField('Book Ticket')

# Create the database tables
with app.app_context():
    db.create_all()

# flask load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define a custom 404 error handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


# Custom error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500


# Route to intentionally raise a server error
@app.route('/force_error')
def force_error():
    # Triggering a division by zero error
    result = 1 / 0
    return f"This won't be reached, due to the intentional error above: {result}"

# Under construction pages
@app.route('/about')
@app.route('/contact')
@app.route('/parcels')
@app.route('/bus_hire')
def under_construction():
    clicked_page = request.path[1:].capitalize()  # Extract page name from URL
    return render_template('under_construction.html', clicked_page=clicked_page)

# initial home route
@app.route('/')
@login_required
def home():
    if current_user.role == 'user':
        return redirect(url_for('user_dashboard'))
    elif current_user.role == 'sacco_admin':
        return redirect(url_for('sacco_admin_dashboard'))
    elif current_user.role == 'driver':
        return redirect(url_for('driver_dashboard'))
    elif current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid user role', 'danger')
        return redirect(url_for('logout'))

# route to send verification email
def send_verification_email(user):
    token = user.token
    subject = 'Verify Your Email'
    body = f'Thank you for registering! Please click the following link to verify your email: {url_for("verify", token=token, _external=True)} \n If you did not request it,you can safely ignore this email'

    msg = Message(subject, recipients=[user.email], body=body)
    mail.send(msg)

# route to verify token
@app.route('/verify/<token>')
@login_required  # Requires the user to be logged in to access this route
def verify(token):
    user = User.query.filter_by(token=token).first()

    if user:
        # Check if the verification link is not expired (you can adjust the duration)
        if datetime.utcnow() - user.date_created < timedelta(hours=24):
            # Mark the user as verified
            user.is_verified = True
            user.token = None
            db.session.commit()

            flash('Your email has been verified!', 'success')

            # If the user is already logged in, redirect to the profile page
            if current_user.is_authenticated:
                return redirect(url_for('profile'))
            else:
                flash('You email has been verified,you can now log in.', 'success')
                return redirect(url_for('login'))
        else:
            flash('The verification link has expired. Please register again.', 'danger')
            return redirect(url_for('register'))
    else:
        flash('Invalid verification link. Please register again.', 'danger')
        return redirect(url_for('register'))

# route to login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UniversalLoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')

            # Determine the role and redirect accordingly
            if user.role == 'user':
                return redirect(url_for('user_dashboard'))
            elif user.role == 'sacco_admin':
                return redirect(url_for('sacco_admin_dashboard'))
            elif user.role == 'driver':
                return redirect(url_for('driver_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    return render_template('login.html', form=form)

# route to logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# route to user profile
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

# route to user dashboard
@app.route('/user-dashboard')
@login_required
def user_dashboard():
    return render_template('user/user_dashboard.html', user=current_user)

# route to sacco admin dashboard
@app.route('/sacco-admin-dashboard')
@login_required
def sacco_admin_dashboard():
    sacco_admin = current_user

    # Check if the Sacco admin is assigned to a Sacco
    if sacco_admin.sacco:
        assigned_sacco = sacco_admin.sacco.name
        return render_template('sacco_admin/sacco_admin_dashboard.html', user=sacco_admin, assigned_sacco=assigned_sacco)
    else:
        flash('You are not assigned to any Sacco.', 'warning')
        return render_template('sacco_admin/sacco_admin_dashboard.html', user=sacco_admin)

# Route for the driver dashboard
@app.route('/driver_dashboard', methods=['GET', 'POST'])
@login_required
def driver_dashboard():
    # Retrieve the driver's assigned vehicle
    driver_vehicle = Vehicle.query.filter_by(driver=current_user).first()

    # Retrieve the travel schedules associated with the driver's vehicle
    if driver_vehicle:
        vehicle_travel_schedules = TravelSchedule.query.filter_by(vehicle=driver_vehicle).all()
    else:
        vehicle_travel_schedules = []

    # Retrieve the booked tickets for each travel schedule with user information
    booked_tickets = {}
    for schedule in vehicle_travel_schedules:
        tickets = Ticket.query.filter_by(travel_schedule=schedule).all()
        booked_tickets[schedule.id] = [(ticket, ticket.user) for ticket in tickets]

    # Calculate the remaining seats for each schedule
    remaining_seats = {}
    for schedule in vehicle_travel_schedules:
        booked_seats = len(booked_tickets.get(schedule.id, []))
        remaining_seats[schedule.id] = schedule.vehicle.capacity - booked_seats

    return render_template('driver/driver_dashboard.html', driver_vehicle=driver_vehicle,
                           vehicle_travel_schedules=vehicle_travel_schedules, booked_tickets=booked_tickets,
                           remaining_seats=remaining_seats)


# route to admin dashboard
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html', user=current_user)


# route to user management page
@app.route('/user-management')
@login_required
def user_management():
    if current_user.role == 'admin':
        # Fetch all users from the database
        all_users = User.query.all()
        return render_template('admin/user_management.html', users=all_users, user=current_user)
    else:
        flash('Access denied. You are not authorized to view this page.', 'danger')
        return redirect(url_for('home'))


# route to change roles
@app.route('/change-role/<int:user_id>', methods=['GET', 'POST'])
@login_required
def change_role(user_id):
    if current_user.role == 'admin':
        user = User.query.get(user_id)

        if user:
            if request.method == 'POST':
                new_role = request.form.get('new_role')
                user.role = new_role
                db.session.commit()
                flash(f'User role changed to {new_role} successfully!', 'success')
                return redirect(url_for('user_management'))

            return render_template('admin/change_role.html', user=user,
                                   user_roles=['user', 'sacco_admin', 'driver', 'admin'])
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('user_management'))
    else:
        flash('Access denied. You are not authorized to perform this action.', 'danger')
        return redirect(url_for('home'))

# route to register user
@app.route('/register/user', methods=['GET', 'POST'])
def register_user():
    form = UserRegistrationForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'danger')
            return redirect(url_for('register_user'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=hashed_password,
            role='user',
            token=str(uuid.uuid4())  # Generate a new token for verification
        )

        try:
            db.session.add(user)
            db.session.commit()

            # Send verification email
            send_verification_email(user)

            flash('Your account has been created! Please check your email for verification.', 'success')
            login_user(user)
            return redirect(url_for('home'))  # Redirect to the user's dashboard or another appropriate page
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register_user'))

    return render_template('user/register_user.html', form=form)

# route to register driver
@app.route('/register/driver', methods=['GET', 'POST'])
def register_driver():
    form = DriverRegistrationForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'danger')
            return redirect(url_for('register_driver'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=hashed_password,
            role='driver',
            driver_license=form.driver_license.data,  # Include driver-specific information
            token=str(uuid.uuid4())  # Generate a new token for verification
        )

        try:
            db.session.add(user)
            db.session.commit()

            # Send verification email
            send_verification_email(user)

            flash('Your driver account has been created! Please check your email for verification.', 'success')
            login_user(user)
            return redirect(url_for('home'))  # Redirect to the driver's dashboard or another appropriate page
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register_driver'))

    return render_template('driver/register_driver.html', form=form)

# route to register sacco admin
@app.route('/register/sacco_admin', methods=['GET', 'POST'])
def register_sacco_admin():
    form = SaccoAdminRegistrationForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'danger')
            return redirect(url_for('register_sacco_admin'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=hashed_password,
            role='sacco_admin',
            sacco_role=form.sacco_role.data,  # Include Sacco admin-specific information
            token=str(uuid.uuid4())  # Generate a new token for verification
        )

        try:
            db.session.add(user)
            db.session.commit()

            # Send verification email
            send_verification_email(user)

            flash('Your Sacco admin account has been created! Please check your email for verification.', 'success')
            login_user(user)
            return redirect(url_for('home'))  # Redirect to the Sacco admin's dashboard or another appropriate page
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register_sacco_admin'))

    return render_template('sacco_admin/register_sacco_admin.html', form=form)

# route to register admin
@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    form = AdminRegistrationForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'danger')
            return redirect(url_for('register_admin'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data,  # Include selected role
            token=str(uuid.uuid4())  # Generate a new token for verification
        )

        try:
            db.session.add(user)
            db.session.commit()

            # Send verification email
            send_verification_email(user)

            flash('Your admin account has been created! Please check your email for verification.', 'success')
            login_user(user)
            return redirect(url_for('home'))  # Redirect to the admin's dashboard or another appropriate page
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register_admin'))

    return render_template('admin/register_admin.html', form=form)

# route to authentication page
@app.route('/auth')
def auth():
    return render_template('auth.html')

# route to add sacco
@app.route('/add_sacco', methods=['GET', 'POST'])
@login_required
def add_sacco():
    # Ensure the current user is an admin before allowing them to add a Sacco
    if current_user.role != 'admin':
        flash('Permission denied. Only admin users can add Saccos.', 'danger')
        return redirect(url_for('home'))

    form = SaccoForm()

    # Dynamically generate choices for the admin field
    form.admin.choices = [(user.id, f'{user.first_name} {user.last_name}') for user in
                          User.query.filter_by(role='sacco_admin').all()]

    if form.validate_on_submit():
        sacco = Sacco(name=form.name.data)

        # Associate the selected Sacco admin with the new Sacco
        selected_admin_id = form.admin.data
        selected_admin = User.query.get_or_404(selected_admin_id)
        sacco.admins.append(selected_admin)

        db.session.add(sacco)
        db.session.commit()

        flash(f'Sacco "{form.name.data}" added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('admin/add_sacco.html', form=form)

# route to delete sacco
@app.route('/delete_sacco', methods=['GET', 'POST'])
@login_required
def delete_sacco():
    # Ensure the current user is an admin before allowing them to delete Saccos
    if current_user.role != 'admin':
        flash('Permission denied. Only admin users can delete Saccos.', 'danger')
        return redirect(url_for('home'))

    saccos = Sacco.query.all()
    form = SaccoForm()  # Instantiate your SaccoForm here

    if request.method == 'POST':
        sacco_id_to_delete = request.form.get('sacco_id')

        if sacco_id_to_delete:
            sacco = Sacco.query.get_or_404(int(sacco_id_to_delete))
            db.session.delete(sacco)
            db.session.commit()
            flash(f'Sacco "{sacco.name}" deleted successfully!', 'success')
            return redirect(url_for('delete_sacco'))

    return render_template('admin/delete_sacco.html', saccos=saccos, form=form)



# route to manage saccos
@app.route('/manage_saccos', methods=['GET', 'POST'])
@login_required
def manage_saccos():
    # Ensure the current user is an admin before allowing them to manage Saccos
    if current_user.role != 'admin':
        flash('Permission denied. Only admin users can manage Saccos.', 'danger')
        return redirect(url_for('home'))

    saccos = Sacco.query.all()

    # Create a form instance
    form = ManageSaccoForm()

    # Populate choices for the admin field
    form.admin_id.choices = [(user.id, f'{user.first_name} {user.last_name}') for user in
                             User.query.filter_by(role='sacco_admin').all()]

    if form.validate_on_submit():
        sacco_id = form.sacco_id.data
        sacco_name = form.sacco_name.data
        admin_id = form.admin_id.data

        # Update Sacco details
        sacco = Sacco.query.get_or_404(sacco_id)
        sacco.name = sacco_name
        sacco.admin_id = admin_id
        db.session.commit()

        flash(f'Sacco "{sacco.name}" details updated successfully.', 'success')
        return redirect(url_for('manage_saccos'))

    return render_template('admin/manage_saccos.html', saccos=saccos, form=form)


# Route to add travel schedules
@app.route('/add_schedule', methods=['GET', 'POST'])
@login_required
def add_schedule():
    if request.method == 'POST':
        departure_location = request.form.get('departure_location')
        destination = request.form.get('destination')
        departure_time = datetime.strptime(request.form.get('departure_time'), '%Y-%m-%dT%H:%M')

        # Create a new travel schedule associated with the current user's sacco
        sacco = current_user.sacco
        vehicle_id = request.form.get('vehicle_id')  # Assuming you have a form field for selecting a vehicle

        if sacco:
            if vehicle_id:
                vehicle = Vehicle.query.filter_by(id=vehicle_id, sacco=sacco).first()
                if vehicle:
                    new_schedule = TravelSchedule(
                        departure_location=departure_location,
                        destination=destination,
                        departure_time=departure_time,
                        price=request.form.get('price'),  # Add the price field
                        vehicle=vehicle
                    )

                    db.session.add(new_schedule)
                    db.session.commit()

                    flash('Schedule added successfully', 'success')
                    return redirect(
                        url_for('sacco_admin_dashboard'))  # Replace 'dashboard' with the route for your dashboard
                else:
                    flash('Invalid vehicle selected', 'error')
            else:
                flash('Please select a vehicle', 'error')
        else:
            flash('User is not associated with a sacco', 'error')

    # Render the form to add schedules
    sacco_vehicles = current_user.sacco.vehicles
    return render_template('sacco_admin/add_schedule.html', sacco_vehicles=sacco_vehicles)

# route to add vehicles by sacco admin
@app.route('/add_vehicle', methods=['GET', 'POST'])
@login_required
def add_vehicle():
    # Ensure the current user is a Sacco admin
    if current_user.role != 'sacco_admin':
        flash('Permission denied. Only Sacco admins can add vehicles.', 'danger')
        return redirect(url_for('home'))

    form = VehicleForm()

    # Populate the driver choices for the form
    form.driver_id.choices = [(user.id, f"{user.first_name} {user.last_name}") for user in
                              User.query.filter_by(role='driver').all()]

    if form.validate_on_submit():
        make = form.make.data
        model = form.model.data
        registration_plate = form.registration_plate.data
        capacity = form.capacity.data
        driver_id = form.driver_id.data

        # Check if the registration plate already exists
        existing_vehicle = Vehicle.query.filter_by(registration_plate=registration_plate).first()
        if existing_vehicle:
            flash('Vehicle with the same registration plate already exists. Please choose a different one.', 'danger')
            return render_template('sacco_admin/add_vehicle.html', form=form)

        vehicle = Vehicle(
            make=make,
            model=model,
            registration_plate=registration_plate,
            capacity=capacity,
            sacco=current_user.sacco  # Associate the vehicle with the Sacco admin's Sacco
        )

        # Associate the driver with the vehicle if a driver is selected
        if driver_id:
            driver = User.query.get(driver_id)
            vehicle.driver = driver

        try:
            db.session.add(vehicle)
            db.session.commit()
            flash('Vehicle added successfully!', 'success')
            return redirect(url_for('sacco_admin_dashboard'))
        except IntegrityError as e:
            db.session.rollback()
            flash('Error adding the vehicle. Please check your input and try again.', 'danger')
            app.logger.error(f"IntegrityError: {str(e)}")
            # You may want to log the error for further investigation

    return render_template('sacco_admin/add_vehicle.html', form=form)


# Route to view travel schedules for a Sacco admin
@app.route('/view_schedules')
@login_required
def view_schedules():
    sacco = current_user.sacco

    if sacco:
        schedules = TravelSchedule.query.join(Vehicle).filter_by(sacco=sacco).all()
        return render_template('sacco_admin/view_schedules.html', schedules=schedules)
    else:
        flash('User is not associated with a sacco', 'error')
        return redirect(url_for('sacco_admin_dashboard'))  # Replace 'dashboard' with the route for your dashboard


# route to view all schedules
@app.route('/schedules')
@login_required
def view_all_schedules():
    # Get unique locations and destinations from the database
    all_locations = set([schedule.departure_location for schedule in TravelSchedule.query.all()])
    all_destinations = set([schedule.destination for schedule in TravelSchedule.query.all()])

    # Retrieve filter parameters from the request
    filter_location = request.args.get('filter_location')
    filter_destination = request.args.get('filter_destination')
    filter_sacco_id = request.args.get('filter_sacco')

    # Query schedules based on filters
    query = TravelSchedule.query.join(Vehicle).join(Sacco)

    if filter_location:
        query = query.filter(TravelSchedule.departure_location == filter_location)

    if filter_destination:
        query = query.filter(TravelSchedule.destination == filter_destination)

    if filter_sacco_id:
        query = query.filter(Sacco.id == filter_sacco_id)

    schedules = query.all()

    # Pass all_saccos, all_locations, and all_destinations to the template for the filters
    all_saccos = Sacco.query.all()

    return render_template('user/schedules.html', schedules=schedules, all_saccos=all_saccos,
                           all_locations=all_locations, all_destinations=all_destinations)

# route to view vehicles by sacco admin
@app.route('/view_vehicles', methods=['GET'])
@login_required
def view_vehicles():
    # Ensure the current user is associated with a Sacco
    if not current_user.sacco:
        flash('You are not associated with a Sacco.', 'danger')
        return redirect(url_for('home'))

    # Retrieve all vehicles associated with the user's Sacco
    vehicles = Vehicle.query.filter_by(sacco=current_user.sacco).all()

    return render_template('sacco_admin/view_vehicles.html', vehicles=vehicles)




# route to view details about a specific schedule
@app.route('/schedule_details/<int:schedule_id>')
@login_required
def schedule_details(schedule_id):
    # Fetch the schedule details based on schedule_id
    schedule = TravelSchedule.query.get_or_404(schedule_id)

    return render_template('user/schedule_details.html', schedule=schedule)

# rote for checkout page with schedule id
@app.route('/checkout/<int:schedule_id>')
@login_required
def checkout(schedule_id):
    # Fetch the schedule details based on schedule_id
    schedule = TravelSchedule.query.get_or_404(schedule_id)

    return render_template('user/checkout.html', schedule=schedule)

# Function to generate a unique random ticket number
def generate_unique_ticket_number():
    while True:
        letters = ''.join(random.choices(string.ascii_uppercase, k=2))
        digits = ''.join(random.choices(string.digits, k=4))
        ticket_number = f"{letters}{digits}"

        # Check if the generated ticket number is unique in the Ticket model
        if not Ticket.query.filter_by(ticket_number=ticket_number).first():
            return ticket_number

# Route to book a ticket
@app.route('/book_ticket/<int:schedule_id>', methods=['GET', 'POST'])
@login_required
def book_ticket(schedule_id):
    travel_schedule = TravelSchedule.query.get_or_404(schedule_id)
    form = BookTicketForm()

    booked_seat_numbers = [ticket.seat_number for ticket in travel_schedule.tickets if ticket.seat_number is not None]
    available_seats = [seat for seat in range(1, travel_schedule.vehicle.capacity + 1) if seat not in booked_seat_numbers]
    form.seat_number.choices = [(seat, seat) for seat in available_seats]

    if request.method == 'POST' and form.validate_on_submit():
        if not travel_schedule.vehicle:
            flash('No vehicle assigned to this travel schedule', 'error')
            return redirect(url_for('user_dashboard'))

        if len(travel_schedule.tickets) >= travel_schedule.vehicle.capacity:
            flash('This vehicle has reached its capacity. No available seats for this travel schedule', 'error')
            return redirect(url_for('user_dashboard'))

        selected_seat = int(form.seat_number.data)

        if selected_seat not in available_seats:
            flash('This seat is already booked. Please choose another seat.', 'error')
            return redirect(url_for('book_ticket', schedule_id=schedule_id))

        new_ticket = Ticket(
            user=current_user,
            travel_schedule=travel_schedule,
            booking_time=datetime.utcnow(),
            seat_number=selected_seat,
            price=travel_schedule.price,
            ticket_number=generate_unique_ticket_number()  # Use the updated function for unique ticket number
        )

        db.session.add(new_ticket)
        db.session.commit()

        booked_seat_numbers.append(selected_seat)
        available_seats = [seat for seat in range(1, travel_schedule.vehicle.capacity + 1) if seat not in booked_seat_numbers]
        form.seat_number.choices = [(seat, seat) for seat in available_seats]

        flash('Ticket booked successfully', 'success')
        return redirect(url_for('download_ticket', ticket_id=new_ticket.id))

    return render_template('user/book_ticket.html', travel_schedule=travel_schedule, form=form, booked_seats=booked_seat_numbers)

# Route to handle ticket download page
@app.route('/download_ticket/<int:ticket_id>')
@login_required
def download_ticket(ticket_id):
    # Retrieve the ticket from the database
    ticket = Ticket.query.get_or_404(ticket_id)

    # Check if the ticket belongs to the current user
    if ticket.user != current_user:
        abort(403)  # Forbidden

    # Retrieve the associated travel schedule for additional details
    travel_schedule = ticket.travel_schedule

    # Render the download_ticket template with the ticket and schedule details
    return render_template('user/download_ticket.html', ticket=ticket, travel_schedule=travel_schedule)

# Route for the user's bookings
@app.route('/user_bookings', methods=['GET'])
@login_required
def user_bookings():
    # Retrieve the user's booked tickets
    user_tickets = current_user.booked_tickets()

    return render_template('user/user_bookings.html', user_tickets=user_tickets)



if __name__ == '__main__':
    app.run(debug=True)
