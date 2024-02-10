from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate  # Import Flask-Migrate
from wtforms import BooleanField
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, FloatField, SubmitField
from wtforms.validators import DataRequired
from flask import render_template, redirect, url_for, flash
from datetime import datetime
from wtforms import SelectField
from flask import render_template, request
from sqlalchemy.orm import joinedload

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)  # Initialize Flask-Migrate

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class Sacco(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    contact_info = db.Column(db.String(100))

    # Define the bidirectional relationship with Vehicle
    vehicles = db.relationship('Vehicle', back_populates='sacco', lazy=True)


class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    sacco_id = db.Column(db.Integer, db.ForeignKey('sacco.id'), nullable=False)
    route_id = db.Column(db.Integer, db.ForeignKey('route.id'), nullable=False)

    # Define the backref for Ticket relationship
    tickets = db.relationship('Ticket', backref='vehicle', lazy=True)

    # Define the backref for Route relationship
    route = db.relationship('Route', backref='vehicles', lazy=True)

    # Define the bidirectional relationship with Sacco
    sacco = db.relationship('Sacco', back_populates='vehicles', lazy=True)


class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    origin = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    distance = db.Column(db.Float, nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    tickets = db.relationship('Ticket', backref='route', lazy=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    route_id = db.Column(db.Integer, db.ForeignKey('route.id'), nullable=False)
    booking_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    departure_date = db.Column(db.DateTime, nullable=False)
    fare = db.Column(db.Float, nullable=False)
    # Add more ticket attributes as needed

# Create a form for adding a new Sacco
class SaccoForm(FlaskForm):
    name = StringField('Sacco Name', validators=[DataRequired()])
    description = StringField('Description')
    contact_info = StringField('Contact Information')
    submit = SubmitField('Add Sacco')

# Create a form for adding a new Vehicle
# ...

class VehicleForm(FlaskForm):
    name = StringField('Vehicle Name', validators=[DataRequired()])
    capacity = IntegerField('Capacity', validators=[DataRequired()])
    type = StringField('Vehicle Type', validators=[DataRequired()])
    sacco_id = SelectField('Sacco', coerce=int, validators=[DataRequired()], choices=[])  # Existing Sacco field
    route_id = SelectField('Route', coerce=int, validators=[DataRequired()])  # New Route field
    submit = SubmitField('Add Vehicle')

# ...

# Create a form for adding a new Route
class RouteForm(FlaskForm):
    origin = StringField('Origin', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    distance = FloatField('Distance', validators=[DataRequired()])
    duration = StringField('Duration', validators=[DataRequired()])
    submit = SubmitField('Add Route')

class RouteSearchForm(FlaskForm):
    origin = SelectField('Origin', choices=[], coerce=int)
    destination = SelectField('Destination', choices=[], coerce=int)
    submit = SubmitField('Search')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define a custom 404 error handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()  # Rollback the transaction to avoid leaving the database in an inconsistent state
            flash('Username or email already exists. Please choose a different one.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print(f"User found: {user.username}")
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                print("Password does not match.")
                flash('Login unsuccessful. Please check your email and password.', 'danger')
        else:
            print("User not found.")
            flash('Login unsuccessful. User not found.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/user/profile')
@login_required  # Ensure that only logged-in users can access their profile
def user_profile():
    return render_template('user_profile.html', user=current_user)

# Add new routes to handle form submissions
@app.route('/add_sacco', methods=['GET', 'POST'])
def add_sacco():
    form = SaccoForm()
    if form.validate_on_submit():
        sacco = Sacco(name=form.name.data, description=form.description.data, contact_info=form.contact_info.data)
        db.session.add(sacco)
        db.session.commit()
        flash('Sacco added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('admin/add_sacco.html', form=form)


# ...

# ...

@app.route('/add_vehicle', methods=['GET', 'POST'])
def add_vehicle():
    form = VehicleForm()

    # Populate choices dynamically with existing Saccos and Routes
    form.sacco_id.choices = [(sacco.id, sacco.name) for sacco in Sacco.query.all()]
    form.route_id.choices = [(route.id, f"{route.origin} to {route.destination}") for route in Route.query.all()]

    if form.validate_on_submit():
        sacco_id = form.sacco_id.data
        sacco = Sacco.query.get(sacco_id)

        # Convert the route_id to an integer
        route_id = int(form.route_id.data)
        route = Route.query.get(route_id)

        if sacco and route:
            vehicle = Vehicle(
                name=form.name.data,
                capacity=form.capacity.data,
                type=form.type.data,
                sacco_id=sacco_id,
                route_id=route_id
            )
            db.session.add(vehicle)
            db.session.commit()
            flash('Vehicle added successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Sacco or Route not found. Please select valid Sacco and Route.', 'danger')

    return render_template('admin/add_vehicle.html', form=form)

# ...

# ...

# ...

# ...

# Add new routes to handle form submissions
@app.route('/add_route', methods=['GET', 'POST'])
def add_route():
    form = RouteForm()

    if form.validate_on_submit():
        route = Route(
            origin=form.origin.data,
            destination=form.destination.data,
            distance=form.distance.data,
            duration=form.duration.data
        )

        try:
            db.session.add(route)
            db.session.commit()
            flash('Route added successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            print(f"Error committing to the database: {e}")
            flash('An error occurred while adding the route. Please try again.', 'danger')
    else:
        print(form.errors)  # Print form validation errors for debugging

    return render_template('admin/add_route.html', form=form)

# ...

@app.route('/routes')
def view_routes():
    routes = Route.query.all()
    return render_template('admin/view_routes.html', routes=routes)

# ...

@app.route('/vehicles')
def view_vehicles():
    vehicles = Vehicle.query.all()
    saccos = Sacco.query.all()
    return render_template('admin/view_vehicles.html', vehicles=vehicles, saccos=saccos)

@app.route('/vehicles/<int:sacco_id>')
def view_vehicles_by_sacco(sacco_id):
    sacco = Sacco.query.get_or_404(sacco_id)
    vehicles = Vehicle.query.filter_by(sacco_id=sacco_id).all()
    saccos = Sacco.query.all()
    return render_template('admin/view_vehicles.html', vehicles=vehicles, saccos=saccos, selected_sacco=sacco)

@app.route('/route_list')
def route_list():
    routes = Route.query.options(joinedload(Route.vehicles).joinedload(Vehicle.sacco)).all()
    return render_template('route_list.html', routes=routes)

@app.route('/find_route', methods=['GET', 'POST'])
def find_route():
    all_routes = Route.query.all()

    if request.method == 'POST':
        origin = request.form.get('origin')
        destination = request.form.get('destination')

        # Print debug information
        print(f"Selected Origin: {origin}, Destination: {destination}")

        # Perform the filtering based on the selected origin and destination
        if origin and destination:
            routes = Route.query.filter_by(origin=origin, destination=destination).all()
        else:
            routes = all_routes
    else:
        routes = all_routes
        origin = ''  # Set default values when loading the page
        destination = ''  # Set default values when loading the page

    return render_template('find_route.html', routes=routes, all_routes=all_routes, origin=origin, destination=destination)

@app.route('/route/<int:route_id>')
def route_detail(route_id):
    route = Route.query.get_or_404(route_id)
    vehicles = Vehicle.query.filter_by(route_id=route_id).all()
    return render_template('route_detail.html', route=route, vehicles=vehicles)

@app.route('/search_routes', methods=['GET', 'POST'])
def search_routes():
    form = RouteSearchForm()

    # Populate choices for origin and destination from existing routes
    form.origin.choices = [(route.id, route.origin) for route in Route.query.all()]
    form.destination.choices = [(route.id, route.destination) for route in Route.query.all()]

    if request.method == 'POST' and form.validate_on_submit():
        origin_route = Route.query.get(form.origin.data)
        destination_route = Route.query.get(form.destination.data)

        # Perform the search based on the selected origin and destination routes
        # You may want to adjust this query based on your specific requirements
        routes = Route.query.filter_by(origin=origin_route.origin, destination=destination_route.destination).all()
    else:
        # If it's a GET request or form not submitted, display all routes
        routes = Route.query.all()

    return render_template('search_routes.html', form=form, routes=routes)

# Add a new route for booking a vehicle
@app.route('/route/<int:route_id>/book/<int:vehicle_id>')
def book_vehicle(route_id, vehicle_id):
    # You can implement the booking logic here
    # For demonstration, I'll redirect back to the route detail page
    flash('Vehicle booked successfully!', 'success')
    return redirect(url_for('route_detail', route_id=route_id))

if __name__ == '__main__':
    # Create all tables before running the app
    with app.app_context():
        db.create_all()

    app.run(debug=True)
