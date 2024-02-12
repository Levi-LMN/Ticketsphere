from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_bcrypt import Bcrypt
from wtforms import SelectField
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import uuid
from sqlalchemy.exc import IntegrityError
from sqlalchemy import DateTime, func
from flask import request

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


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    date_created = db.Column(DateTime(timezone=True), server_default=func.now())
    token = db.Column(db.String(100), unique=True)
    is_verified = db.Column(db.Boolean, default=False)


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'), ('sacco_admin', 'Sacco Admin'), ('driver', 'Driver'),
                                        ('admin', 'Admin')],
                       validators=[DataRequired()])
    submit = SubmitField('Register')


# ... (remaining code)


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Create the database tables
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define a custom 404 error handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


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



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        # If email doesn't exist, proceed with registration
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data,
            token=str(uuid.uuid4())  # Generate a new token for verification
        )

        try:
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
            flash('Your account has been created! Please check your email for verification.', 'success')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)




def send_verification_email(user):
    token = user.token
    subject = 'Verify Your Email'
    body = f'Thank you for registering! Please click the following link to verify your email: {url_for("verify", token=token, _external=True)}'

    msg = Message(subject, recipients=[user.email], body=body)
    mail.send(msg)



@app.route('/verify/<token>')
def verify(token):
    user = User.query.filter_by(token=token).first()

    if user:
        # Check if the verification link is not expired (you can adjust the duration)
        if datetime.utcnow() - user.date_created < timedelta(hours=24):
            # Mark the user as verified
            user.is_verified = True
            user.token = None
            db.session.commit()
            flash('Your email has been verified! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('The verification link has expired. Please register again.', 'danger')
            return redirect(url_for('register'))
    else:
        flash('Invalid verification link. Please register again.', 'danger')
        return redirect(url_for('register'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/user-dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html', user=current_user)

@app.route('/sacco-admin-dashboard')
@login_required
def sacco_admin_dashboard():
    return render_template('sacco_admin_dashboard.html', user=current_user)

@app.route('/driver-dashboard')
@login_required
def driver_dashboard():
    return render_template('driver_dashboard.html', user=current_user)

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html', user=current_user)

# Add this route to your Flask app
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

# Add this route to your Flask app
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

            return render_template('admin/change_role.html', user=user, user_roles=['user', 'sacco_admin', 'driver', 'admin'])
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('user_management'))
    else:
        flash('Access denied. You are not authorized to perform this action.', 'danger')
        return redirect(url_for('home'))



if __name__ == '__main__':
    app.run(debug=True)
