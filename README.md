# TicketSphere - Public Transport Booking System

## Overview
TicketSphere is a comprehensive Public Transport Booking System designed to streamline the booking process for users, manage vehicles across different Saccos, and facilitate secure transactions through M-Pesa. The system includes four panels: Admin, Sacco Admin, User, and Driver, each with specific functionalities to enhance the overall user experience.

## Features
- **User Management:** Register and authenticate users with distinct roles (User, Sacco Admin, Driver, Admin).
- **Sacco Management:** Admins can add and delete Saccos, assign Sacco admins, and manage Sacco details.
- **Vehicle Management:** Sacco admins can add vehicles associated with their Sacco.
- **Travel Schedule:** Admins can create and manage travel schedules, and users can book rides.
- **M-Pesa Integration:** Users can pay for booked rides securely through M-Pesa.
- **Role-based Access Control:** Different roles have tailored access to specific features and dashboards.

## Panels
- **Admin Panel:** Manages system-wide operations, Saccos, and users.
- **Sacco Admin Panel:** Manages vehicles, travel schedules, and Sacco-specific operations.
- **User Panel:** Books rides, views schedules, and completes payments.
- **Driver Panel:** Accesses relevant information and updates schedules.

## Dependencies
- Flask: Web framework for building the application.
- Flask-WTF: Integration of WTForms for handling forms.
- Flask-Login: User authentication and management.
- Flask-SQLAlchemy: ORM for database management.
- Flask-Migrate: Database migration tool.
- Flask-Bcrypt: Password hashing for security.
- Flask-Mail: Sending verification emails.
- SQLite: Database used for storing application data.

## M-Pesa Integration
- TicketSphere seamlessly integrates with M-Pesa for secure and convenient payment transactions.
- Users can pay for their booked rides through the M-Pesa payment gateway.

## Installation
1. Clone the repository: `git clone [repository_url]`
2. Install dependencies: `pip install -r requirements.txt`
3. Set up the database: `flask db upgrade`
4. Run the application: `python app.py`

## Usage
- Access the application through a web browser at `http://localhost:5000`.
- Register as a user, driver, Sacco admin, or admin.
- Use the respective dashboards based on your role.
- Admins can manage Saccos, users, and roles.
- Sacco admins can manage vehicles, schedules, and Sacco details.
- Drivers can view their dashboards and update schedules.
- Users can book rides, view schedules, and make payments.

## Important Note
- The application is currently in debug mode (`app.run(debug=True)`). In a production environment, set `debug` to `False`.
- Update the email configuration (`MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, etc.) in the `app.py` file for email functionality.

## Contributions
Contributions are welcome! Feel free to open issues, provide feedback, or submit pull requests to enhance the TicketSphere application.

## License
This project is licensed under the [MIT License](LICENSE).
