from flask import Flask
from models.models import *
from controllers.controllers import controllers
from werkzeug.security import generate_password_hash
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///Quiz_master.db"
app.config['SECRET_KEY']="Quiz_master"

db.init_app(app)

app.register_blueprint(controllers)

def createAdminLogin():
    with app.app_context():
        admin_email="admin@testemail.com"
        admin_user=User.query.filter_by(email=admin_email).first()
        if not admin_user:
            admin_username="admin"
            admin_password = generate_password_hash("admin123", method='pbkdf2:sha256')
            admin_user = User(username=admin_username, email=admin_email, password=admin_password, full_name='Admin Login',roles='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists.")

with app.app_context():
    db.create_all()
    createAdminLogin()

if __name__=="__main__":
    app.run(debug=True)