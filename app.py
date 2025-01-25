from flask import Flask
from models.models import *;

app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///mad1.db"
app.config['SECRET_KEY']="mad1"

db.init_app(app)

with app.app_context():
    db.create_all()

if __name__=="__main__":
    app.run(debug=True)