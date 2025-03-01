from flask import Flask,redirect,url_for,render_template,request,flash,session,Blueprint
import os
import matplotlib.pyplot as plt
from werkzeug.security import generate_password_hash,check_password_hash
from models.models import *
from datetime import datetime

controllers=Blueprint('controllers',__name__)
def check_role(role):
    pass
#home page which would redirect to user dashboard which the user is logined or takes to register page
@controllers.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('controllers.user_dashboard'))
    return redirect(url_for('controllers.register'))

#admin login page
@controllers.route('/admin/login',methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']

        user=User.query.filter_by(email=email,roles='admin').first()
        if user and check_password_hash(user.password,password):
            session['user_id']=user.id
            session['role']=user.roles
            flash('Admin login successful')
            return redirect(url_for('controllers.admin_dashboard'))
        else:
            flash('Admin login failed.check your credentials and try again')
    return render_template('admin_login.html')

#register page
@controllers.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        full_name = request.form['full_name']
        qualification = request.form['qualification']
        dob = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()
        college = request.form['college']
        new_user=User(username=username,email=email,password=password,full_name=full_name,qualification=qualification,dob=dob,college=college,roles="user")
        db.session.add(new_user)
        db.session.commit()
        flash('User registered sucessfully! Please log in !!')
        return redirect(url_for('controllers.login'))
    return render_template('registration.html')

#login page
@controllers.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password,password):
            session['user_id']=user.id
            session['role']=user.roles
            flash('Login Successful')
            if user.roles == 'admin':
                return redirect(url_for('controllers.admin_dashboard'))
            else:
                return redirect(url_for('controllers.user_dashboard'))
        else:
            flash('Login failed. Check your credentials and try again')
    return render_template('login.html')

@controllers.route('/user/daashboard')
def user_dashboard():
    if not check_role('user'):
        return render_template('userdashboard')

