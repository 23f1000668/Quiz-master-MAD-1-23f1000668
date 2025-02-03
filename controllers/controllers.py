from flask import Flask,redirect,url_for,render_template,request,flash,session,Blueprint
import os
import matplotlib.pyplot as plt
from werkzeug.security import generate_password_hash,check_password_hash
from models.models import *

controllers=Blueprint('controllers',__name__)
@controllers.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('controllers.view_posts'))
    return redirect(url_for('controllers.register'))

#admin login page
@controllers.route('/admin/login',methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']

        user=User.query.filter_by(email=email,roles='admin').first()
        if user and check_password_hash(user.password,password):
            session['user.id']=user.id
            session['role']=user.roles
            flask('Admin login successful')
            return redirect(url_for('controllers.admin_dashboard'))
        else:
            flask('Admin login failed.check your credentials and try again')
    return render_template('admin_login.html')

@controllers.route('/register',method=['GET','POST'])
def register():
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        password=generate_password_hash(request.form['password'],method='pdkdf2:sha256')
        full_name = request.form['full_name']
        qualification = request.form['qualification']
        dob = request.form['data of birth']
        college = request.form['college']
        new_user=User(username=username,email=email,password=password,full_name=full_name,qualification=qualification,dob=dob,college=college)
        db.session.add(new_user)
        db.session.commit()
        flask('User registered sucessfully! Please log in !!')
        return redirect(url_for('controllers.login'))
    return render_template('registration.html')
    
        

        