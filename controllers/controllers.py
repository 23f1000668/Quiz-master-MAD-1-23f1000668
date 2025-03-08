from flask import Flask,redirect,url_for,render_template,request,flash,session,Blueprint
import os
import matplotlib.pyplot as plt
from werkzeug.security import generate_password_hash,check_password_hash
from models.models import *
from datetime import datetime

controllers=Blueprint('controllers',__name__)
def check_role(role):
    if 'user_id' in session and session['role']==role:
        return True
    return False
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
        if User.query.filter_by(email=email).first():
            flash("Email already exists")
            return render_template('register.html')
        new_user=User(username=username,email=email,password=password,full_name=full_name,qualification=qualification,dob=dob,college=college,roles="user")
        db.session.add(new_user)
        db.session.commit()
        flash('User registered sucessfully! Please log in !!')
        return redirect(url_for('controllers.login'))
    return render_template('register.html')

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

#logout page
@controllers.route('/logout')
def logout():
    session.clear()
    flash('You have been looged out.')
    return redirect(url_for('controllers.home'))
#user dashboard
@controllers.route('/user/dashboard')
def user_dashboard():
    if not check_role('user'):
        flash('Access denied.You must be logged in as a user')
        return redirect(url_for('controllers.login'))
    return render_template('user_dashboard.html')

#admin dashboard
@controllers.route("/admin/dashboard")
def admin_dashboard():
    if not check_role('admin'):
        flash('Access denied.Your not allowed here')
        return redirect(url_for('controllers.login'))
    subjects=Subject.query.all()
    users=User.query.all()
    return render_template('admin_dashboard.html',subjects=subjects,users=users)

@controllers.route('/admin/quiz/show')
def quiz_show():
    if not check_role('admin'):
        flash('You not allowed here')
        return redirect(url_for('controllers.login'))
    quiz=Quiz.query().all()
    return render_template('admin_quiz.html',quiz=quiz)

@controllers.route('/admin/summary')
def summary_show():
    if not check_role('admin'):
        flash('Your not allowed here')
        return redirect(url_for('controllers.login'))
    score=Score.query().all()
    return render_template('summary_show.html',score=score)

@controllers.route('/admin/subject/create',methods=['GET','POST'])
def subjects_create():
    if not check_role('admin'):
        flash('Your are not allowed here')
        return redirect(url_for('controllers.login'))
    if request.method=='POST':
        name=request.form['name']
        description=request.form['description']
        new_subject=request.form(name = name,description=description)
        db.session.add(new_subject)
        db.session.commit()
        flash('Subject created successfully')
        return redirect(url_for('controllers.admin_dashboard'))
    return render_template('subject_create.html')

@controllers.route('/admin/subject/<int:id>/edit',methods=['GET','POST'])
def subject_edit(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('contollers.login'))
    subject=Subject.query.get_or_404(id)
    if request.method=='POST':
        subject.name=request.form['name']
        subject.description=request.form['description']
        db.session.commit()
        flash('Subject updated successfully!')
        return redirect(url_for('controllers.admin_dashboard'))
    return render_template('subject_edit.html',subject=subject)

