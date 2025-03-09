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
        flash('Your not allowed here')
        return redirect(url_for('controllers.login'))
    subjects=Subject.query.all()
    users=User.query.filter_by(roles='user').all()
    return render_template('admin_dashboard.html',subjects=subjects,users=users)

@controllers.route('/admin/quiz/show')
def quiz_show():
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    quizzes=Quiz.query.all()
    return render_template('admin_quiz.html',quizzes=quizzes)

@controllers.route('/admin/summary')
def summary_show():
    if not check_role('admin'):
        flash('Your are not allowed here')
        return redirect(url_for('controllers.login'))
    score=Score.query.all()
    return render_template('summary_show.html',score=score)

@controllers.route('/admin/subject/create',methods=['GET','POST'])
def subject_create():
    if not check_role('admin'):
        flash('Your are not allowed here')
        return redirect(url_for('controllers.login'))
    if request.method=='POST':
        name=request.form['name']
        description=request.form['description']
        remarks=request.form['remarks']
        new_subject=Subject(name = name,description=description,remarks=remarks)
        db.session.add(new_subject)
        db.session.commit()
        flash('Subject created successfully')
        return redirect(url_for('controllers.admin_dashboard'))
    return render_template('subject_create.html')

@controllers.route('/admin/subject/<int:id>/edit',methods=['GET','POST'])
def subject_edit(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    subject=Subject.query.get_or_404(id)
    if request.method=='POST':
        subject.name=request.form['name']
        subject.description=request.form['description']
        subject.remarks=request.form['remarks']
        db.session.commit()
        flash('Subject updated successfully!')
        return redirect(url_for('controllers.admin_dashboard'))
    return render_template('subject_edit.html',subject=subject)

@controllers.route('/admin/subject/<int:id>/delete', methods=['POST'])
def subject_delete(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    subject=Subject.query.get_or_404(id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted successfully!')
    return redirect(url_for('controllers.admin_dashboard'))

@controllers.route('/admin/subject/<int:id>',methods=['GET'])
def subject_show(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    subject=Subject.query.get_or_404(id)
    return render_template('subject_show.html',subject=subject)

@controllers.route('/admin/subject/<int:subject_id>/chapter/create', methods=['GET', 'POST'])
def chapter_create(subject_id):
    if not check_role('admin'):
        flash('Access denied')
        return redirect(url_for('controllers.login'))

    subject = Subject.query.get_or_404(subject_id)

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        remarks=request.form['remarks']
        new_chapter = Chapter(name=name, description=description,remarks=remarks, subject_id=subject_id)
        db.session.add(new_chapter)
        db.session.commit()
        flash('Chapter created successfully!')
        return redirect(url_for('controllers.subject_show', id=subject_id))

    return render_template('chapter_create.html', subject=subject)

@controllers.route('/admin/chapter/<int:id>/edit',methods=['GET','POST'])
def chapter_edit(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    
    chapter=Chapter.query.get_or_404(id)

    if request.method=='POST':
        chapter.name=request.form['name']
        chapter.description=request.form['description']
        chapter.remarks=request.form['remarks']
        db.session.commit()
        flash('Chapter updated successfully!')
        return redirect(url_for('controllers.subject_show',id=chapter.subject_id))
    return render_template('chapter_edit.html',chapter=chapter)

@controllers.route('/admin/chapter/<int:id>/delete',methods=['POST'])
def chapter_delete(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    
    chapter=Chapter.query.get_or_404(id)
    subject_id=chapter.subject_id
    db.session.delete(chapter)
    db.session.commit()
    flash('Chapter deleted successfully!')
    return redirect(url_for('controllers.subject_show',id=subject_id))

@controllers.route('/admin/chapter/<int:id>')
def chapter_show(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    chapter = Chapter.query.get_or_404(id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()  # Fetch quizzes for this chapter
    return render_template('chapter_show.html', chapter=chapter, quizzes=quizzes)

@controllers.route('/admin/chapter/<int:chapter_id>/quiz/create',methods=['GET','POST'])
def quiz_create(chapter_id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    
    chapter=Chapter.query.get_or_404(chapter_id)

    if request.method=='POST':
        name=request.form['name']
        description=request.form['description']
        remarks=request.form['remarks']
        date_of_quiz = datetime.strptime(request.form['date_of_quiz'], '%Y-%m-%d').date()
        new_quiz = Quiz(name=name, description=description, remarks=remarks,date_of_quiz=date_of_quiz, chapter_id=chapter_id)
        db.session.add(new_quiz)
        db.session.commit()
        flash('Quiz created successfully!')
        return redirect(url_for('controllers.quiz_show'))

    return render_template('quiz_create.html', chapter=chapter)

@controllers.route('/admin/quiz/<int:id>/edit',methods=['GET','POST'])
def quiz_edit(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    
    quiz=Quiz.query.get_or_404(id)

    if request.method == 'POST':
        quiz.name = request.form['name']
        quiz.description = request.form['description']
        quiz.remarks=request.form['remarks']
        quiz.date_of_quiz = datetime.strptime(request.form['date_of_quiz'], '%Y-%m-%d').date()
        db.session.commit()
        flash('Quiz updated successfully!')
        return redirect(url_for('controllers.quiz_show'))

    return render_template('quiz_edit.html', quiz=quiz)

@controllers.route('/admin/quiz/<int:id>/delete',methods=['POST'])
def quiz_delete(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    
    quiz=Quiz.query.get_or_404(id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully!')
    return redirect(url_for('controllers.quiz_show'))

@controllers.route('/admin/quiz/<int:id>')
def quiz_show_detail(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    quiz = Quiz.query.get_or_404(id)
    questions = Question.query.filter_by(quiz_id=quiz.id).all()
    return render_template('quiz_show_detail.html', quiz=quiz, questions=questions)

@controllers.route('/admin/quiz/<int:quiz_id>/question/create', methods=['GET', 'POST'])
def question_create(quiz_id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))

    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        question_statement = request.form['question_statement']
        choice1 = request.form['choice1']
        choice2 = request.form['choice2']
        choice3 = request.form['choice3']
        choice4 = request.form['choice4']
        correct_answer = int(request.form['correct_answer'])
        score = int(request.form['score']) if request.form['score'] else 1
        new_question = Question(question_statement=question_statement, choice1=choice1, choice2=choice2,choice3=choice3, choice4=choice4, correct_answer=correct_answer, score=score,quiz_id=quiz_id)
        db.session.add(new_question)
        db.session.commit()
        flash('Question created successfully!')
        return redirect(url_for('controllers.quiz_show_detail',id=quiz_id))

    return render_template('question_create.html', quiz=quiz)

@controllers.route('/admin/question/<int:id>/edit', methods=['GET', 'POST'])
def question_edit(id):
    if not check_role('admin'):
        flash('Access denied')
        return redirect(url_for('controllers.login'))

    question = Question.query.get_or_404(id)
    quiz_id = question.quiz_id

    if request.method == 'POST':
        question.question_statement = request.form['question_statement']
        question.choice1 = request.form['choice1']
        question.choice2 = request.form['choice2']
        question.choice3 = request.form['choice3']
        question.choice4 = request.form['choice4']
        question.correct_answer = int(request.form['correct_answer'])
        question.score = int(request.form['score']) if request.form['score'] else 1
        db.session.commit()
        flash('Question updated successfully!')
        return redirect(url_for('controllers.quiz_show_detail', id=quiz_id))

    return render_template('question_edit.html', question=question)

@controllers.route('/admin/question/<int:id>/delete', methods=['POST'])
def question_delete(id):
    if not check_role('admin'):
        flash('Access denied')
        return redirect(url_for('controllers.login'))

    question = Question.query.get_or_404(id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!')
    return redirect(url_for('controllers.quiz_show_detail',  id=quiz_id))
