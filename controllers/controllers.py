from flask import Flask,redirect,url_for,render_template,request,flash,session,Blueprint
from werkzeug.security import generate_password_hash,check_password_hash
from models.models import *
from datetime import datetime
import pandas as pd
import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import io
import base64
import os
from collections import defaultdict
from sqlalchemy import  or_

controllers=Blueprint('controllers',__name__)

def check_role(role):
    if 'user_id' in session and session['role']==role:
        return True
    return False

#home page which would redirect to user dashboard which the user is logined or takes to register page
@controllers.route('/')
def home():
    if 'user_id' in session:
        if check_role('user'):
            return redirect(url_for('controllers.user_dashboard'))
        else:
            return redirect(url_for('controllers.admin_dashboard'))
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
    subjects=Subject.query.all()
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    scores = Score.query.filter_by(user_id=user_id).all()
    
    return render_template('user_dashboard.html', subjects=subjects, scores=scores, user=user)

#admin dashboard
@controllers.route("/admin/dashboard")
def admin_dashboard():
    if not check_role('admin'):
        flash('Your not allowed here')
        return redirect(url_for('controllers.login'))
    subjects = Subject.query.all()
    users = User.query.filter_by(roles='user').all()
    return render_template('admin_dashboard.html',subjects=subjects,users=users)

@controllers.route('/admin/quiz/show')
def quiz_show():
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    quizzes = Quiz.query.all()
    return render_template('admin_quiz.html',quizzes=quizzes)

@controllers.route('/admin/summary')
def summary_show():
    if not check_role('admin'):
        flash('Your are not allowed here')
        return redirect(url_for('controllers.login'))
    
    scores = Score.query.all()
    quizzes = Quiz.query.all()
    total_users = User.query.filter_by(roles='user').count()
    total_subjects = Subject.query.count()
    total_chapters = Chapter.query.count()
    total_quizzes = Quiz.query.count()
    total_attempts = Score.query.count()

    quiz_data = []
    for quiz in quizzes:
        attempts = Score.query.filter_by(quiz_id=quiz.id).count()
        avg_score = db.session.query(db.func.avg(Score.total_score)).filter(Score.quiz_id == quiz.id).scalar() or 0
        quiz_data.append({
            "Quiz Name": quiz.name,
            "Subject": quiz.chapter.subject.name,
            "Attempts": max(0, attempts),
            "Avg. Score": round(avg_score, 2)
        })

    plt.figure(figsize=(12, 6))
    subjects = [q['Subject'] for q in quiz_data]
    attempts = [q['Attempts'] for q in quiz_data]
    plt.bar([q['Quiz Name'] for q in quiz_data], attempts, color=plt.cm.tab10(range(len(subjects))))
    plt.title('Quiz Attempts by Subject')
    plt.xlabel('Quiz Name')
    plt.ylabel('Number of Attempts')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    bar_buffer = io.BytesIO()
    plt.savefig(bar_buffer, format='png')
    bar_buffer.seek(0)
    bar_chart = base64.b64encode(bar_buffer.getvalue()).decode()
    plt.close()

    subject_count = defaultdict(int)
    for q in quiz_data:
        subject_count[q['Subject']] += 1

    plt.figure(figsize=(8, 8))
    plt.pie(subject_count.values(), labels=subject_count.keys(), 
        autopct='%1.1f%%', colors=plt.cm.tab20.colors)
    plt.title('Subject-wise Quiz Distribution')
    plt.axis('equal')
    pie_buffer = io.BytesIO()
    plt.savefig(pie_buffer, format='png')
    pie_buffer.seek(0)
    pie_chart = base64.b64encode(pie_buffer.getvalue()).decode()
    plt.close()

    return render_template('summary_show.html',total_users=total_users,total_subjects=total_subjects,total_chapters=total_chapters,total_quizzes=total_quizzes,total_attempts=total_attempts,bar_chart=bar_chart,pie_chart=pie_chart)

@controllers.route('/admin/user/<int:id>/delete')
def user_delete(id):
    if not check_role('admin'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    user=User.query.get_or_404(id)
    Score.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('User deleted')
    return redirect(url_for('controllers.admin_dashboard'))

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
    scores = Score.query.filter_by(quiz_id=quiz.id).join(User).order_by(Score.timestamp.desc()).all()
    return render_template('quiz_show_detail.html', quiz=quiz, questions=questions, scores=scores)

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

@controllers.route('/user/available_quizzes')
def available_quizzes():
    if not check_role('user'):
        flash('Access denied.You must be logged in as a user')
        return redirect(url_for('controllers.login'))
    today = datetime.now().date()
    quizzes = Quiz.query.filter(Quiz.date_of_quiz <= today).all()
    return render_template('available_quizzes.html', quizzes=quizzes)

@controllers.route('/user/chapter/<int:chapter_id>')
def user_chapter_show(chapter_id):
    if not check_role('user'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    chapter = Chapter.query.get_or_404(chapter_id)
    today = datetime.now().date()
    quizzes = Quiz.query.filter(Quiz.chapter_id == chapter.id, Quiz.date_of_quiz <= today).all()
    return render_template('user_chapter_show.html', chapter=chapter, quizzes=quizzes)

@controllers.route('/user/subject/<int:subject_id>')
def user_subject_show(subject_id):
    if not check_role('user'):
        flash('You are not allowed here')
        return redirect(url_for('controllers.login'))
    subject = Subject.query.get_or_404(subject_id)
    return render_template('user_subject_show.html', subject=subject)

@controllers.route('/user/attempt_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def attempt_quiz(quiz_id):
    if not check_role('user'):
        flash('Access denied. You must be logged in as a user.')
        return redirect(url_for('controllers.login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    today = datetime.now().date()

    if quiz.date_of_quiz > today:
        flash('Quiz Expired. Try other quiz')
        return redirect(url_for('controllers.user_dashboard'))
    
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    total_questions = len(questions)
    current_question_index = session.get(f'quiz_{quiz_id}_current_question', 0)
    
    if request.method == 'POST':
        user_answer = request.form.get('answer')
        question_id = int(request.form.get('question_id'))
        
        if user_answer:
            if f'quiz_{quiz_id}_answers' not in session:
                session[f'quiz_{quiz_id}_answers'] = {}
            
            session[f'quiz_{quiz_id}_answers'][str(question_id)] = int(user_answer)
            session.modified = True
        
        if 'submit' in request.form:
            total_score = 0
            answers = session.get(f'quiz_{quiz_id}_answers', {})
            
            for question in questions:
                if str(question.id) in answers and answers[str(question.id)] == question.correct_answer:
                    total_score += question.score if question.score else 1
            
            user_id = session.get('user_id')
            new_attempt = Score(quiz_id=quiz_id, user_id=user_id, total_score=total_score, timestamp=datetime.now())
            db.session.add(new_attempt)
            db.session.commit()
            
            session.pop(f'quiz_{quiz_id}_answers', None)
            session.pop(f'quiz_{quiz_id}_current_question', None)

            flash(f'Quiz completed successfully! Your score: {total_score}')
            return redirect(url_for('controllers.user_dashboard'))
        elif 'save_and_next' in request.form:
            current_question_index += 1
            if current_question_index >= total_questions:
                current_question_index = total_questions - 1
            
            session[f'quiz_{quiz_id}_current_question'] = current_question_index
            session.modified = True

    current_question = questions[current_question_index]
    
    return render_template(
        'user_attempt_quiz.html',
        quiz=quiz,
        question=current_question,
        current_question_index=current_question_index + 1,
        total_questions=total_questions
    )

@controllers.route('/user/summary')
def user_summary():
    if not check_role('user'):
        flash('Access denied. You must be logged in as a user.')
        return redirect(url_for('controllers.login'))
    
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)
    scores = Score.query.filter_by(user_id=user_id).all()
    
    subject_scores = defaultdict(list)
    for score in scores:
        subject_scores[score.quiz.chapter.subject.name].append(score.total_score)
    
    avg_scores = {subject: sum(scores) / len(scores) for subject, scores in subject_scores.items()}
    max_scores = {subject: max(scores) for subject, scores in subject_scores.items()}
    
    plt.figure(figsize=(10, 5))
    plt.bar(avg_scores.keys(), avg_scores.values())
    plt.title('Average Scores by Subject')
    plt.xlabel('Subject')
    plt.ylabel('Average Score')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    bar_buffer = io.BytesIO()
    plt.savefig(bar_buffer, format='png')
    bar_buffer.seek(0)
    bar_chart = base64.b64encode(bar_buffer.getvalue()).decode()
    plt.close()
    plt.figure(figsize=(8, 8))
    plt.pie(max_scores.values(), labels=max_scores.keys(), autopct='%1.1f%%')
    plt.title('Max Score Distribution by Subject')
    plt.axis('equal')
    pie_buffer = io.BytesIO()
    plt.savefig(pie_buffer, format='png')
    pie_buffer.seek(0)
    pie_chart = base64.b64encode(pie_buffer.getvalue()).decode()
    plt.close()
    
    return render_template('user_summary.html', user=user, scores=scores,bar_chart=bar_chart, pie_chart=pie_chart)

@controllers.route('/admin/search')
def admin_search():
    if not check_role('admin'):
        flash('You are not allowed here!')
        return redirect(url_for('controllers.login'))
    
    query = request.args.get('query','')

    users = User.query.filter(or_(User.username.ilike(f'%{query}%'),User.email.ilike(f'%{query}%'),User.email.ilike(f'%{query}%'),User.qualification.ilike(f'%{query}%'),User.college.ilike(f'%{query}%'))).all()

    subjects = Subject.query.filter(or_(Subject.name.ilike(f'%{query}%'),Subject.description.ilike(f'%{query}%'),Subject.remarks.ilike(f'%{query}%'))).all()

    chapters = Chapter.query.filter(or_(Chapter.name.ilike(f'%{query}%'),Chapter.description.ilike(f'%{query}%'),Chapter.remarks.ilike(f'%{query}%'))).all()

    quizzes = Quiz.query.filter(or_(Quiz.name.ilike(f'%{query}%'),Quiz.description.ilike(f'%{query}%'),Quiz.remarks.ilike(f'%{query}%'))).all()

    questions = Question.query.filter(or_(Question.question_statement.ilike(f'%{query}%'))).all()

    return render_template('admin_search.html',users=users,subjects=subjects,chapters=chapters,quizzes=quizzes,questions=questions)

@controllers.route('/user/search')
def user_search():
    if not check_role('user'):
        flash('Your are not allowed here!')
        return redirect(url_for('controllers.login'))
    
    query = request.args.get('query','')

    subjects = Subject.query.filter(or_(Subject.name.ilike(f'%{query}%'),Subject.description.ilike(f'%{query}%'),Subject.remarks.ilike(f'%{query}%'))).all()

    chapters = Chapter.query.filter(or_(Chapter.name.ilike(f'%{query}%'),Chapter.description.ilike(f'%{query}%'),Chapter.remarks.ilike(f'%{query}%'))).all()

    quizzes = Quiz.query.filter(or_(Quiz.name.ilike(f'%{query}%'),Quiz.description.ilike(f'%{query}%'),Quiz.remarks.ilike(f'%{query}%'))).all()

    return render_template('user_search.html',subjects=subjects,chapters=chapters,quizzes=quizzes)

