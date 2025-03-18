from flask import Flask,redirect,url_for,render_template,request,flash,session,Blueprint
import os
import matplotlib.pyplot as plt
from werkzeug.security import generate_password_hash,check_password_hash
from models.models import *
from datetime import datetime
from sqlalchemy import and_

controllers=Blueprint('controllers',__name__)

def check_role(role):
    if 'user_id' in session and session['role']==role:
        return True
    return False

'''def can_attempt_quiz(f):
    @warps(f)
    def attempt_quiz(*args,**kwargs):
        quiz_id=kwargs.get('quiz.id')
        quiz=Quiz.query.get_or_404(quiz_id)
        if quiz_id:
            flash("Quiz not found")
            return redirect(url_for('controllers.available_quizzes'))
        user_id=session.get('user_id')
        if user_id is None:
            flash("You must be logged in to attempt the quiz")
            return redirect(url_for('controllers.login'))
        return f(*args,**kwargs)
    return attempt_quiz
'''

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
            # Initialize answers dictionary in session if it doesn't exist
            if f'quiz_{quiz_id}_answers' not in session:
                session[f'quiz_{quiz_id}_answers'] = {}
            
            # Convert to string for dictionary key since session serializes to JSON
            session[f'quiz_{quiz_id}_answers'][str(question_id)] = int(user_answer)
            session.modified = True  # Ensure session is saved
        
        # Check if submit button was clicked
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
            
            # Clear session data for this quiz
            session.pop(f'quiz_{quiz_id}_answers', None)
            session.pop(f'quiz_{quiz_id}_current_question', None)

            flash(f'Quiz completed successfully! Your score: {total_score}')
            return redirect(url_for('controllers.user_dashboard'))
        elif 'save_and_next' in request.form:
            # If it's "Save and Next", increment the question index
            current_question_index += 1
            if current_question_index >= total_questions:
                current_question_index = total_questions - 1
            
            session[f'quiz_{quiz_id}_current_question'] = current_question_index
            session.modified = True

    # Get the current question to display
    current_question = questions[current_question_index]
    
    return render_template(
        'user_attempt_quiz.html',
        quiz=quiz,
        question=current_question,  # Fixed typo: qustion -> question
        current_question_index=current_question_index + 1,
        total_questions=total_questions
    )
    

    