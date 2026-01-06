from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from data import quizzes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(50))
    score = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
        else:
            new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

# --- UPDATED QUIZ LOGIC ---
@app.route('/quiz/<subject>', methods=['GET', 'POST'])
@login_required
def quiz(subject):
    if subject not in quizzes:
        return redirect(url_for('dashboard'))
    
    questions = quizzes[subject]
    
    if request.method == 'POST':
        score = 0
        details = [] # List to store the report card
        
        for i, q in enumerate(questions):
            # Get user's answer from form
            user_answer = request.form.get(f'question-{i}')
            correct_answer = q['answer']
            
            # Check if correct
            is_correct = (user_answer == correct_answer)
            if is_correct:
                score += 1
            
            # Add details for the result page
            details.append({
                'q': q['q'],
                'user_answer': user_answer,
                'correct_answer': correct_answer,
                'is_correct': is_correct,
                'options': q['options']
            })
        
        # Save score to Database
        new_score = Score(user_id=current_user.id, subject=subject, score=score)
        db.session.add(new_score)
        db.session.commit()
        
        # Directly render result page with the details
        return render_template('result.html', subject=subject, score=score, total=len(questions), details=details)

    return render_template('quiz.html', subject=subject, questions=questions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)