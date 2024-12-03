from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os
import csv

# put comments for the login function

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "24352afjhljaskdf"

app.secret_key = os.environ.get('SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

all_questions = []
with open("static/quizzes/quiztesting.csv") as f:
    for row in csv.reader(f, delimiter=";"):
        all_questions.append(row)

all_words = []
with open("static/glossary/definitions.csv") as f:
    for row in csv.reader(f, delimiter=';'):
        all_words.append(row)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# class depicting the user's data in the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


# creates the form for registering
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username already exists. Please choose a different one.")


# creates the form for login
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/')
def homepage():
    return render_template("front_page.html")

@app.route("/home", methods=["GET", "POST"])
@login_required
def auth_home():
    session.pop('_flashes', None)
    if session.get("score", None) == None:
        session["score"] = 0
    return render_template("auth_home.html", username=current_user.username, score=session.get("latest_score", None))


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # check if user submitted the form
        user = User.query.filter_by(username=form.username.data).first()  # check username validity
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):  # check hashed password matches
                login_user(user)
                flash("Login successful.")
                return redirect(url_for('auth_home', username=form.username.data))  # return homepage
        flash("Failed to login.")
        return render_template('login.html', form=form)
    return render_template("login.html", form=form)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # hashing the password and creating the new user
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Register successful.")
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route("/quiz1", methods=["GET", "POST"])
@login_required
def firstquiz():
    question_index = session.get("question_index", 1)
    # check if last question has been done
    if question_index >= len(all_questions):
        session["question_index"] = 1
        return redirect(url_for("results"))

    # check if variables have been created in session
    if session.get("score", None) == None:
        session["score"] = 0
    if session.get("questions_correct", None) == None:
        session["questions_correct"] = []

    current_question = all_questions[question_index]
    allOptions = current_question[1:-1]

    if request.method == "POST":
        # check if user entered something
        if request.form.get("answer") != None:
            selected_answer = int(request.form.get("answer"))
            user_answer = chr(selected_answer + 65)
            session["question_index"] = question_index + 1
            if user_answer != current_question[-1]:
                session["questions_correct"].append(False)
                return render_template("feedback.html", feedback=f"Correct Answer is {current_question[-1]}")
            else:
                session["score"] += 1
                session["questions_correct"].append(True)
                return redirect(url_for("firstquiz"))
    return render_template("quiz1.html", question=current_question[0], options=allOptions,
                           question_num=question_index)


@app.route("/results", methods=["GET", "POST"])
def results():
    current_score = session.get("score")
    session["latest_score"] = current_score
    session["score"] = 0  # set score to 0 for next quiz
    correct_questions = session["questions_correct"]
    session["questions_correct"] = []
    return render_template("quiz_results.html", score=current_score, corrects=correct_questions,
                           num_questions=len(all_questions) - 1)


@app.route("/web_programming")
@login_required
def web_programming():
    return render_template("web_programming_applications.html")


@app.route("/data_transfers")
@login_required
def data_transfers():
    return render_template("data_transfer.html")


@app.route("/web_security")
@login_required
def web_security():
    return render_template("web_security.html")


@app.route("/big_data_accessibility")
@login_required
def big_data_accessibility():
    return render_template("big_data_accessibility.html")


@app.route("/web_development")
@login_required
def web_development():
    return render_template("frameworks_web_dev.html")


@app.route("/glossary")
@login_required
def glossary():
    return render_template("glossary.html", word_list=all_words)


# @app.route("/forum")
# @login_required
# def forum():
#     return "Forum page."


if __name__ == '__main__':
    app.run()
