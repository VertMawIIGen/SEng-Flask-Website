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
    for row in csv.reader(f):
        all_questions.append(row)

# to show which questions the person got wrong
questions_correct = []


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
    return render_template("home2.html")


@app.route("/base")
def base():
    return render_template("base.html")


@app.route("/home", methods=["GET", "POST"])
@login_required
def auth_home():
    session.pop('_flashes', None)
    return render_template("auth_home.html", username=current_user.username)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # check if user submitted the form
        user = User.query.filter_by(username=form.username.data).first()  # check username validity
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):  # check hashed password
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
    if question_index >= len(all_questions):
        session["question_index"] = 0
        return redirect(url_for("results"))

    if session.get("score", None) == None:
        session["score"] = 0

    current_question = all_questions[question_index]
    allOptions = [current_question[1], current_question[2], current_question[3], current_question[4]]

    if request.method == "POST":
        selected_answer = int(request.form.get("answer"))
        user_answer = chr(selected_answer + 65)
        session["question_index"] = question_index + 1
        if user_answer != current_question[5]:
            return render_template("feedback.html", feedback=f"Correct Answer is {current_question[5]}")
        else:
            session["score"] += 1
            return redirect(url_for("firstquiz"))
    print(session["score"])
    return render_template("quiztesting.html", question=current_question[0], options=allOptions, question_num=question_index)


@app.route("/results", methods=["GET", "POST"])
def results():
    current_score = session.get("score")
    return f"Your score is {current_score}"

@app.route("/web_programming")
@login_required
def web_programming():
    return render_template("web_programming_applications.html")


@app.route("/data_transfers")
@login_required
def data_transfers():
    return render_template("data_transfer.html")


if __name__ == '__main__':
    app.run()
