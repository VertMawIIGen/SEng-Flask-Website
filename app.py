from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# class depicting the user's data
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username already exists. Please choose a different one.")

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
    return render_template("auth_home.html", username=current_user.username)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('auth_home', username=form.username.data))

        flash("Failed to login.")
        return render_template('login.html', form=form)
    return render_template("login.html", form = form)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    #hashing the password and creating the new user
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form = form)

# code for quizzes
@app.route("/quiztesting", methods=["GET", "POST"])
@login_required
def quiztesting():
    questions = ["This is the question", "Question number 2"]
    question_index = session.get("question_index", 0)
    if question_index >= len(questions):
        session["question_index"] = 0
        return redirect(url_for("homepage"))
    session["score"] = 0

    question = questions[question_index]
    if request.method == "POST":
        selected_answer = request.form.get("answer")
        session["question_index"] = question_index + 1
        if selected_answer == "bad":
            session["score"] += 1
            return redirect(url_for("quiztesting"))
        else:
            feedback = f"Wrong answer."
            return render_template("feedback.html", feedback=feedback)
    return render_template("quiztesting.html", question=question, question_num=question_index + 1)

@app.route("/testering")
@login_required
def testering():
    return render_template("auth_notes.html")

if __name__ == '__main__':
    app.run()
