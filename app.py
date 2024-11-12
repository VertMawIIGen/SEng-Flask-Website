from flask import Flask, render_template, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')


@app.route('/')
def homepage():
    return render_template("home2.html")


# implement login function
# do jumbotron with carousel underneath there's a video online
@app.route("/login", methods=['GET', 'POST'])
def login():
    return render_template("base.html")


# code for quizzes
@app.route("/quiztesting", methods=["GET", "POST"])
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


if __name__ == '__main__':
    app.run()
