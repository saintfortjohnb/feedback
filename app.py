from flask import Flask, render_template, redirect, session
from forms import LoginForm, RegisterForm, FeedbackForm
from models import User, connect_db, db, Feedback
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

app = Flask(__name__)

def create_and_configure_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = True
    app.config['SECRET_KEY'] = 'secret'

    connect_db(app)

    with app.app_context():
        db.create_all()

    return app

app = create_and_configure_app()
bcrypt = Bcrypt(app)

@app.route('/')
def redirect_register():
    return redirect("/register")

@app.route('/register', methods=["GET", "POST"])
def register_user():
    if 'username' in session:
        return redirect("/users/" + session['username'])
    
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        # Hash the password
        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(username=username, password=hashed_pwd, email=email, first_name=first_name, last_name=last_name)
        db.session.add(user)
        db.session.commit()
        session['username'] = username
        return redirect(f"/users/{username}")

    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login_user():
    if 'username' in session:
        return redirect("/users/" + session['username'])
    
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = user.username
            return redirect(f"/users/{user.username}")
        else:
            form.username.errors = ["Invalid username/password."]

    return render_template("login.html", form=form)

@app.route('/users/<username>')
def user_page(username):
    if 'username' not in session or username != session['username']:
        return redirect("/login")
    
    user = User.query.get(username)
    feedbacks = Feedback.query.filter_by(username=username).all()
    return render_template("user.html", user=user, feedbacks=feedbacks)

@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    if 'username' not in session or username != session['username']:
        return redirect("/login")
    
    user = User.query.get(username)
    feedbacks = Feedback.query.filter_by(username=username).all()

    for feedback in feedbacks:
        db.session.delete(feedback)
    
    db.session.delete(user)
    db.session.commit()

    session.pop('username', None)
    return redirect("/")

@app.route('/users/<username>/feedback/add', methods=["GET", "POST"])
def add_feedback(username):
    if 'username' not in session or username != session['username']:
        return redirect("/login")

    form = FeedbackForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        feedback = Feedback(title=title, content=content, username=username)
        db.session.add(feedback)
        db.session.commit()

        return redirect(f"/users/{username}")

    return render_template("add_feedback.html", form=form)

@app.route('/feedback/<int:feedback_id>/update', methods=["GET", "POST"])
def update_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)

    if 'username' not in session or feedback.username != session['username']:
        return redirect("/login")

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data

        db.session.commit()
        return redirect(f"/users/{feedback.username}")

    return render_template("update_feedback.html", form=form, feedback_id=feedback_id)

@app.route('/feedback/<int:feedback_id>/delete', methods=["POST"])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)

    if 'username' not in session or feedback.username != session['username']:
        return redirect("/login")

    db.session.delete(feedback)
    db.session.commit()

    return redirect(f"/users/{feedback.username}")

@app.route('/logout', methods=["GET", "POST"])
def logout_user():
    session.pop('username', None)
    return redirect("/")
