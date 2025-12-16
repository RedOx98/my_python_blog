from functools import wraps
from datetime import date

from flask import (
    Flask, render_template, redirect,
    url_for, request, flash, abort
)
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin, LoginManager,
    login_user, login_required,
    logout_user, current_user
)
from flask_wtf import FlaskForm
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Integer, String, Text, Boolean


# -------------------- APP SETUP --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"

Bootstrap5(app)
CKEditor(app)


# -------------------- DATABASE --------------------
class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)


# -------------------- LOGIN MANAGER --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# -------------------- MODELS --------------------
class User(UserMixin, db.Model):
    id = db.Column(Integer, primary_key=True)
    email = db.Column(String(100), unique=True, nullable=False)
    password = db.Column(String(200), nullable=False)
    name = db.Column(String(100), nullable=False)
    is_admin = db.Column(Boolean, default=False)


class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = db.relationship("User", backref="posts")


class Comment(db.Model):
    id = db.Column(Integer, primary_key=True)
    text = db.Column(Text, nullable=False)

    author_id = db.Column(Integer, db.ForeignKey("user.id"))
    author = db.relationship("User")

    post_id = db.Column(Integer, db.ForeignKey("blog_post.id"))
    post = db.relationship("BlogPost", backref="comments")


with app.app_context():
    db.create_all()


# -------------------- FORMS --------------------
from wtforms.validators import DataRequired, Email, EqualTo

class RegisterForm(FlaskForm):
    name = StringField(
        'Name',
        validators=[DataRequired()]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match')
        ]
    )
    submit = SubmitField('Register')



class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class BlogPostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField(
        'Author',
        validators=[DataRequired()]
    )
    img_url = StringField("Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Content", validators=[DataRequired()])
    submit = SubmitField("Submit")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Post Comment")


# -------------------- HELPERS --------------------
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# -------------------- ROUTES --------------------
@app.route("/")
def home():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            abort(403)

        new_comment = Comment(
            text=form.comment.data,
            author=current_user,
            post=post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("post.html", post=post, form=form)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = BlogPostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author=current_user,  # instead of form.author.data
            img_url=form.img_url.data,
            body=form.body.data,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("home"))
    return render_template("make-post.html", form=form)


@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
# @admin_only
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    form = BlogPostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )

    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=form, is_edit=True)


@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
# @admin_only
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered. Please log in instead.")
            return redirect(url_for("login"))

        # Hash the password
        hashed_pw = generate_password_hash(
            form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )

        # Create new user
        new_user = User(
            email=form.email.data,
            password=hashed_pw,
            name=form.name.data,
            is_admin=False  # or True for specific users
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user or not check_password_hash(user.password, form.password.data):
            flash("Invalid credentials")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("home"))

    return render_template("login.html", form=form)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(debug=True)