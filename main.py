from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if current_user.get_id() != "1":
            return abort(403)

        return f(*args, **kwargs)

    return decorated_function


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    blogs_comment = relationship("Comment", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    posts = relationship("BlogPost", back_populates="blogs_comment")

    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    commenter = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user_id = current_user.get_id()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user_id=user_id)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_user = RegisterForm()
    if register_user.validate_on_submit():
        user_email = register_user.email.data.lower()
        user_name = register_user.name.data.title()

        if User.query.filter_by(email=user_email).first() is not None:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        user_password = generate_password_hash(register_user.password.data, method="pbkdf2:sha256", salt_length=8)
        # noinspection PyArgumentList
        new_user = User(
            name=user_name,
            email=user_email,
            password=user_password
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=register_user, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    user_login = LoginForm()

    if user_login.validate_on_submit():
        user_email = user_login.email.data.lower()
        user = User.query.filter_by(email=user_email).first()

        if user is not None:
            if check_password_hash(user.password, user_login.password.data):
                login_user(user)

                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect, please try again.")
        else:
            flash("The email does not exist, please try again.")

    return render_template("login.html", form=user_login, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    user_id = current_user.get_id()
    comment_form = CommentForm()
    logged_in = current_user.is_authenticated

    if comment_form.validate_on_submit():
        if not logged_in:
            flash("You need to login or register to comment!")
            return redirect(url_for("login"))

        comment = comment_form.comment.data

        user_comment = Comment(
            text=comment,
            commenter=current_user,
            posts=requested_post
        )

        db.session.add(user_comment)
        db.session.commit()

    all_comments = Comment.query.all()

    return render_template("post.html", post=requested_post, logged_in=logged_in, user_id=user_id,
                           comments=all_comments, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    Comment.query.filter(Comment.post_id == post_id).delete()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
