from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from flask_wtf import FlaskForm
import wtforms
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////study/python_bootcamp_2/Day69_finalBlogSite/blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# login manager object
login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # create foreign key, users.id the users refers to the tablename of user.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # create reference to the user object, the posts refers to the posts property in the user class.
    author = relationship("User", back_populates="posts")

    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250))
    # this will act like a list of blogpost objects attached to each user.
    # the author refers to the author property in the blogpost class.
    posts = relationship("BlogPost", back_populates="author")

    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship('BlogPost', back_populates='comments')


with app.app_context():
    db.create_all()


# user register form
class UserForm(FlaskForm):
    name = wtforms.StringField(label='Name', validators=[wtforms.validators.DataRequired()])
    email = wtforms.EmailField(label='Email', validators=[wtforms.validators.DataRequired(), wtforms.validators.Email()])
    password = wtforms.PasswordField(label='Password', validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField(label="Let me register")


class UserLoginForm(FlaskForm):
    email = wtforms.EmailField(label='Email', validators=[wtforms.validators.DataRequired(), wtforms.validators.Email()])
    password = wtforms.PasswordField(label='Password', validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField(label="Let me login")


class CommentForm(FlaskForm):
    body = CKEditorField(label="Comment")
    submit = wtforms.SubmitField(label="Submit Comment")


# def admin_only(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         #If id is not 1 then return abort with 403 error
#         if current_user.id != 1:
#             return abort(403)
#         #Otherwise continue with the route function
#         return f(*args, **kwargs)
#     return decorated_function
def admin_only(f):
    def wrapper_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    wrapper_function.__name__ = f.__name__
    return wrapper_function


# login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    with app.app_context():
        posts = BlogPost.query.all()
        for post in posts:
            print(post.author.name)

    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = UserForm()
    if request.method == "POST":
        user_data = User.query.filter_by(email=request.form["email"]).first()
        if user_data is None:
            hashed_password = generate_password_hash(
                request.form["password"],
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                name=request.form["name"],
                email=request.form["email"],
                password=hashed_password
            )
            with app.app_context():
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for("get_all_posts"))
        else:
            flash("The user already exist! please login instead")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = UserLoginForm()
    if request.method == "POST":
        user_data = User.query.filter_by(email=request.form["email"]).first()
        if user_data is not None:
            if check_password_hash(user_data.password, request.form["password"]):
                login_user(user_data)
                return redirect(url_for("get_all_posts"))
            else:
                flash("The password you entered is wrong")
        else:
            flash("The email doesn't exist!")

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    with app.app_context():
        requested_post = BlogPost.query.get(post_id)
        print(requested_post.author.name)
        if request.method == "POST":
            new_comment = Comment(
                text=request.form['body'],
                author_id=current_user.id,
                post_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        for i in requested_post.comments:
            print(i.comment_author.name)
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


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
            # author=current_user,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        with app.app_context():
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    with app.app_context():
        post = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            # author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            # post.author = post.author
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    with app.app_context():
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=5000)
