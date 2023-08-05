from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

# 查找資料庫套件用
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# 認證登入的
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
Base = declarative_base()

#  gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # 作為多組的要多建置foreignKey

    user = relationship('Comment', back_populates='blogpost')


class User(UserMixin, db.Model, Base):
    __tablename__ = "User_data"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(1000))
    password = db.Column(db.String(100))
    # 1對多的出發點改backref
    comment_co = relationship('Comment', back_populates='user')


# 作為中介表
class Comment(db.Model, Base):
    __tablename__ = "User_comment"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(1000))

    user_id = db.Column(db.Integer, ForeignKey('User_data.id'), nullable=False)
    blog_id = db.Column(db.Integer, ForeignKey('blog_posts.id'), nullable=False)

    blogpost = relationship('BlogPost', back_populates='user')
    user = relationship('User', back_populates='comment_co')


db.create_all()

# 要使用登入的前置作業
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# 要一個驗證是admin的裝飾器   =>  什麼時候該/要驗證呢?
# login > 在User確認可以登入後 啟用session時 直接對session驗證 再連接到回傳
# ALL POST葉面不顯示可編輯選項
# edit  delete post這些編輯相關葉面直接拒絕登入
def check_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return wrapper


### 原本想要連網頁控制顯示部顯示edit delete之類的功能 發現無法  最好還是一個func只做一件事 在這裡就是禁用非admin的人  網頁部分用current_user.id 去判別
# def show_admin_page(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         is_admin = False
#         if current_user:
#             if current_user.id == 1:
#                 is_admin = True
#         setattr(func, 'is_admin', is_admin)
#         return func(*args, **kwargs)
#     return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            # 要搭配html的jinger get_flashed_messages()
            flash("帳戶已經存在了喔")
            print("帳戶已存在")
            return redirect(url_for("login"))
        else:
            password_before = form.password.data
            # 加密密碼
            password_after = generate_password_hash(password=password_before, method='pbkdf2:sha256', salt_length=8)
            user_data = User(
                email=form.email.data,
                password=password_after,
                name=form.name.data
            )
            db.session.add(user_data)
            db.session.commit()
            login_user(User.query.filter_by(email=form.email.data).first())
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)
# 1. 登入 2.註冊後直接登入 3.註冊發現email重複回到登入後的錯誤訊息 4.nav再登入後讓登入從nav消失 5.用session記住登入狀態 6.登出

# 需要一個id為1的人為管理者並進行身分認證已顯示不同網頁
@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_data = User.query.filter_by(email=form.email.data).first()
        if user_data:
            if check_password_hash(pwhash=user_data.password, password=form.password.data):
                print("login ok")
                login_user(user_data)
                return redirect(url_for("get_all_posts"))
            else:
                flash("密碼錯誤")
                print("bad password")
                return redirect(url_for("login"))
        else:
            print("no data")
            flash("還未註冊")
            return redirect(url_for("login"))
    #     當已經登入的User再使用login網頁時導入主頁
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    # 給使用者comment
    if form.validate_on_submit():
        new_comment = Comment(
            comment=form.body.data,
            user_id=current_user.id,
            blog_id=post_id,
        )
        db.session.add(new_comment)
        db.session.commit()
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@check_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@check_admin
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

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@check_admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)