from enum import unique
from flask import Flask ,render_template,url_for,request,redirect,session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import UserMixin,LoginManager,login_required,login_user,logout_user,current_user
from wtforms import StringField, PasswordField ,SubmitField
from wtforms.validators import InputRequired,Length , ValidationError
from datetime import timedelta
import pandas as pd
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///bhaskar.db'
app.config["SECRET_KEY"]= 'BHASKARisAgoodboy'
db = SQLAlchemy(app)
date_time =datetime.now() 

#Login/Logout related predefine work
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.refresh_view = 'relogin'
login_manager.needs_refresh_message = (u"Session timedout, please re-login")
login_manager.needs_refresh_message_category = "info"

#Login related work 

@login_manager.user_loader
def userload(user_id):
    return User.query.get(int(user_id))

#session restart

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=2)

#database table creation 
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80),nullable=False)
    

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(20),unique=True,nullable=False)
    device_ip = db.Column(db.Integer,unique=True,nullable=False)
    device_vendor = db.Column(db.String(20),unique=True,nullable=False)
    device_ = db.Column(db.String(20),unique=True,nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80),nullable=False)
    

#Login form Creation     
class loginform(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(
        min=4,max=20)],render_kw={"Placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(
        min=4,max=20)],render_kw={"Placeholder":"Password"}) 
    submit = SubmitField("Login")   

#Newuser form creation 
class registerform(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(
        min=4,max=20)],render_kw={"Placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(
        min=4,max=20)],render_kw={"Placeholder":"Password"}) 
    submit = SubmitField("Register")     

#Root /Home page 
@app.route("/")
def home():
    return render_template ("front.html")

#Login page 
@app.route("/login",methods= ['GET','POST'])
def login():
    form = loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if (user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template ("login.html",form = form)

#New user page 
@app.route("/register",methods= ['GET','POST'])
@login_required
def register():
    form = registerform()
    if form.validate_on_submit():
        new_user = User(username=form.username.data ,password = form.password.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect (url_for("user")) 
    return render_template('register.html',form=form)       

#Logout page 
@app.route("/logout",methods= ['GET','POST'])
@login_required
def logout():
    return redirect("/login")
    
#Dasboard page
@app.route("/dashboard",methods= ['GET','POST'])
@login_required
def dashboard():
    return render_template ("dashboard.html")

#Sub dashboard user setting page 
@app.route("/user",methods= ['GET','POST'])
@login_required
def user():
    data = pd.read_sql_table('user', 'sqlite:///bhaskar.db')
    return render_template ("user.html",data = data )    

#Script related page (Work in progress)
@app.route("/scrip")
def scrip():
    return render_template ("scrip.html")

#Contact  related page (Work in progress)
@app.route("/contact")
def contact():
    return render_template ("contact.html")

#Contact  related page (Work in progress)
@app.route("/about")
def about():
    return render_template ("about.html")              

#Application run and debug related work 
if __name__ == "__main__":
    app.run(debug=True)