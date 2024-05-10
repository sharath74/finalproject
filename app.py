from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'your_very_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TIMEZONE'] = 'America/New_York'


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class QuoteForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    source = StringField('Source')
    public = BooleanField('Public')
    comments_allowed = BooleanField('Comments Allowed')
    submit = SubmitField('Submit')

class CommentForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    public = BooleanField('Public Comment')
    submit = SubmitField('Submit')
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    quotes = db.relationship('Quote', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Quote(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(100))  # Add the source attribute
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    public = db.Column(db.Boolean, default=True)
    comments_allowed = db.Column(db.Boolean, default=True)
    comments = db.relationship('Comment', backref='quote', lazy='dynamic')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    public = db.Column(db.Boolean, default=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote.id'), nullable=False)

@app.route('/')
def home():
    if current_user.is_authenticated:
        quotes = Quote.query.all()  # Fetch all quotes from the database
        comment_form = CommentForm()  # Instantiate the comment form
        return render_template('index.html', quotes=quotes, comment_form=comment_form)
    else:
        return redirect(url_for('login'))  # Redirect to login page if not logged in


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next') or url_for('home')
            return redirect(next_page)
        flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/quote/add', methods=['GET', 'POST'])
@login_required
def add_quote():
    form = QuoteForm()
    if form.validate_on_submit():
        new_quote = Quote(
            content=form.content.data,
            source=form.source.data,  # Get the source from the form
            public=form.public.data,
            comments_allowed=form.comments_allowed.data,
            author=current_user
        )
        db.session.add(new_quote)
        db.session.commit()
        flash('Quote added successfully', 'success')
        return redirect(url_for('home'))
    return render_template('add_quote.html', form=form)


# Route to view a quote and add comments
@app.route('/quote/<int:quote_id>', methods=['GET', 'POST'])
@login_required
def view_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)

    # Format the date and time
    edt = pytz.timezone('America/New_York')
    formatted_date_time = quote.date_posted.astimezone(edt).strftime('%b %d, %Y %H:%M %Z')

    form = CommentForm()  # Create an instance of the CommentForm

    if form.validate_on_submit():
        new_comment = Comment(
            content=form.content.data,
            public=form.public.data,
            quote=quote,
            author=current_user
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully', 'success')
        return redirect(url_for('view_quote', quote_id=quote.id))

    comments = quote.comments.filter_by(public=True).all() if quote.public else quote.comments.all()

    return render_template('view_quote.html', quote=quote, formatted_date_time=formatted_date_time, comment_form=form, comments=comments)


@app.route('/quote/<int:quote_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if current_user != quote.author:
        abort(403)  # Only allow the quote's author to edit it
    form = QuoteForm(obj=quote)
    if form.validate_on_submit():
        form.populate_obj(quote)
        db.session.commit()
        flash('Quote updated successfully', 'success')
        return redirect(url_for('home'))
    return render_template('edit_quote.html', form=form)


@app.route('/quote/<int:quote_id>/delete', methods=['POST'])
@login_required
def delete_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if quote.author != current_user:
        abort(403)  # Forbidden
    db.session.delete(quote)
    db.session.commit()
    flash('Quote deleted successfully', 'success')
    return redirect(url_for('home'))

# Route to delete a comment
@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author == current_user or comment.quote.author == current_user:
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted successfully', 'success')
    else:
        abort(403)  # Forbidden access
    return redirect(url_for('view_quote', quote_id=comment.quote.id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they do not exist
    app.run(debug=True)  
