from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, Length, EqualTo, InputRequired
from flask_ckeditor import CKEditorField

import markdown
import bleach

allowed_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'a', 'strong', 'em', 'ul', 'ol', 'li', 'blockquote', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt', 'title'], 'p': ['style']}

def clean_html(html):
    """Clean html tags using bleach"""
    return bleach.clean(html, tags=allowed_tags, attributes=allowed_attributes, strip=True)

class CleanMarkdownField(CKEditorField):
    def process_formdata(self, valuelist):
        if valuelist:
            self.data = clean_html(markdown.markdown(valuelist[0]))
        else:
            self.data = ''









# WTForm for creating a notes
class CreateNoteForm(FlaskForm):
    title = StringField("Note Title", validators=[DataRequired()])
    body = CleanMarkdownField("Note Content", validators=[DataRequired()])
    encrypted = BooleanField("Encrypt Note")
    password = PasswordField("Password For Encryption")
    submit = SubmitField("Submit Note")

# Once user clicked encrypted check box, the password field will appear

# Create a form to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    password2 = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


# Create a form to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")
