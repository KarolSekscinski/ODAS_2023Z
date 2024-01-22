from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, InputRequired, Regexp
from flask_ckeditor import CKEditorField
import markdown
import bleach

allowed_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'a', 'strong', 'em', 'ul', 'ol', 'li', 'blockquote', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt', 'title'], 'p': ['style']}
special_characters = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '{', '}', '[', ']',
                      '|', '\\', ':', ';', ',', '.', '?', '/', '~', '_', '#']


def clean_html(html):
    """Clean html tags using bleach"""
    return bleach.clean(html, tags=allowed_tags, attributes=allowed_attributes, strip=True)


class CleanMarkdownField(CKEditorField):
    def __init__(
            self,
            label=None,
            validators=None,
            filters=(),
            description="",
            id=None,
            default=None,
            widget=None,
            render_kw=None,
            name=None,
            _form=None,
            _prefix="",
            _translations=None,
            _meta=None,
    ):
        super().__init__(label, validators, filters, description, id, default, widget, render_kw, name, _form, _prefix,
                         _translations, _meta)
        self.data = None

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
    password = PasswordField("Password For Encryption",
                             validators=[Length(min=0, max=16, message="Password must be 16 characters long.", )])
    submit = SubmitField("Submit Note")


# WTForm for decrypting a note
class PasswordForm(FlaskForm):
    password = PasswordField("Password For Decryption",
                             validators=[InputRequired(),
                                         Length(min=16, max=16, message="Password must be 8 characters long.")])
    submit = SubmitField("Submit Password")


# Create a form to register new users
# Password must contain at least one uppercase letter, one lowercase letter, one number and one special character.
# with this requirement, entropy of passwords would be .
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(min=5, max=100), ])
    password = PasswordField("Password", validators=[DataRequired(),
                                                     Regexp(
                                                         r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])["
                                                         r"rA-Za-z\d@$!%*?&]{8,16}$",
                                                         message="Password must contain at least one uppercase "
                                                                 "letter, one lowercase letter, one number and one "
                                                                 "special character."),
                                                     Length(min=8, max=16,
                                                            message="Password must be 8-16 characters long.")])
    password2 = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    name = StringField("Name", validators=[DataRequired(), Length(min=3, max=100)])
    submit = SubmitField("Sign Me Up!")


# Create a form to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


# Create a form to use TOTP
class TOTPForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired()])
    submit = SubmitField("Submit Token")
