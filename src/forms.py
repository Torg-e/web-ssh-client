from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, IntegerField, TextAreaField,
    SelectField, BooleanField, SubmitField, FloatField
)
from wtforms.validators import (
    DataRequired, Length, NumberRange, Optional, EqualTo, Regexp
)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'), Length(min=3, max=80)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Passwort is required')
    ])
    remember = BooleanField('remain signed in')
    submit = SubmitField('Log in')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Only letters, numbers, and underscores')
    ])
    password = PasswordField('Passwort', validators=[
        DataRequired(), Length(min=8, message='Password must be at least 8 characters long.')
    ])
    password_confirm = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password', message='Passwords do not match')
    ])
    submit = SubmitField('Register')


class HostForm(FlaskForm):
    name = StringField('Display name', validators=[DataRequired(), Length(max=120)])
    hostname = StringField('Hostname / IP', validators=[DataRequired(), Length(max=255)])
    port = IntegerField('Port', default=22, validators=[
        DataRequired(), NumberRange(min=1, max=65535)
    ])
    username = StringField('SSH Username', validators=[DataRequired(), Length(max=120)])
    auth_type = SelectField('Authentication', choices=[
        ('password', 'Passwort'), ('key', 'SSH Key')
    ])
    password = PasswordField('Password', validators=[Optional()])
    ssh_key = TextAreaField('SSH Private Key', validators=[Optional()])
    passphrase = PasswordField('Key Passphrase', validators=[Optional()])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    is_favorite = BooleanField('Favorite')
    color_tag = SelectField('Color-Tag', choices=[
        ('', 'None'), ('green', 'Green'), ('blue', 'Blue'), ('red', 'Red'),
        ('yellow', 'Yellow'), ('purple', 'Purple'), ('cyan', 'Cyan'), ('orange', 'Orange')
    ], validators=[Optional()])
    submit = SubmitField('Save')


class TerminalStyleForm(FlaskForm):
    name = StringField('Style Name', validators=[DataRequired(), Length(max=80)])
    background = StringField('Background', default='#1c1c1c')
    foreground = StringField('Foreground', default='#ededed')
    cursor_color = StringField('Cursor Color', default='#3ecf8e')
    selection_bg = StringField('Selection background', default='#3ecf8e4d')
    color_black = StringField('Black', default='#1c1c1c')
    color_red = StringField('Red', default='#f56565')
    color_green = StringField('Green', default='#3ecf8e')
    color_yellow = StringField('Yellow', default='#ecc94b')
    color_blue = StringField('Blue', default='#63b3ed')
    color_magenta = StringField('Magenta', default='#b794f6')
    color_cyan = StringField('Cyan', default='#76e4f7')
    color_white = StringField('White', default='#ededed')
    font_size = IntegerField('Font size', default=14, validators=[NumberRange(min=8, max=32)])
    font_family = StringField('Font', default="'JetBrains Mono', monospace")
    cursor_blink = BooleanField('Cursor blinking', default=True)
    cursor_style = SelectField('Cursor Style', choices=[
        ('block', 'Block'), ('underline', 'Underline'), ('bar', 'Bar')
    ])
    bg_image_url = StringField('Background image URL', validators=[Optional()])
    bg_opacity = FloatField('Background opacity', default=1.0,
                            validators=[NumberRange(min=0.0, max=1.0)])
    bg_blur = IntegerField('Background blur (px)', default=0,
                           validators=[NumberRange(min=0, max=50)])
    scrollback = IntegerField('Scrollback lines', default=10000,
                              validators=[NumberRange(min=100, max=100000)])
    submit = SubmitField('Save')


class SnippetForm(FlaskForm):
    category = StringField('Category', default='Generally', validators=[DataRequired(), Length(max=80)])
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    command = TextAreaField('Command', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Save')


class AIConfigForm(FlaskForm):
    provider = SelectField('AI Provider', choices=[
        ('ollama', 'Ollama (Local)'), ('openai', 'OpenAI (ChatGPT)'), ('gemini', 'Google Gemini')
    ])
    model = StringField('Modell', default='llama3', validators=[DataRequired()])
    api_key = PasswordField('API Key', validators=[Optional()])
    ollama_url = StringField('Ollama URL', default='http://localhost:11434')
    system_prompt = TextAreaField('System prompt', validators=[Optional()])
    submit = SubmitField('Save')