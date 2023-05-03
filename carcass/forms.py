from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[Email(), DataRequired('Некорректный email')])
    psw = PasswordField('Пароль', validators=[DataRequired(), Length(min=5, max=32,
                                                                     message='Пароль должен быть от 5 до 32 символов')])
    remember = BooleanField('Запомнить', default=False)
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    name = StringField('Имя пользователья', validators=[DataRequired(), Length(min=2, max=16)])
    email = EmailField('Email', validators=[Email(), DataRequired('Некорректный email')])
    psw = PasswordField('Пароль', validators=[DataRequired(), Length(min=5, max=32,
                                                                     message='Пароль должен быть от 5 до 32 символов')])
    psw2 = PasswordField('Повтор пароля', validators=[DataRequired(), EqualTo('psw',
                                                                              message='Пароли не совпадают')])
    submit = SubmitField('Регистрация')
