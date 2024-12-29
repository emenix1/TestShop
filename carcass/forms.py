from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, SelectField, SelectMultipleField
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    psw = PasswordField('Пароль', validators=[DataRequired(), Length(min=4, max=32, message='Пароль должен быть от 4 до 32 символов')])
    remember = BooleanField('Запомнить', default=False)
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    username = StringField('Имя пользователья', validators=[DataRequired(), Length(min=2, max=16)])
    psw = PasswordField('Пароль', validators=[DataRequired(), Length(min=5, max=32,
                                                                     message='Пароль должен быть от 5 до 32 символов')])
    psw2 = PasswordField('Повтор пароля', validators=[DataRequired(), EqualTo('psw',
                                                                              message='Пароли не совпадают')])
    submit = SubmitField('Регистрация')


class AddGDSForm(FlaskForm):
    title = StringField('Название товара', validators=[DataRequired(), Length(max=32)])
    price = IntegerField('Цена  $', validators=[DataRequired('Укажите цену товара')])
    category = SelectField('Категория товара', choices=[], validators=[DataRequired()])
    description = TextAreaField('Описание товара')
    submit = SubmitField('Добавить')


class CategoryForm(FlaskForm):
    name = StringField('Имя категории', validators=[DataRequired()])
    parent_id = SelectField('Supercat')
    submit = SubmitField('Добавить категорию')


class RoleForm(FlaskForm):
    name = StringField('Имя роли', validators=[DataRequired()])
    description = StringField('Описание роли')
    permissions = SelectMultipleField('Доступы', choices=[])
    submit = SubmitField('Добавить')


class PermissionForm(FlaskForm):
    name = StringField('Название доступа', validators=[DataRequired()])
    description = StringField('Описание доступа')
    submit = SubmitField('Добавить')


class ManagerCreatForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=2, max=16)])
    psw = PasswordField('Пароль', validators=[DataRequired()])
    role = SelectField('Рол', validators=[DataRequired()])
    submit = SubmitField('Добавить')