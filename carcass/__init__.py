from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///TestShop.db"
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.secret_key = 'kl_as_As-#@$d-aSDADs#@@#$%$^%&^'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'process_login'
login_manager.login_message = 'Авторизуйтесь для доступа к закрытым страницам'


from carcass import config, handlers, forms


with app.app_context():
    db.create_all()

    base_permissions = [
        ('manage_roles', 'Управление ролями'),
        ('manage_permissions', 'Управление разрешениями'),
        ('manage_users', 'Управление пользователями'),
        ('edit_content', 'Редактирование контента')]

    base_role = [('superadmin', 'Администратор ситемы', ['manage_roles', 'manage_permissions', 'manage_users', 'edit_content']),
            ('admin', 'Администратор контента', ['edit_content']),('user', 'Пользователи', [])]

    test_users = [('superadmin'), ('admin'), ('user')]
    for perm_name, perm_desc in base_permissions:
        if not config.Permission.query.filter_by(name=perm_name).first():
            config.Permission.create(perm_name, perm_desc)


    for name, description, permissions in base_role:
        if not config.Role.query.filter_by(name=name).first():
            config.Role.create(name, description)
            role = config.Role.query.filter_by(name=name).first()
            role.add_permissions(permissions)


    for user in test_users:
        if not config.User.query.filter_by(username=user).first():
            role = config.Role.query.filter_by(name=user).first()
            new_user = config.User(username=user,
                                password=handlers.generate_password_hash(user),
                                role=role)
            db.session.add(new_user)
        db.session.commit()