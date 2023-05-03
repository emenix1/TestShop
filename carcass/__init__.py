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
