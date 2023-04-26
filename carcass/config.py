from flask_login import UserMixin

from carcass import db, login_manager


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    isActive = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return self.title


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))
