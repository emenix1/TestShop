from flask_login import UserMixin
from sqlalchemy import Column
from sqlalchemy.orm import backref

from carcass import db, login_manager


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    

    def __repr__(self):
        return str(self.title,
                   self.price)


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    item = db.relationship('Item', backref='product', lazy=True, cascade='all, delete')


class Role(db.Model):
    __tablename__='role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=True)
    description = db.Column(db.String(200))
    permissions = db.relationship('Permission', secondary='role_permission')

    @classmethod
    def create(cls, name, description):
        try:
            permission = cls(name=name, description=description)
            db.session.add(permission)
            db.session.commit()
            return "Разрешение успешно создано"
        except Exception as e:
            db.session.rollback()
            return f"Ошибка при создании разрешения: {str(e)}"

    def add_permissions(self, permissions):
        for perm_name in permissions:
            perm = Permission.query.filter_by(name=perm_name).first()
            if perm:
                self.permissions.append(perm)
                db.session.commit()


    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
            return "Разрешение успешно удалено"
        except Exception as e:
            db.session.rollback()
            return f"Ошибка при удалении разрешения: {str(e)}"

    def update(self, name, desc):
        self.description = desc
        self.name = name
        try:
            db.session.update(self)
            db.commit()
        except Exception as e:
            db.session.rollback()
            return f"Ошибка при изменение разрешения: {str(e)}"


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), nullable=False)
    password = db.Column(db.String(32), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref='users')


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=True)
    description = db.Column(db.String(200))


    @classmethod
    def create(cls, name, description=None):
        try:
            permission = cls(name=name, description=description)
            db.session.add(permission)
            db.session.commit()
            return "Разрешение успешно создано"
        except Exception as e:
            db.session.rollback()
            return f"Ошибка при создании разрешения: {str(e)}"

    def delete(self, name):
        try:
            db.session.delete(self)
            db.session.commit()
            return "Разрешение успешно удалено"
        except Exception as e:
            db.session.rollback()
            return f"Ошибка при удалении разрешения: {str(e)}"

    def update(self, name, desc):
        self.description = desc
        self.name = name
        try:
            db.session.update(self)
            db.commit()
        except Exception as e:
            db.session.rollback()
            return f"Ошибка при изменение разрешения: {str(e)}"



class RolePermission(db.Model):
    __tabename__='role_permission'
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), primary_key=True)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))



