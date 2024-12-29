from functools import wraps

from cloudipsp import Api, Checkout
from flask import request, render_template, redirect, flash, session, url_for
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from carcass import app, db
from carcass.config import Item, User, Category, Permission, Role
from carcass.forms import LoginForm, RegisterForm, AddGDSForm, CategoryForm, RoleForm, PermissionForm, ManagerCreatForm


def requires_permission(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Авторизуйтесь для доступа к закрытым страницам')
                return redirect(url_for('process_login'))
            if current_user.role is None or not any(perm.name == permission_name for perm in current_user.role.permissions):
                    flash("Доступ ограничен")
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/admin')
@requires_permission('edit_content')
def admin_actions():
    return render_template('admin.html')



@app.route("/")
def index():
    flag = False
    if current_user.is_authenticated and any(
            perm.name in ('edit_content', 'manage_users', 'manage_permissions', 'manage_roles') for perm in
            current_user.role.permissions):
        flag=True
    items = Item.query.all()
    categories = Category.query.all()
    return render_template("index.html", data=items, categories=categories,flag=flag)


@app.route('/category/<int:cat>')
def sort_by_cat(cat):
    flag = False
    if current_user.is_authenticated and any(
            perm.name in ('edit_content', 'manage_users', 'manage_permissions', 'manage_roles') for perm in
            current_user.role.permissions):
        flag = True
    items = Item.query.filter_by(category_id=cat).all()
    categories = Category.query.all()
    return render_template("index.html", data=items, categories=categories, flag=flag)


@app.route("/about")
def about():
    users = User.query.order_by(User.username).all()
    return render_template("about.html",
                           data=users)


@app.route("/create_gds", methods=['POST', 'GET'])
@login_required
@requires_permission('edit_content')
def create():
    form = AddGDSForm()
    form.category.choices =['Выберите категорию'] + [(c.id, c.name) for c in Category.query.all()]
    if form.validate_on_submit():
        category_id = 0 if form.category.data == 'Выберите категорию' else int(form.category.data[1])
        item = Item(
            title=form.title.data,
            price=form.price.data,
            description=form.description.data,
            category_id=category_id)
        try:
            db.session.add(item)
            db.session.commit()
            flash('Товар успешно добавлен')
            return redirect(url_for('create'))
        except Exception as e:
            db.session.rollback()
            flash(f"Ошибка при добавлении товара: {str(e)}")
            return redirect(url_for('create'))
    else:
        return render_template("create_gds.html", form=form)


@app.route("/login", methods=['GET', 'POST'])
def process_login():
    if current_user.is_authenticated:
        flash(f'Вы уже авторизованы как "{current_user.username}"')
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        password = form.psw.data
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, password):
            rm = form.remember.data
            login_user(user, remember=rm)
            return redirect(request.args.get('next') or url_for('index'))
        else:
            flash('Ошибка в логине или пароле')
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Деавторизован')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def process_register():
    form = RegisterForm()
    if form.validate_on_submit():
        role_user = Role.query.filter_by(name='user').first()
        hash_psw = generate_password_hash(form.psw.data)
        new_user = User(username=form.username.data,
                        password=hash_psw,
                        role=role_user)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('process_login'))

        except Exception as e:
            db.session.rollback()
            flash(f"""Ошибка регистрации пользователя.\n
                  Попробуйте ввести другой логин:  {str(e)}""")
            return redirect(url_for('process_register'))
    return render_template("register.html", form=form)


@app.route('/buy/<int:id>')
@login_required
def item_buy(id):
    item = Item.query.get(id)
    api = Api(merchant_id=1396424,
              secret_key='test')
    checkout = Checkout(api=api)
    data = {
        "currency": "USD",
        "amount": str(item.price) + "00"
    }
    url = checkout.url(data).get('checkout_url')
    return redirect(url)


@app.route('/baskbuy')
@login_required
def bask_bye():
    amount = 0
    for _, price in session['basket']:
        amount += price
    api = Api(merchant_id=1396424,
              secret_key='test')
    checkout = Checkout(api=api)
    data = {
        "currency": "USD",
        "amount": str(amount) + "00"
    }
    session.pop('basket')
    url = checkout.url(data).get('checkout_url')

    return redirect(url)


@app.route('/basket')
@login_required
def show_basket():
    data = session.get('basket', [])
    return render_template('basket.html', data=data)


@app.route('/basket/<title>', methods=['GET'])
@login_required
def add_to_basket(title):
    item = Item.query.filter_by(title=title).first()
    basket = session.setdefault('basket', [])
    basket.append((item.title, item.price))

    if not session.modified:
        session.modified = True
        flash('Товар успешно добавлен в корзину')
    return redirect(url_for('index'))


@app.route('/delgds/<title>')
@login_required
def delete_from_basket(title):
    if session['basket']:
        for i in session['basket']:
            if i[0] == title:
                session['basket'].remove(i)
                session.modified = True
                flash('Товар удален с корзины')
                return redirect(url_for('show_basket'))
    else:
        flash('В корзине нет товаров')
    return redirect(url_for('index'))



@app.route('/categories', methods=['GET', 'POST'])
@requires_permission('edit_content')
def show_categories():
    form = CategoryForm()
    categories = Category.query.all()
    form.parent_id.choices =['Выберите категорию'] + [(c.id, c.name) for c in categories]
    if form.validate_on_submit():
        parent_id = 0 if form.parent_id.data == 'Выберите категорию' else int(form.parent_id.data[1])
        new_category = Category(name=form.name.data,
                                parent_id=parent_id)
        try:
            db.session.add(new_category)
            db.session.commit()
            flash('Катеория успешно добавлено')
            return redirect(url_for('show_categories'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error:  {str(e)}")
            return redirect(url_for('show_categories'))
    return render_template('categories.html', form=form, categories=categories)



@app.route('/delete_category/<int:id>')
@requires_permission('edit_content')
def del_category(id):
    category = Category.query.get_or_404(id)
    try:
        db.session.delete(category)
        db.session.commit()
    except Exception as e:
        flash(f"Что-то пошло не так: {str(e)}")
    return redirect(url_for('show_categories'))


@app.route('/update_category/<int:id>')
@requires_permission('edit_content')
def update_category(id):
    form = CategoryForm()
    categories = Category.query.all()
    form.parent_id.choices = ['Выберите категорию'] + [(c.id, c.name) for c in categories]
    category = Category.query.get(id)
    if form.validate_on_submit():
        parent_id = 0 if form.parent_id.data == 'Выберите категорию' else int(form.parent_id.data[1])
        category.name = form.name.data
        category.parent_id = parent_id
        db.session.commit()
        return redirect('/categories')
    return render_template('edit_category.html', categories=categories)



@app.route('/roles', methods=['POST', 'GET'])
@requires_permission('manage_roles')
def role_actions():
    form = RoleForm()
    roles = Role.query.all()
    permissions = Permission.query.all()
    form.permissions.choices = [(p.name, p.description) for p in permissions]
    if form.validate_on_submit():
        permissions = 0 if form.permissions.data == 'Выберите категорию' else [perm for perm in form.permissions.data]
        Role.create(form.name.data, form.description.data)
        role = Role.query.filter_by(name=form.name.data).first()
        role.add_permissions(permissions)
        return redirect(url_for('role_actions'))
    return render_template('roles.html', form=form, roles=roles)


@app.route('/roles/delete/<int:id>')
@requires_permission('manage_roles')
def delete_role(id):
    role = Role.query.get_or_404(id)
    try:
        db.session.delete(role)
        db.session.commit()
    except Exception as e:
        flash(f"Что-то пошло не так: {str(e)}")
    return redirect(url_for('role_actions'))


@app.route('/permissions', methods=['POST', 'GET'])
@requires_permission('manage_permissions')
def permission_actions():
    form = PermissionForm()
    permissions = Permission.query.all()
    if form.validate_on_submit():
        if not Permission.query.get(form.name.data):
            Permission.create(form.name.data, form.description.data)
        return redirect(url_for('role_actions'))
    return render_template('permission.html', form=form, permissions=permissions)


@app.route('/managers/delete/<int:id>')
@requires_permission('manage_roles')
def delete_manager(id):
    manager = User.query.get_or_404(id)
    try:
        db.session.delete(manager)
        db.session.commit()
    except Exception as e:
        flash(f"Что-то пошло не так: {str(e)}")
    return redirect(url_for('manager_control'))

@app.route('/managers', methods=['POST', 'GET'])
@requires_permission('manage_users')
def manager_control():
    managers = User.query.filter(User.role_id != 3).all()
    form = ManagerCreatForm()
    roles = Role.query.all()
    form.role.choices = [(r.id, r.name) for r in roles]
    if form.validate_on_submit():
        role = Role.query.get_or_404(form.role.data)
        hash_psw = generate_password_hash(form.psw.data)
        new_user = User(
            username=form.username.data,
            password=hash_psw,
            role=role
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('manager_control'))

        except Exception as e:
            db.session.rollback()
            flash(f"""Ошибка регистрации менеджера.  {str(e)}""")
    return render_template('managers.html', form=form, managers=managers)


@app.errorhandler(404)
def page_not_found(error):
    return render_template("error404.html", title='Страница не найдено'), 404

