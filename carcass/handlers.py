from cloudipsp import Api, Checkout
from flask import request, render_template, redirect, flash, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from carcass import app, db
from carcass.config import Item, User
from carcass.forms import LoginForm, RegisterForm


@app.route("/")
def index():
    items = Item.query.order_by(Item.price).all()

    return render_template("index.html", data=items)


@app.route("/about")
def about():
    users = User.query.order_by(User.username).all()
    return render_template("about.html",
                           data=users)


@app.route("/create", methods=['POST', 'GET'])
@login_required
def create():
    if request.method == 'POST':
        item = Item(
            title=request.form["title"],
            price=request.form["price"],
            quantity=request.form["quantity"])
        try:
            db.session.add(item)
            db.session.commit()
            flash('Товар успешно добавлен')
            return redirect("/create")
        except:
            db.session.rollback()
            flash("Что-то пошло не так")
            return redirect("/create")

    else:
        return render_template("create_gds.html")


@app.route("/login", methods=['GET', 'POST'])
def process_login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.psw.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            rm = form.remember.data
            login_user(user, remember=rm)
            return redirect(request.args.get('next') or '/')
        else:
            flash('Ошибка в логине или пароле')
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def process_register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash_psw = generate_password_hash(form.psw.data)
        new_user = User(username=form.name.data, email=form.email.data, password=hash_psw)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
        except:
            db.session.rollback()
            flash('Ошибка регистрации пользователя.\n'
                      'Попробуйте ввести другой логин')
            redirect('/register')
    return render_template("register.html", form=form)


@app.route('/profile/<login>')
@login_required
def profile(login):
    if 'userLogged' not in session or session['userLogged'] != login:

        abort(401)
    else:
        return "User profile"


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
    if item.quantity < 0:
        flash('К сожалению, данный товар временно отсутствует')
    else:
        basket = session.setdefault('basket', [])
        basket.append((item.title, item.price))

        if not session.modified:
            session.modified = True
            flash('Товар успешно добавлен в корзину')
    return redirect('/')


@app.route('/delgds/<title>')
@login_required
def delete_from_basket(title):
    if session['basket']:
        for i in session['basket']:
            if i[0] == title:
                session['basket'].remove(i)
                session.modified = True
                flash('Товар удален с корзины')
                return redirect('/basket')
    else:
        flash('В корзине нет товаров')
        return redirect('/')
    return redirect('/')

@app.route
@app.errorhandler(404)
def page_not_found(error):
    return render_template("error404.html", title='Страница не найдено'), 404
