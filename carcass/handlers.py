from cloudipsp import Api, Checkout
from flask import request, render_template, redirect, flash, session, abort
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from carcass import app, db
from carcass.config import Item, User


@app.route("/")
def index():
    items = Item.query.order_by(Item.price).all()

    return render_template("index.html", data=items)


@app.route("/about")
def about():
    users = User.query.order_by(User.login).all()
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
        return render_template("create.html")


@app.route("/login", methods=['GET', 'POST'])
def process_login():
    if request.method == 'POST':
        login = request.form["login"]
        password = request.form["password"]
        if login and password:
            user = User.query.filter_by(login=login).first()
            if check_password_hash(user.password, password):
                login_user(user)
                next_page = request.args.get('next')

                return redirect('/')
            else:
                flash('Ошибка в логине или пароле')
        else:
            flash('Ошибка авторизации')
    return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def process_register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    if request.method == 'POST':
        if not (login or password or password2):
            flash('Пожалуйста, заполните все поля!')
        elif password != password2:
            flash('Пароли не совпадают!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            print(new_user.login, new_user.id, sep='\n')
            try:
                db.session.add(new_user)
                db.session.commit()
                return redirect('/login')
            except:
                db.session.rollback()
                flash('Ошибка регистрации пользователя.\n'
                      'Попробуйте ввести другой логин')
                redirect('/register')
    return render_template("register.html")


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


@app.route('/basket/<title>/<int:price>', methods=['GET'])
@login_required
def add_to_basket(title, price):
    basket = session.setdefault('basket', [])
    basket.append((title, price))
    if not session.modified:
        session.modified = True
        flash('Товар успешно добавлен в корзину')
    return redirect('/')


@app.route
@app.errorhandler(404)
def page_not_found(error):
    return render_template("error404.html", title='Страница не найдено'), 404
