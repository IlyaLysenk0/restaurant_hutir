from flask import Flask, render_template, request, redirect, url_for, flash, session, g

from flask_login import login_required, current_user, login_user, logout_user # pip install flask-login

from online_restaurant_db import Session, Users, Menu, Orders, Reservation, Base
from flask_login import LoginManager
from datetime import datetime

import os
import uuid

import secrets

from geopy.distance import geodesic

app = Flask(__name__)

FILES_PATH = 'static/menu'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024  # 1MB
app.config['MAX_FORM_PARTS'] = 500

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.config['SECRET_KEY'] = '#cv)3v7w$*s3fk;5c!@y0?:?№3"9)#'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

TABLE_NUM = {'1-2':8, '3-4':11, '4+':4}
KYIV_COORDS = (50.4501, 30.5234)
MARGANETS_COORDS = (47.6396, 34.6262)
DNIPRO_COORDS = (48.4647, 35.0462)
KYIV_RADIUS_KM = 20


@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(Users).filter_by(id = user_id).first()
        if user:
            return user


@app.before_request
def generate_nonce():
   g.nonce = secrets.token_urlsafe(16)

@app.after_request
def apply_csp(response):
   csp = (
       f"default-src 'self'; "
       f"script-src 'self' 'nonce-{g.nonce}' https://cdn.jsdelivr.net; "
       f"style-src 'self' 'nonce-{g.nonce}' https://cdn.jsdelivr.net; "
       f"frame-ancestors 'none'; "
       f"base-uri 'self'; "
       f"form-action 'self';"
   )
   response.headers["Content-Security-Policy"] = csp
   return response

@app.context_processor
def inject_nonce():
   return {'nonce': g.nonce}

@app.route('/')
@app.route('/home')
def home():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return render_template('home.html')

@app.route("/register", methods = ['GET','POST'])
def register():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']

        with Session() as cursor:
            if cursor.query(Users).filter_by(email=email).first() or cursor.query(Users).filter_by(nickname = nickname).first():
                flash('Користувач з таким email або нікнеймом вже існує!', 'danger')
                return render_template('register.html',csrf_token=session["csrf_token"])

            new_user = Users(nickname=nickname, email=email)
            new_user.set_password(password)
            cursor.add(new_user)
            cursor.commit()
            cursor.refresh(new_user)
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('register.html',csrf_token=session["csrf_token"])


@app.route("/login", methods = ["GET","POST"])
def login():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        nickname = request.form['nickname']
        password = request.form['password']

        with Session() as cursor:
            user = cursor.query(Users).filter_by(nickname = nickname).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('home'))

            flash('Неправильний nickname або пароль!', 'danger')

    return render_template('login.html', csrf_token=session["csrf_token"])

base = Base()
base.create_db()


@app.route('/menu')
def menu():
    with Session() as session:
        all_positions = session.query(Menu).filter_by(active = True).all()
    return render_template('menu.html',all_positions = all_positions)

@app.route('/position/<name>', methods = ['GET','POST'])
def position(name):
    if request.method == 'POST':

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        position_name = request.form.get('name')
        position_num = request.form.get('num')
        if 'basket' not in session:
            basket = {}
            basket[position_name] = position_num
            session['basket'] = basket
        else:
            basket = session.get('basket')
            basket[position_name] = position_num
            session['basket'] = basket
        flash('Позицію додано у кошик!')
    with Session() as cursor:
        us_position = cursor.query(Menu).filter_by(active = True, name = name).first()
    return render_template('position.html', csrf_token=session["csrf_token"] ,position = us_position)

@app.route('/create_order', methods=['GET','POST'])
def create_order():
    basket = session.get('basket')
    if request.method == 'POST':

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        if not current_user:
            flash("Для оформлення замовлення необхідно бути зареєстрованим")
        else:
            if not basket:
                flash("Ваш кошик порожній")
            else:
                with Session() as cursor:
                    new_order = Orders(order_list = basket,order_time = datetime.now(), user_id=current_user.id)
                    cursor.add(new_order)
                    cursor.commit()
                    session.pop('basket')
                    cursor.refresh(new_order)
                    return redirect(f"/my_order/{new_order.id}")


    return render_template('create_order.html', csrf_token=session["csrf_token"], basket=basket)


@app.route('/my_orders')
@login_required
def my_orders():
    with Session() as cursor:
        us_order = cursor.query(Orders).filter_by(user_id = current_user.id)
    return render_template('my_orders.html',us_orders=us_order)


@app.route("/my_order/<int:id>")
@login_required
def my_order(id):
    with Session() as cursor:
        us_order = cursor.query(Orders).filter_by(id = id).first()
        total_price = 0
        for i, cnt in us_order.order_list.items():
            us_position = cursor.query(Menu).filter_by(name=i).first()
            if us_position:
                total_price += int(us_position.price) * int(cnt)
        return render_template('my_order.html', order = us_order, total_price=total_price)


@app.route("/add_position", methods=['GET','POST'])
@login_required
def add_position():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))
    if request.method == "POST":

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        name = request.form['name']
        file = request.files.get('img')
        ingredients = request.form['ingredients']
        description = request.form['description']
        price = request.form['price']
        weight = request.form['weight']

        if not file or not file.filename:
            return 'Файл не вибрано або завантаження не вдалося'
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join(FILES_PATH, unique_filename)

        with open(output_path, 'wb') as f:
            f.write(file.read())

        with Session() as cursor:
            new_position = Menu(name = name, ingredients=ingredients,description=description,price=price,weight=weight,file_name=unique_filename)
            cursor.add(new_position)
            cursor.commit()
    return render_template('add_position.html', csrf_token=session["csrf_token"])



@app.route('/reserved', methods=['GET','POST'])
@login_required
def reserved():
    if request.method == "POST":

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        table_type = request.form['table_type']
        reserved_time_start = request.form['time']
        user_latitude = request.form['latitude']
        user_longitude = request.form['longitude']

        if not user_longitude or not user_latitude:
            return 'Ви не надали інформацію про своє місцезнаходження'

        user_cords = (float(user_latitude), float(user_longitude))
        distance = geodesic(DNIPRO_COORDS, user_cords).km
        if distance > KYIV_RADIUS_KM:
            return "Ви знаходитеся в зоні недоступній для бронювання"

        with Session() as cursor:
            reserved_check = cursor.query(Reservation).filter_by(type_table = table_type).count()
            user_reserved_check = cursor.query(Reservation).filter_by(user_id=current_user.id).first()

            message = f'Бронь на {reserved_time_start}  столика на {table_type} людини успішно створено!'
            if reserved_check < TABLE_NUM.get(table_type) and not user_reserved_check:
                new_reserved = Reservation(type_table = table_type, time_start = reserved_time_start, user_id = current_user.id)
                cursor.add(new_reserved)
                cursor.commit()
            elif user_reserved_check:
                message = 'Можна мати лише одну активну бронь'
            else:
                message = 'На жаль бронь такого типу стола на разі неможлива('
            return render_template('reserved.html', message=message, csrf_token=session["csrf_token"])
    return render_template('reserved.html', csrf_token=session["csrf_token"])

# HTML - файли
@app.route('/reservations_check', methods =['GET','POST'])
@login_required
def reservations_check():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == "POST":

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        reserv_id = request.form['reserv_id']
        with Session() as cursor:
            reservetion = cursor.query(Reservation).filter_by(id = reserv_id).first()
            cursor.delete(reservetion)
            cursor.commit()
    with Session() as cursor:
        all_reservations = cursor.query(Reservation).all()
        return render_template('reservations_check.html', all_reservations=all_reservations, csrf_token=session["csrf_token"])


@app.route('/menu_check', methods =['GET','POST'])
@login_required
def menu_check():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == 'POST':

        if request.form.get("csrf_token") != session['csrf_token']:
            return "Запит заблоковано!", 403

        position_id = request.form['pos_id']
        with Session() as cursor:
            position_obj = cursor.query(Menu).filter_by(id = position_id).first()
            if 'change_status' in request.form:
                if position_obj.active:
                    position_obj.active = False
                else:
                    position_obj.active = True
            elif 'delete_position' in request.form:
                    cursor.delete(position_obj)
            cursor.commit()
    with Session() as cursor:
        all_positions = cursor.query(Menu).all()
    return render_template('check_menu.html',all_positions = all_positions, csrf_token=session["csrf_token"])


@app.route('/check_orders')
@login_required
def check_orders():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    with Session() as cursor:
        all_orders = cursor.query(Orders).all()
        return render_template('all_orders.html', all_orders=all_orders)

@app.route('/all_users')
def all_users():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    with Session() as cursor:
        all_users = cursor.query(Users).with_entities(Users.id,Users.nickname, Users.email).all()
    return render_template('all_users.html', all_users=all_users)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)


#

# /all_users
# /check_orders
# /menu_check
# /reservations_check
# /add_position

# /logout

# /reserved
# /my_order/<int:id>
# /my_orders
# /create_order
# /position/<name>
# /menu
# /register
# /login



