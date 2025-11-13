from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = 'shop.db'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # Пользователи
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')
    # Товары
    c.execute('''
    CREATE TABLE IF NOT EXISTS positions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        price REAL NOT NULL,
        description TEXT,
        image TEXT
    )''')
    # Корзина пользователя
    c.execute('''
    CREATE TABLE IF NOT EXISTS carts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        position_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(position_id) REFERENCES positions(id),
        UNIQUE(user_id, position_id)
    )''')
    conn.commit()
    conn.close()

def query_db(query, args=(), one=False, commit=False):
    conn = get_db()
    cur = conn.execute(query, args)
    if commit:
        conn.commit()
        conn.close()
        return
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/')
def index():
    positions = query_db('SELECT * FROM positions')
    return render_template('index.html', positions=positions)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if not username or not password:
            flash('Введите имя пользователя и пароль')
            return redirect(url_for('register'))
        existing = query_db('SELECT * FROM users WHERE username=?', (username,), one=True)
        if existing:
            flash('Имя уже занято')
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
        query_db('INSERT INTO users (username, password_hash) VALUES (?,?)', (username, pw_hash), commit=True)
        flash('Регистрация успешна. Войдите в систему.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        user = query_db('SELECT * FROM users WHERE username=?', (username,), one=True)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Добро пожаловать, ' + user['username'])
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы')
    return redirect(url_for('index'))

@app.route('/add_position', methods=['GET','POST'])
def add_position():
    if 'user_id' not in session:
        flash('Войдите для добавления товаров')
        return redirect(url_for('login'))
    if request.method=='POST':
        name = request.form['name'].strip()
        price = request.form['price'].strip()
        description = request.form['description'].strip()
        file = request.files.get('image')

        if not name or not price:
            flash('Название и цена обязательны')
            return redirect(url_for('add_position'))
        try:
            price_val = float(price)
        except:
            flash('Цена должна быть числом')
            return redirect(url_for('add_position'))

        image_filename = None
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{int(datetime.now().timestamp())}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename
            else:
                flash('Допустимые форматы картинки: png, jpg, jpeg, gif')
                return redirect(url_for('add_position'))

        try:
            query_db('INSERT INTO positions (name, price, description, image) VALUES (?,?,?,?)',
                     (name, price_val, description, image_filename), commit=True)
            flash('Товар добавлен')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Товар с таким названием уже существует')
            return redirect(url_for('add_position'))
    return render_template('add_position.html')

@app.route('/add_to_cart/<int:position_id>', methods=['POST'])
def add_to_cart(position_id):
    if 'user_id' not in session:
        flash('Войдите для добавления в корзину')
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing = query_db('SELECT * FROM carts WHERE user_id=? AND position_id=?', (user_id, position_id), one=True)
    if existing:
        query_db('UPDATE carts SET quantity=quantity+1 WHERE id=?', (existing['id'],), commit=True)
    else:
        query_db('INSERT INTO carts (user_id, position_id, quantity) VALUES (?,?,1)', (user_id, position_id), commit=True)
    flash('Товар добавлен в корзину')
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Войдите, чтобы посмотреть корзину')
        return redirect(url_for('login'))
    user_id = session['user_id']
    items = query_db('''
        SELECT carts.id as cart_id, positions.id as position_id, positions.name, positions.price, positions.image, carts.quantity 
        FROM carts
        JOIN positions ON carts.position_id=positions.id
        WHERE carts.user_id=?
    ''', (user_id,))
    total = sum(item['price']*item['quantity'] for item in items)
    return render_template('cart.html', items=items, total=total)

@app.route('/remove_from_cart/<int:cart_id>', methods=['POST'])
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        flash('Войдите для управления корзиной')
        return redirect(url_for('login'))
    # Удаляем элемент корзины, проверяем, принадлежит ли он пользователю
    user_id = session['user_id']
    item = query_db('SELECT * FROM carts WHERE id=? AND user_id=?', (cart_id, user_id), one=True)
    if item:
        query_db('DELETE FROM carts WHERE id=?', (cart_id,), commit=True)
        flash('Товар удалён из корзины')
    else:
        flash('Ошибка удаления')
    return redirect(url_for('cart'))

if __name__=='__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
