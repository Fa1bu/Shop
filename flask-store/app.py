from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['DATABASE'] = 'store.db'

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Таблица пользователей
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    
    # Таблица товаров
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  price REAL NOT NULL,
                  image TEXT,
                  category TEXT,
                  stock INTEGER DEFAULT 0,
                  created_by_user_id INTEGER,
                  FOREIGN KEY (created_by_user_id) REFERENCES users(id))''')
    
    # Добавляем поле created_by_user_id если его нет (миграция)
    try:
        c.execute('ALTER TABLE products ADD COLUMN created_by_user_id INTEGER')
    except sqlite3.OperationalError:
        pass  # Колонка уже существует
    
    # Добавляем поле specifications если его нет (миграция)
    try:
        c.execute('ALTER TABLE products ADD COLUMN specifications TEXT')
    except sqlite3.OperationalError:
        pass  # Колонка уже существует
    
    # Таблица корзины
    c.execute('''CREATE TABLE IF NOT EXISTS cart
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  product_id INTEGER NOT NULL,
                  quantity INTEGER DEFAULT 1,
                  FOREIGN KEY (user_id) REFERENCES users(id),
                  FOREIGN KEY (product_id) REFERENCES products(id))''')
    
    # Таблица избранного
    c.execute('''CREATE TABLE IF NOT EXISTS favorites
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  product_id INTEGER NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users(id),
                  FOREIGN KEY (product_id) REFERENCES products(id),
                  UNIQUE(user_id, product_id))''')
    
    # Таблица отзывов
    c.execute('''CREATE TABLE IF NOT EXISTS reviews
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  product_id INTEGER NOT NULL,
                  rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
                  comment TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id),
                  FOREIGN KEY (product_id) REFERENCES products(id))''')

    # Таблица баннеров
    c.execute('''CREATE TABLE IF NOT EXISTS banners
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  image_url TEXT NOT NULL,
                  link_url TEXT,
                  is_active INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  created_by_user_id INTEGER,
                  FOREIGN KEY (created_by_user_id) REFERENCES users(id))''')
    
    # Добавляем поле created_by_user_id если его нет (миграция)
    try:
        c.execute('ALTER TABLE banners ADD COLUMN created_by_user_id INTEGER')
    except sqlite3.OperationalError:
        pass  # Колонка уже существует

# Декоратор для проверки авторизации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Получение соединения с БД
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Работа с гостевой корзиной и избранным
def get_guest_cart():
    return session.get('guest_cart', {})

def save_guest_cart(cart):
    session['guest_cart'] = cart

def get_guest_favorites():
    return session.get('guest_favorites', [])

def save_guest_favorites(favorites):
    session['guest_favorites'] = favorites

def merge_guest_cart_to_user(user_id):
    guest_cart = session.pop('guest_cart', {})
    if not guest_cart:
        return
    conn = get_db()
    for product_id_str, quantity in guest_cart.items():
        try:
            product_id = int(product_id_str)
            quantity = int(quantity)
        except (TypeError, ValueError):
            continue
        if quantity <= 0:
            continue
        existing = conn.execute(
            'SELECT id FROM cart WHERE user_id = ? AND product_id = ?',
            (user_id, product_id)
        ).fetchone()
        if existing:
            conn.execute(
                'UPDATE cart SET quantity = quantity + ? WHERE id = ?',
                (quantity, existing['id'])
            )
        else:
            conn.execute(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                (user_id, product_id, quantity)
            )
    conn.commit()
    conn.close()

def merge_guest_favorites_to_user(user_id):
    guest_favorites = session.pop('guest_favorites', [])
    if not guest_favorites:
        return
    conn = get_db()
    for product_id_str in guest_favorites:
        try:
            product_id = int(product_id_str)
        except (TypeError, ValueError):
            continue
        try:
            conn.execute(
                'INSERT OR IGNORE INTO favorites (user_id, product_id) VALUES (?, ?)',
                (user_id, product_id)
            )
        except sqlite3.IntegrityError:
            continue
    conn.commit()
    conn.close()

# Главная страница
@app.route('/')
def index():
    conn = get_db()
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    
    query = 'SELECT * FROM products WHERE 1=1'
    params = []
    
    if search:
        like_search = f'%{search}%'
        query += ' AND (name LIKE ? OR description LIKE ? OR category LIKE ?)'
        params.extend([like_search, like_search, like_search])
    
    if category:
        query += ' AND category = ?'
        params.append(category.strip())
    
    query += ' ORDER BY id'
    products = conn.execute(query, params).fetchall()
    
    # Получаем категории (исключаем NULL и пустые значения)
    categories = conn.execute('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()
    banners = conn.execute('SELECT * FROM banners WHERE is_active = 1 ORDER BY created_at DESC').fetchall()

    if 'user_id' in session:
        favorite_rows = conn.execute(
            'SELECT product_id FROM favorites WHERE user_id = ?',
            (session['user_id'],)
        ).fetchall()
        favorite_product_ids = {row['product_id'] for row in favorite_rows}
    else:
        favorite_product_ids = set()
        for pid in get_guest_favorites():
            try:
                favorite_product_ids.add(int(pid))
            except (TypeError, ValueError):
                continue
    
    conn.close()
    
    return render_template('index.html', products=products, categories=categories, 
                         search=search, selected_category=category,
                         favorite_product_ids=favorite_product_ids,
                         banners=banners)

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('Все поля обязательны для заполнения', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')
        
        conn = get_db()
        
        # Проверка существующего пользователя
        if conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                       (username, email)).fetchone():
            flash('Пользователь с таким именем или email уже существует', 'error')
            conn.close()
            return render_template('register.html')
        
        # Создание пользователя
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Регистрация успешна! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Введите email и пароль', 'error')
            return render_template('login.html')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            merge_guest_cart_to_user(user['id'])
            merge_guest_favorites_to_user(user['id'])
            flash(f'Добро пожаловать, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный email или пароль', 'error')
    
    return render_template('login.html')

# Выход
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# Страница товара
@app.route('/product/<int:product_id>')
def product(product_id):
    conn = get_db()
    product = conn.execute('''SELECT p.*, u.username as creator_username
                             FROM products p
                             LEFT JOIN users u ON p.created_by_user_id = u.id
                             WHERE p.id = ?''', (product_id,)).fetchone()
    
    if not product:
        flash('Товар не найден', 'error')
        conn.close()
        return redirect(url_for('index'))
    
    # Получаем отзывы
    reviews = conn.execute('''SELECT r.*, u.username 
                             FROM reviews r 
                             JOIN users u ON r.user_id = u.id 
                             WHERE r.product_id = ? 
                             ORDER BY r.created_at DESC''', 
                          (product_id,)).fetchall()
    
    # Проверяем, в избранном ли товар
    in_favorites = False
    if 'user_id' in session:
        favorite = conn.execute('SELECT id FROM favorites WHERE user_id = ? AND product_id = ?',
                              (session['user_id'], product_id)).fetchone()
        in_favorites = favorite is not None
    else:
        in_favorites = str(product_id) in get_guest_favorites()
    
    conn.close()
    
    return render_template('product.html', product=product, reviews=reviews, 
                         in_favorites=in_favorites)

# Добавление отзыва
@app.route('/product/<int:product_id>/review', methods=['POST'])
@login_required
def add_review(product_id):
    rating = request.form.get('rating')
    comment = request.form.get('comment', '')
    
    if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        flash('Выберите оценку от 1 до 5', 'error')
        return redirect(url_for('product', product_id=product_id))
    
    conn = get_db()
    conn.execute('''INSERT INTO reviews (user_id, product_id, rating, comment) 
                   VALUES (?, ?, ?, ?)''',
                (session['user_id'], product_id, int(rating), comment))
    conn.commit()
    conn.close()
    
    flash('Отзыв добавлен', 'success')
    return redirect(url_for('product', product_id=product_id))

# Удаление отзыва
@app.route('/review/<int:review_id>/delete', methods=['POST'])
@login_required
def delete_review(review_id):
    conn = get_db()
    review = conn.execute('SELECT * FROM reviews WHERE id = ?', (review_id,)).fetchone()
    
    if review and review['user_id'] == session['user_id']:
        product_id = review['product_id']
        conn.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
        conn.commit()
        flash('Отзыв удален', 'success')
    else:
        flash('Вы не можете удалить этот отзыв', 'error')
    
    conn.close()
    return redirect(url_for('product', product_id=review['product_id']))

# Добавление в корзину
@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    product_id = request.form.get('product_id')
    quantity_raw = request.form.get('quantity', 1)
    try:
        product_id = int(product_id)
        quantity = max(1, int(quantity_raw))
    except (TypeError, ValueError):
        flash('Некорректный товар или количество', 'error')
        return redirect(request.referrer or url_for('index'))
    
    conn = get_db()
    product = conn.execute('SELECT id FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(request.referrer or url_for('index'))
    
    if 'user_id' in session:
        existing = conn.execute('SELECT * FROM cart WHERE user_id = ? AND product_id = ?',
                               (session['user_id'], product_id)).fetchone()
        
        if existing:
            conn.execute('UPDATE cart SET quantity = quantity + ? WHERE id = ?',
                        (quantity, existing['id']))
        else:
            conn.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                        (session['user_id'], product_id, quantity))
        conn.commit()
        conn.close()
    else:
        conn.close()
        guest_cart = get_guest_cart()
        key = str(product_id)
        guest_cart[key] = guest_cart.get(key, 0) + quantity
        save_guest_cart(guest_cart)
    
    flash('Товар добавлен в корзину', 'success')
    return redirect(request.referrer or url_for('index'))

# Корзина
@app.route('/cart')
def cart():
    conn = get_db()
    cart_items = []
    total = 0
    
    if 'user_id' in session:
        rows = conn.execute('''SELECT c.*, p.name, p.price, p.image, p.id as product_id
                               FROM cart c
                               JOIN products p ON c.product_id = p.id
                               WHERE c.user_id = ?
                               ORDER BY c.id''',
                            (session['user_id'],)).fetchall()
        for row in rows:
            cart_items.append({
                'cart_id': row['id'],
                'product_id': row['product_id'],
                'name': row['name'],
                'price': row['price'],
                'image': row['image'],
                'quantity': row['quantity']
            })
            total += row['price'] * row['quantity']
    else:
        guest_cart = get_guest_cart()
        if guest_cart:
            product_ids = []
            for pid in guest_cart.keys():
                try:
                    product_ids.append(int(pid))
                except (TypeError, ValueError):
                    continue
            products_by_id = {}
            if product_ids:
                placeholders = ','.join(['?'] * len(product_ids))
                products = conn.execute(
                    f'SELECT * FROM products WHERE id IN ({placeholders})',
                    tuple(product_ids)
                ).fetchall()
                products_by_id = {product['id']: product for product in products}
            for pid_str, quantity in guest_cart.items():
                try:
                    pid = int(pid_str)
                except (TypeError, ValueError):
                    continue
                product = products_by_id.get(pid)
                if not product:
                    continue
                cart_items.append({
                    'cart_id': None,
                    'product_id': product['id'],
                    'name': product['name'],
                    'price': product['price'],
                    'image': product['image'],
                    'quantity': quantity
                })
                total += product['price'] * quantity
    
    conn.close()
    
    return render_template('cart.html', cart_items=cart_items, total=total)

# Обновление количества в корзине
@app.route('/cart/update', methods=['POST'])
def update_cart():
    quantity_raw = request.form.get('quantity', 1)
    try:
        quantity = int(quantity_raw)
    except (TypeError, ValueError):
        flash('Некорректное количество', 'error')
        return redirect(url_for('cart'))
    
    if 'user_id' in session:
        cart_id = request.form.get('cart_id')
        if not cart_id:
            flash('Не удалось обновить товар', 'error')
            return redirect(url_for('cart'))
        conn = get_db()
        if quantity <= 0:
            conn.execute('DELETE FROM cart WHERE id = ? AND user_id = ?',
                        (cart_id, session['user_id']))
            flash('Товар удален из корзины', 'info')
        else:
            conn.execute('UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?',
                        (quantity, cart_id, session['user_id']))
            flash('Корзина обновлена', 'success')
        conn.commit()
        conn.close()
    else:
        product_id = request.form.get('product_id')
        guest_cart = get_guest_cart()
        if not product_id or product_id not in guest_cart:
            flash('Товар не найден в корзине', 'error')
            return redirect(url_for('cart'))
        if quantity <= 0:
            guest_cart.pop(product_id, None)
            flash('Товар удален из корзины', 'info')
        else:
            guest_cart[product_id] = quantity
            flash('Корзина обновлена', 'success')
        save_guest_cart(guest_cart)
    
    return redirect(url_for('cart'))

# Удаление из корзины
@app.route('/cart/remove', methods=['POST'])
def remove_from_cart():
    if 'user_id' in session:
        cart_id = request.form.get('cart_id')
        conn = get_db()
        conn.execute('DELETE FROM cart WHERE id = ? AND user_id = ?',
                    (cart_id, session['user_id']))
        conn.commit()
        conn.close()
    else:
        product_id = request.form.get('product_id')
        if not product_id:
            flash('Не удалось удалить товар', 'error')
            return redirect(url_for('cart'))
        guest_cart = get_guest_cart()
        guest_cart.pop(product_id, None)
        save_guest_cart(guest_cart)
    
    flash('Товар удален из корзины', 'info')
    return redirect(url_for('cart'))

# Добавление в избранное
@app.route('/favorites/add', methods=['POST'])
def add_to_favorites():
    product_id = request.form.get('product_id')
    try:
        product_id = int(product_id)
    except (TypeError, ValueError):
        flash('Некорректный товар', 'error')
        return redirect(request.referrer or url_for('index'))
    
    if 'user_id' in session:
        conn = get_db()
        try:
            conn.execute('INSERT INTO favorites (user_id, product_id) VALUES (?, ?)',
                        (session['user_id'], product_id))
            conn.commit()
            flash('Товар добавлен в избранное', 'success')
        except sqlite3.IntegrityError:
            flash('Товар уже в избранном', 'info')
        finally:
            conn.close()
    else:
        favorites = get_guest_favorites()
        key = str(product_id)
        if key in favorites:
            flash('Товар уже в избранном', 'info')
        else:
            favorites.append(key)
            save_guest_favorites(favorites)
            flash('Товар добавлен в избранное', 'success')
    
    return redirect(request.referrer or url_for('index'))

# Удаление из избранного
@app.route('/favorites/remove', methods=['POST'])
def remove_from_favorites():
    product_id = request.form.get('product_id')
    if not product_id:
        flash('Не удалось удалить товар', 'error')
        return redirect(request.referrer or url_for('index'))
    
    if 'user_id' in session:
        conn = get_db()
        conn.execute('DELETE FROM favorites WHERE user_id = ? AND product_id = ?',
                    (session['user_id'], product_id))
        conn.commit()
        conn.close()
    else:
        favorites = get_guest_favorites()
        key = str(product_id)
        if key in favorites:
            favorites.remove(key)
            save_guest_favorites(favorites)
    
    flash('Товар удален из избранного', 'info')
    return redirect(request.referrer or url_for('index'))

# Страница избранного
@app.route('/favorites')
def favorites():
    conn = get_db()
    products = []
    
    if 'user_id' in session:
        products = conn.execute('''SELECT p.* 
                                   FROM products p
                                   JOIN favorites f ON p.id = f.product_id
                                   WHERE f.user_id = ?
                                   ORDER BY f.id DESC''',
                               (session['user_id'],)).fetchall()
    else:
        favorite_ids = get_guest_favorites()
        favorite_ids_int = []
        for pid in favorite_ids:
            try:
                favorite_ids_int.append(int(pid))
            except (TypeError, ValueError):
                continue
        if favorite_ids_int:
            placeholders = ','.join(['?'] * len(favorite_ids_int))
            rows = conn.execute(
                f'SELECT * FROM products WHERE id IN ({placeholders})',
                tuple(favorite_ids_int)
            ).fetchall()
            products_map = {row['id']: row for row in rows}
            products = [products_map[pid] for pid in favorite_ids_int if pid in products_map]
    
    conn.close()
    
    return render_template('favorites.html', products=products)

# Оформление заказа
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    conn = get_db()
    cart_items = conn.execute('''SELECT c.*, p.name, p.price
                                 FROM cart c
                                 JOIN products p ON c.product_id = p.id
                                 WHERE c.user_id = ?''',
                             (session['user_id'],)).fetchall()
    
    if not cart_items:
        flash('Корзина пуста', 'error')
        conn.close()
        return redirect(url_for('cart'))
    
    # Очищаем корзину
    conn.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    flash('Спасибо за покупку! Заказ оформлен', 'success')
    return redirect(url_for('index'))

# Управление баннерами
@app.route('/banners', methods=['GET', 'POST'])
@login_required
def manage_banners():
    conn = get_db()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        image_url = request.form.get('image_url', '').strip()
        link_url = request.form.get('link_url', '').strip() or None
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        if not title or not image_url:
            flash('Заполните название и ссылку на изображение', 'error')
        else:
            conn.execute(
                'INSERT INTO banners (title, image_url, link_url, is_active, created_by_user_id) VALUES (?, ?, ?, ?, ?)',
                (title, image_url, link_url, is_active, session['user_id'])
            )
            conn.commit()
            flash('Баннер добавлен', 'success')
    banners = conn.execute('SELECT * FROM banners ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('banners.html', banners=banners)

@app.route('/banners/<int:banner_id>/toggle', methods=['POST'])
@login_required
def toggle_banner(banner_id):
    conn = get_db()
    banner = conn.execute('SELECT is_active, created_by_user_id FROM banners WHERE id = ?', (banner_id,)).fetchone()
    if not banner:
        conn.close()
        flash('Баннер не найден', 'error')
        return redirect(url_for('manage_banners'))
    
    # Проверяем, что пользователь является создателем баннера
    if banner['created_by_user_id'] is not None and banner['created_by_user_id'] != session['user_id']:
        conn.close()
        flash('Вы можете изменять только свои баннеры', 'error')
        return redirect(url_for('manage_banners'))
    
    new_state = 0 if banner['is_active'] else 1
    conn.execute('UPDATE banners SET is_active = ? WHERE id = ?', (new_state, banner_id))
    conn.commit()
    conn.close()
    flash('Статус баннера обновлен', 'success')
    return redirect(url_for('manage_banners'))

@app.route('/banners/<int:banner_id>/delete', methods=['POST'])
@login_required
def delete_banner(banner_id):
    conn = get_db()
    banner = conn.execute('SELECT created_by_user_id FROM banners WHERE id = ?', (banner_id,)).fetchone()
    
    if not banner:
        conn.close()
        flash('Баннер не найден', 'error')
        return redirect(url_for('manage_banners'))
    
    # Проверяем, что пользователь является создателем баннера
    if banner['created_by_user_id'] is not None and banner['created_by_user_id'] != session['user_id']:
        conn.close()
        flash('Вы можете удалять только свои баннеры', 'error')
        return redirect(url_for('manage_banners'))
    
    conn.execute('DELETE FROM banners WHERE id = ?', (banner_id,))
    conn.commit()
    conn.close()
    flash('Баннер удален', 'info')
    return redirect(url_for('manage_banners'))

@app.route('/account')
@login_required
def account():
    conn = get_db()
    user = conn.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    cart_count_row = conn.execute(
        'SELECT COALESCE(SUM(quantity), 0) as total FROM cart WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()
    favorites_count_row = conn.execute(
        'SELECT COUNT(*) as total FROM favorites WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()
    reviews = conn.execute(
        '''SELECT r.rating, r.comment, r.created_at, p.name
           FROM reviews r
           JOIN products p ON r.product_id = p.id
           WHERE r.user_id = ?
           ORDER BY r.created_at DESC
           LIMIT 5''',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    cart_count = cart_count_row['total'] if cart_count_row else 0
    favorites_count = favorites_count_row['total'] if favorites_count_row else 0

    return render_template(
        'account.html',
        user=user,
        cart_count=cart_count,
        favorites_count=favorites_count,
        reviews=reviews
    )

@app.route('/products/new', methods=['GET', 'POST'])
@login_required
def add_product():
    # Дополнительная проверка авторизации
    if 'user_id' not in session:
        flash('Для добавления товара необходимо войти в систему', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()
        image = request.form.get('image', '').strip()
        category = request.form.get('category', '').strip()
        stock_raw = request.form.get('stock', '').strip() or '0'
        specifications = request.form.get('specifications', '').strip()

        if not all([name, description, price_raw, image, category]):
            flash('Заполните все обязательные поля', 'error')
            return render_template('product_form.html')

        try:
            price = float(price_raw)
            if price < 0:
                raise ValueError
        except ValueError:
            flash('Некорректная цена', 'error')
            return render_template('product_form.html')

        try:
            stock = int(stock_raw)
            if stock < 0:
                raise ValueError
        except ValueError:
            flash('Некорректное количество на складе', 'error')
            return render_template('product_form.html')

        conn = get_db()
        cursor = conn.execute(
            '''INSERT INTO products (name, description, price, image, category, stock, created_by_user_id, specifications)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (name, description, price, image, category, stock, session['user_id'], specifications)
        )
        conn.commit()
        product_id = cursor.lastrowid
        conn.close()

        flash('Товар успешно добавлен', 'success')
        return redirect(url_for('product', product_id=product_id))

    return render_template('product_form.html')

# Редактирование товара
@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    conn = get_db()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(url_for('index'))
    
    # Проверяем, что пользователь является создателем товара
    if product['created_by_user_id'] is not None and product['created_by_user_id'] != session['user_id']:
        conn.close()
        flash('Вы можете редактировать только свои товары', 'error')
        return redirect(url_for('product', product_id=product_id))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()
        image = request.form.get('image', '').strip()
        category = request.form.get('category', '').strip()
        stock_raw = request.form.get('stock', '').strip() or '0'
        specifications = request.form.get('specifications', '').strip()

        if not all([name, description, price_raw, image, category]):
            flash('Заполните все обязательные поля', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True)

        try:
            price = float(price_raw)
            if price < 0:
                raise ValueError
        except ValueError:
            flash('Некорректная цена', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True)

        try:
            stock = int(stock_raw)
            if stock < 0:
                raise ValueError
        except ValueError:
            flash('Некорректное количество на складе', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True)

        conn.execute(
            '''UPDATE products SET name = ?, description = ?, price = ?, image = ?, category = ?, stock = ?, specifications = ?
               WHERE id = ?''',
            (name, description, price, image, category, stock, specifications, product_id)
        )
        conn.commit()
        conn.close()

        flash('Товар успешно обновлен', 'success')
        return redirect(url_for('product', product_id=product_id))
    
    conn.close()
    return render_template('product_form.html', product=product, is_edit=True)

# Удаление товара
@app.route('/product/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    conn = get_db()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(url_for('index'))
    
    # Проверяем, что пользователь является создателем товара
    if product['created_by_user_id'] is not None and product['created_by_user_id'] != session['user_id']:
        conn.close()
        flash('Вы можете удалять только свои товары', 'error')
        return redirect(url_for('product', product_id=product_id))
    
    # Удаляем связанные данные
    conn.execute('DELETE FROM cart WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM favorites WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM reviews WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    
    flash('Товар успешно удален', 'info')
    return redirect(url_for('index'))

# Редактирование баннера
@app.route('/banners/<int:banner_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_banner(banner_id):
    conn = get_db()
    is_new = (banner_id == 0)
    banner = None if is_new else conn.execute('SELECT * FROM banners WHERE id = ?', (banner_id,)).fetchone()
    
    if not is_new and not banner:
        conn.close()
        flash('Баннер не найден', 'error')
        return redirect(url_for('manage_banners'))
    
    # Проверяем, что пользователь является создателем баннера (только для редактирования существующего)
    if not is_new and banner['created_by_user_id'] is not None and banner['created_by_user_id'] != session['user_id']:
        conn.close()
        flash('Вы можете редактировать только свои баннеры', 'error')
        return redirect(url_for('manage_banners'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        image_url = request.form.get('image_url', '').strip()
        link_url = request.form.get('link_url', '').strip() or None
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        
        if not title or not image_url:
            flash('Заполните название и ссылку на изображение', 'error')
            conn.close()
            return render_template('banner_form.html', banner=banner, is_edit=not is_new)
        
        if is_new:
            conn.execute(
                'INSERT INTO banners (title, image_url, link_url, is_active, created_by_user_id) VALUES (?, ?, ?, ?, ?)',
                (title, image_url, link_url, is_active, session['user_id'])
            )
            flash('Баннер добавлен', 'success')
        else:
            conn.execute(
                'UPDATE banners SET title = ?, image_url = ?, link_url = ?, is_active = ? WHERE id = ?',
                (title, image_url, link_url, is_active, banner_id)
            )
            flash('Баннер обновлен', 'success')
        
        conn.commit()
        conn.close()
        return redirect(url_for('manage_banners'))
    
    conn.close()
    return render_template('banner_form.html', banner=banner, is_edit=not is_new)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

