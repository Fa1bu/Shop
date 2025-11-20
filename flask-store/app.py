from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import uuid
import random
from functools import wraps
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['DATABASE'] = 'store.db'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB per request

ALLOWED_PRODUCT_CATEGORIES = ['одежда', 'обувь', 'аксессуары', 'техника', 'игрушки']
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ORDER_STATUS_FLOW = [
    ('pending', 'В обработке'),
    ('processing', 'Подготовка к отправке'),
    ('shipped', 'В пути'),
    ('delivered', 'Доставлен'),
    ('completed', 'Завершен')
]
ORDER_STATUS_LABELS = {key: label for key, label in ORDER_STATUS_FLOW}
ORDER_STATUS_LABELS.update({
    'cancelled': 'Отменен'
})
UPLOAD_ROOT = os.path.join(app.root_path, 'static', 'uploads')
PRODUCT_UPLOAD_FOLDER = os.path.join(UPLOAD_ROOT, 'products')
BANNER_UPLOAD_FOLDER = os.path.join(UPLOAD_ROOT, 'banners')

os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(BANNER_UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def save_uploaded_file(file_storage, target_folder):
    if not file_storage or file_storage.filename == '' or not allowed_file(file_storage.filename):
        return None
    filename = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    full_path = os.path.join(target_folder, unique_name)
    file_storage.save(full_path)
    # Получаем путь относительно папки static
    static_folder = app.static_folder or os.path.join(app.root_path, 'static')
    relative_path = os.path.relpath(full_path, static_folder).replace('\\', '/')
    # Убеждаемся, что путь начинается с правильного префикса
    if not relative_path.startswith('uploads/'):
        # Если путь не начинается с uploads, добавляем его
        uploads_part = os.path.relpath(target_folder, static_folder).replace('\\', '/')
        relative_path = os.path.join(uploads_part, unique_name).replace('\\', '/')
    return relative_path


def delete_file(relative_path):
    if not relative_path:
        return
    if isinstance(relative_path, str) and relative_path.startswith('http'):
        return
    full_path = os.path.join(app.static_folder, relative_path)
    if os.path.exists(full_path):
        try:
            os.remove(full_path)
        except OSError:
            pass


@app.context_processor
def inject_helpers():
    def image_url(path):
        if not path:
            return 'https://via.placeholder.com/400x400?text=Нет+изображения'
        if isinstance(path, str) and path.startswith('http'):
            return path
        # Убеждаемся, что путь правильный
        # Если путь уже начинается с uploads/, используем его как есть
        # Если нет, пытаемся найти файл
        clean_path = path.replace('\\', '/').lstrip('/')
        # Проверяем, существует ли файл
        static_folder = app.static_folder or os.path.join(app.root_path, 'static')
        full_path = os.path.join(static_folder, clean_path)
        if os.path.exists(full_path):
            return url_for('static', filename=clean_path)
        # Если файл не найден, возвращаем путь как есть (Flask попытается найти его)
        return url_for('static', filename=clean_path)

    return {
        'image_url': image_url,
        'category_choices': ALLOWED_PRODUCT_CATEGORIES
    }


def get_order_status_timeline(current_status):
    status = current_status or 'pending'
    if status == 'cancelled':
        return [{
            'key': 'cancelled',
            'label': ORDER_STATUS_LABELS.get('cancelled', 'Отменен'),
            'state': 'cancelled'
        }]
    timeline = []
    current_index = None
    for idx, (key, _) in enumerate(ORDER_STATUS_FLOW):
        if key == status:
            current_index = idx
            break
    if current_index is None:
        current_index = len(ORDER_STATUS_FLOW) - 1
    for idx, (key, label) in enumerate(ORDER_STATUS_FLOW):
        if idx < current_index:
            state = 'completed'
        elif idx == current_index:
            state = 'current'
        else:
            state = 'upcoming'
        timeline.append({
            'key': key,
            'label': label,
            'state': state
        })
    return timeline

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
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'buyer'")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN seller_request_status TEXT NOT NULL DEFAULT 'none'")
    except sqlite3.OperationalError:
        pass
    
    c.execute("UPDATE users SET role = 'buyer' WHERE role IS NULL")
    c.execute("UPDATE users SET seller_request_status = 'none' WHERE seller_request_status IS NULL")
    
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
    
    # Добавляем поле is_approved если его нет (миграция)
    try:
        c.execute('ALTER TABLE products ADD COLUMN is_approved INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Колонка уже существует
    
    c.execute("UPDATE products SET is_approved = 1 WHERE is_approved IS NULL")
    
    c.execute('''CREATE TABLE IF NOT EXISTS product_images
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  product_id INTEGER NOT NULL,
                  image_path TEXT NOT NULL,
                  position INTEGER DEFAULT 0,
                  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE)''')
    
    # Миграции для заказов
    for column_def in [
        ("payment_status TEXT NOT NULL DEFAULT 'pending'", "payment_status"),
        ("payment_reference TEXT", "payment_reference"),
        ("cancelled_at TIMESTAMP", "cancelled_at"),
        ("cancelled_by INTEGER", "cancelled_by")
    ]:
        try:
            c.execute(f"ALTER TABLE orders ADD COLUMN {column_def[0]}")
        except sqlite3.OperationalError:
            pass

    for column_def in [
        ("seller_id INTEGER", "seller_id"),
        ("seller_confirmed INTEGER DEFAULT 0", "seller_confirmed"),
        ("confirmed_at TIMESTAMP", "confirmed_at")
    ]:
        try:
            c.execute(f"ALTER TABLE order_items ADD COLUMN {column_def[0]}")
        except sqlite3.OperationalError:
            pass
    
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
    
    # Таблица заказов
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  total_amount REAL NOT NULL,
                  customer_name TEXT NOT NULL,
                  customer_phone TEXT NOT NULL,
                  delivery_address TEXT NOT NULL,
                  comment TEXT,
                  payment_status TEXT NOT NULL DEFAULT 'pending',
                  payment_reference TEXT,
                  status TEXT DEFAULT 'pending',
                  cancelled_at TIMESTAMP,
                  cancelled_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    # Таблица элементов заказа
    c.execute('''CREATE TABLE IF NOT EXISTS order_items
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  order_id INTEGER NOT NULL,
                  product_id INTEGER NOT NULL,
                  product_name TEXT NOT NULL,
                  price REAL NOT NULL,
                  quantity INTEGER NOT NULL,
                  seller_id INTEGER,
                  seller_confirmed INTEGER DEFAULT 0,
                  confirmed_at TIMESTAMP,
                  FOREIGN KEY (order_id) REFERENCES orders(id),
                  FOREIGN KEY (product_id) REFERENCES products(id))''')
    
    conn.commit()
    conn.close()

# Декоратор для проверки авторизации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Недостаточно прав для выполнения действия', 'error')
            return redirect(url_for('index'))
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


def build_product_order_key(search, category):
    search_key = (search or '').strip().lower()
    category_key = (category or '').strip().lower()
    return f"{search_key}|{category_key}"


def get_cached_product_order(order_key):
    cache = session.get('product_order_cache', {})
    return cache.get(order_key)


def store_product_order(order_key, product_ids):
    cache = session.get('product_order_cache', {})
    cache[order_key] = product_ids
    session['product_order_cache'] = cache


def should_preserve_product_order():
    return session.pop('preserve_product_order', False)


def mark_preserve_order_if_index_referrer():
    referrer = request.referrer
    if not referrer:
        return
    try:
        parsed = urlparse(referrer)
    except ValueError:
        return
    if parsed.path == url_for('index'):
        session['preserve_product_order'] = True

# Главная страница
@app.route('/')
def index():
    conn = get_db()
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip().lower()
    
    # Показываем все товары всем пользователям
    query = 'SELECT * FROM products WHERE 1=1'
    params = []
    
    if search:
        like_search = f'%{search}%'
        query += ' AND (name LIKE ? OR description LIKE ? OR category LIKE ?)'
        params.extend([like_search, like_search, like_search])
    
    if category:
        query += ' AND LOWER(category) = ?'
        params.append(category)
    
    products = conn.execute(query, params).fetchall()
    products = list(products)
    
    order_key = build_product_order_key(search, category)
    preserve_order = should_preserve_product_order()
    cached_order = get_cached_product_order(order_key) if preserve_order else None
    
    if preserve_order and cached_order:
        product_map = {row['id']: row for row in products}
        ordered_products = [product_map[pid] for pid in cached_order if pid in product_map]
        remaining_products = [row for row in products if row['id'] not in cached_order]
        products = ordered_products + remaining_products
    else:
        random.shuffle(products)
        store_product_order(order_key, [row['id'] for row in products])
    
    categories = [{'category': cat} for cat in ALLOWED_PRODUCT_CATEGORIES]
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
        
        existing_admin = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
        role = 'admin' if not existing_admin else 'buyer'
        seller_request_status = 'none'
        
        # Создание пользователя
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password, role, seller_request_status) VALUES (?, ?, ?, ?, ?)',
                    (username, email, hashed_password, role, seller_request_status))
        conn.commit()
        conn.close()
        
        flash('Регистрация успешна! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        
        if not username or not password:
            flash('Введите логин и пароль', 'error')
            return render_template('login.html')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            merge_guest_cart_to_user(user['id'])
            merge_guest_favorites_to_user(user['id'])
            flash(f'Добро пожаловать, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'error')
    
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
    
    gallery_rows = conn.execute(
        'SELECT image_path FROM product_images WHERE product_id = ? ORDER BY position, id',
        (product_id,)
    ).fetchall()
    gallery_images = [row['image_path'] for row in gallery_rows]
    if not gallery_images and product['image']:
        gallery_images.append(product['image'])
    if not gallery_images:
        gallery_images.append(None)
    
    conn.close()
    
    return render_template('product.html', product=product, reviews=reviews, 
                         in_favorites=in_favorites, gallery_images=gallery_images)

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
    mark_preserve_order_if_index_referrer()
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

    flash('Товар добавлен в корзину', 'success')
    flash('Товар добавлен в избранное', 'success')
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
    mark_preserve_order_if_index_referrer()
    product_id = request.form.get('product_id')
    try:
        product_id = int(product_id)
    except (TypeError, ValueError):
        flash('Некорректный товар', 'error')
        return redirect(request.referrer or url_for('index'))
    
    conn = get_db()
    product = conn.execute('SELECT id FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(request.referrer or url_for('index'))
    
    if 'user_id' in session:
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
        conn.close()
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
    mark_preserve_order_if_index_referrer()
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
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    conn = get_db()
    cart_rows = conn.execute('''SELECT c.*, p.name, p.price, p.image, p.id as product_id, p.created_by_user_id as seller_id
                                 FROM cart c
                                 JOIN products p ON c.product_id = p.id
                                 WHERE c.user_id = ?''',
                             (session['user_id'],)).fetchall()
    
    if not cart_rows:
        flash('Корзина пуста', 'error')
        conn.close()
        return redirect(url_for('cart'))
    
    def map_rows(rows):
        items = []
        for row in rows:
            items.append({
                'cart_id': row['id'],
                'product_id': row['product_id'],
                'name': row['name'],
                'price': row['price'],
                'image': row['image'],
                'quantity': row['quantity'],
                'seller_id': row['seller_id']
            })
        return items
    
    cart_items = map_rows(cart_rows)
    
    if request.method == 'POST':
        selected_ids = [cid for cid in request.form.getlist('cart_ids') if cid]
    else:
        selected_ids = request.args.getlist('items')
    
    def filter_items(items, selected):
        if not selected:
            return items
        selected_int = set()
        for value in selected:
            try:
                selected_int.add(int(value))
            except (TypeError, ValueError):
                continue
        filtered = [item for item in items if item['cart_id'] in selected_int]
        return filtered if filtered else items
    
    selected_items = filter_items(cart_items, selected_ids)
    selected_cart_ids = [item['cart_id'] for item in selected_items]
    if not selected_cart_ids:
        flash('Выберите товары для оформления', 'error')
        conn.close()
        return redirect(url_for('cart'))
    
    total = sum(item['price'] * item['quantity'] for item in selected_items)
    
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip()
        customer_phone = request.form.get('customer_phone', '').strip()
        delivery_address = request.form.get('delivery_address', '').strip()
        comment = request.form.get('comment', '').strip()
        payment_reference = request.form.get('payment_reference', '').strip()
        
        if not all([customer_name, customer_phone, delivery_address]):
            flash('Заполните все обязательные поля', 'error')
            conn.close()
            return render_template('checkout.html', cart_items=selected_items, total=total, selected_cart_ids=selected_cart_ids)

        orders_created = []
        for item in selected_items:
            item_total = item['price'] * item['quantity']
            cursor = conn.execute(
                '''INSERT INTO orders (user_id, total_amount, customer_name, customer_phone, delivery_address, comment, payment_status, payment_reference, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (session['user_id'], item_total, customer_name, customer_phone, delivery_address, comment, 'pending', payment_reference or None, 'pending')
            )
            order_id = cursor.lastrowid
            orders_created.append(order_id)
            conn.execute(
                '''INSERT INTO order_items (order_id, product_id, product_name, price, quantity, seller_id)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (order_id, item['product_id'], item['name'], item['price'], item['quantity'], item['seller_id'])
            )
        
        placeholders = ','.join(['?'] * len(selected_cart_ids))
        conn.execute(f'DELETE FROM cart WHERE user_id = ? AND id IN ({placeholders})',
                     (session['user_id'], *selected_cart_ids))
        conn.commit()
        conn.close()
        
        if len(orders_created) == 1:
            flash('Заказ успешно оформлен! Номер заказа: #' + str(orders_created[0]), 'success')
            return redirect(url_for('order_confirmation', order_id=orders_created[0]))
        
        flash(f'Создано {len(orders_created)} отдельных заказов', 'success')
        return redirect(url_for('orders'))
    
    conn.close()
    return render_template('checkout.html', cart_items=selected_items, total=total, selected_cart_ids=selected_cart_ids)

# Список заказов пользователя
@app.route('/orders')
@login_required
def orders():
    conn = get_db()
    user_orders = conn.execute('''
        SELECT o.*, 
               COUNT(oi.id) as items_count,
               SUM(oi.price * oi.quantity) as total
        FROM orders o
        LEFT JOIN order_items oi ON o.id = oi.order_id
        WHERE o.user_id = ?
        GROUP BY o.id
        ORDER BY o.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Получаем детали для каждого заказа
    orders_with_items = []
    for order in user_orders:
        order_dict = dict(order)
        order_items = conn.execute('''
            SELECT oi.*, p.image
            FROM order_items oi
            LEFT JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        ''', (order['id'],)).fetchall()
        order_dict['items'] = [dict(item) for item in order_items]
        order_dict['status_label'] = ORDER_STATUS_LABELS.get(order['status'], order['status'])
        order_dict['status_timeline'] = get_order_status_timeline(order['status'])
        orders_with_items.append(order_dict)
    
    conn.close()
    return render_template('orders.html', orders=orders_with_items)

# Подтверждение заказа
@app.route('/order/<int:order_id>')
@login_required
def order_confirmation(order_id):
    conn = get_db()
    order = conn.execute('''SELECT o.*, u.username
                            FROM orders o
                            JOIN users u ON o.user_id = u.id
                            WHERE o.id = ? AND o.user_id = ?''',
                         (order_id, session['user_id'])).fetchone()
    
    if not order:
        conn.close()
        flash('Заказ не найден', 'error')
        return redirect(url_for('index'))
    
    order_items = conn.execute('''SELECT oi.*, p.image
                                  FROM order_items oi
                                  LEFT JOIN products p ON oi.product_id = p.id
                                  WHERE oi.order_id = ?''',
                               (order_id,)).fetchall()
    conn.close()
    
    status_label = ORDER_STATUS_LABELS.get(order['status'], order['status'])
    status_timeline = get_order_status_timeline(order['status'])
    
    return render_template(
        'order_confirmation.html',
        order=order,
        order_items=order_items,
        status_label=status_label,
        status_timeline=status_timeline
    )


@app.route('/seller/orders/<int:order_id>')
@login_required
def seller_order_details(order_id):
    user_role = session.get('role')
    if user_role not in ('seller', 'admin'):
        flash('Доступ разрешен только продавцам и администраторам', 'error')
        return redirect(url_for('account'))
    
    conn = get_db()
    order = conn.execute('''SELECT o.*, u.username, u.email
                            FROM orders o
                            JOIN users u ON o.user_id = u.id
                            WHERE o.id = ?''',
                         (order_id,)).fetchone()
    if not order:
        conn.close()
        flash('Заказ не найден', 'error')
        return redirect(url_for('account'))
    
    order_items = conn.execute('''
        SELECT oi.*, p.image
        FROM order_items oi
        LEFT JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ? AND oi.seller_id = ?
    ''', (order_id, session['user_id'])).fetchall()
    
    if not order_items:
        conn.close()
        flash('В этом заказе нет ваших товаров', 'error')
        return redirect(url_for('account'))
    
    conn.close()
    status_label = ORDER_STATUS_LABELS.get(order['status'], order['status'])
    status_timeline = get_order_status_timeline(order['status'])
    
    return render_template(
        'seller_order_detail.html',
        order=order,
        order_items=order_items,
        status_label=status_label,
        status_timeline=status_timeline,
        is_admin=(user_role == 'admin')
    )

# Отмена заказа
@app.route('/order/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    conn = get_db()
    order = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?',
                         (order_id, session['user_id'])).fetchone()
    
    if not order:
        conn.close()
        flash('Заказ не найден', 'error')
        return redirect(url_for('orders'))
    
    # Проверяем, что заказ еще не отменен и не выполнен
    if order['status'] == 'cancelled':
        conn.close()
        flash('Заказ уже отменен', 'info')
        return redirect(url_for('orders'))
    
    if order['status'] == 'completed':
        conn.close()
        flash('Нельзя отменить выполненный заказ', 'error')
        return redirect(url_for('orders'))
    
    # Отменяем заказ
    from datetime import datetime
    conn.execute('''
        UPDATE orders 
        SET status = 'cancelled', cancelled_at = ?, cancelled_by = ?
        WHERE id = ?
    ''', (datetime.now(), session['user_id'], order_id))
    conn.commit()
    conn.close()
    
    flash('Заказ отменен', 'success')
    return redirect(url_for('orders'))

# Управление баннерами
@app.route('/banners', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_banners():
    conn = get_db()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        link_url = request.form.get('link_url', '').strip() or None
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        image_file = request.files.get('image_file')
        if not title or not image_file or not image_file.filename:
            flash('Заполните название и загрузите изображение', 'error')
        else:
            saved_path = save_uploaded_file(image_file, BANNER_UPLOAD_FOLDER)
            if not saved_path:
                flash('Недопустимый формат изображения', 'error')
            else:
                conn.execute(
                    'INSERT INTO banners (title, image_url, link_url, is_active, created_by_user_id) VALUES (?, ?, ?, ?, ?)',
                    (title, saved_path, link_url, is_active, session['user_id'])
                )
                conn.commit()
                flash('Баннер добавлен', 'success')
    banners = conn.execute('SELECT * FROM banners ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('banners.html', banners=banners)

@app.route('/banners/<int:banner_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_banner(banner_id):
    conn = get_db()
    banner = conn.execute('SELECT is_active FROM banners WHERE id = ?', (banner_id,)).fetchone()
    if not banner:
        conn.close()
        flash('Баннер не найден', 'error')
        return redirect(url_for('manage_banners'))
    
    new_state = 0 if banner['is_active'] else 1
    conn.execute('UPDATE banners SET is_active = ? WHERE id = ?', (new_state, banner_id))
    conn.commit()
    conn.close()
    flash('Статус баннера обновлен', 'success')
    return redirect(url_for('manage_banners'))

@app.route('/banners/<int:banner_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_banner(banner_id):
    conn = get_db()
    banner = conn.execute('SELECT image_url FROM banners WHERE id = ?', (banner_id,)).fetchone()
    
    if not banner:
        conn.close()
        flash('Баннер не найден', 'error')
        return redirect(url_for('manage_banners'))
    
    conn.execute('DELETE FROM banners WHERE id = ?', (banner_id,))
    conn.commit()
    conn.close()
    delete_file(banner['image_url'])
    flash('Баннер удален', 'info')
    return redirect(url_for('manage_banners'))

@app.route('/account')
@login_required
def account():
    conn = get_db()
    user = conn.execute('SELECT username, email, role, seller_request_status FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if user and session.get('role') != user['role']:
        session['role'] = user['role']
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
    
    # Получаем товары продавца, если он продавец
    seller_products = []
    seller_orders = []
    if user['role'] in ('seller', 'admin'):
        seller_products = conn.execute(
            'SELECT id, name, price FROM products WHERE created_by_user_id = ? ORDER BY id DESC',
            (session['user_id'],)
        ).fetchall()
        
        # Получаем заказы на товары продавца от других пользователей
        # Сначала получаем уникальные заказы
        order_ids = conn.execute('''
            SELECT DISTINCT o.id
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            WHERE oi.seller_id = ? AND o.user_id != ?
            ORDER BY o.created_at DESC
        ''', (session['user_id'], session['user_id'])).fetchall()
        
        seller_orders = []
        for row in order_ids:
            order_id = row['id']
            order = conn.execute('''
                SELECT o.id, o.user_id, o.total_amount, o.customer_name, o.customer_phone, 
                       o.delivery_address, o.status, o.created_at, u.username as buyer_username
                FROM orders o
                JOIN users u ON o.user_id = u.id
                WHERE o.id = ?
            ''', (order_id,)).fetchone()
            
            if order:
                if order['status'] == 'cancelled':
                    continue
                # Получаем товары из этого заказа, принадлежащие продавцу
                order_items = conn.execute('''
                    SELECT oi.id, oi.product_id, oi.product_name, oi.price, oi.quantity, 
                           oi.seller_confirmed, oi.confirmed_at
                    FROM order_items oi
                    WHERE oi.order_id = ? AND oi.seller_id = ?
                ''', (order_id, session['user_id'])).fetchall()
                
                order_dict = dict(order)
                order_dict['items'] = [dict(item) for item in order_items] if order_items else []
                order_dict['all_confirmed'] = all(item['seller_confirmed'] for item in order_items) if order_items else False
                order_dict['status_label'] = ORDER_STATUS_LABELS.get(order['status'], order['status'])
                seller_orders.append(order_dict)
    
    conn.close()

    cart_count = cart_count_row['total'] if cart_count_row else 0
    favorites_count = favorites_count_row['total'] if favorites_count_row else 0

    return render_template(
        'account.html',
        user=user,
        cart_count=cart_count,
        favorites_count=favorites_count,
        reviews=reviews,
        seller_status=user['seller_request_status'],
        user_role=user['role'],
        seller_products=seller_products,
        seller_orders=seller_orders
    )


@app.route('/seller/request', methods=['POST'])
@login_required
def request_seller_status():
    conn = get_db()
    user = conn.execute('SELECT role, seller_request_status FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        conn.close()
        flash('Пользователь не найден', 'error')
        return redirect(url_for('account'))
    
    if user['role'] == 'seller':
        conn.close()
        flash('Вы уже являетесь продавцом', 'info')
        return redirect(url_for('account'))
    
    if user['seller_request_status'] == 'pending':
        conn.close()
        flash('Запрос уже находится на рассмотрении', 'info')
        return redirect(url_for('account'))
    
    conn.execute('UPDATE users SET seller_request_status = ? WHERE id = ?', ('pending', session['user_id']))
    conn.commit()
    conn.close()
    flash('Заявка отправлена администратору', 'success')
    return redirect(url_for('account'))


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    conn = get_db()
    pending_requests = conn.execute(
        '''SELECT id, username, email, seller_request_status 
           FROM users 
           WHERE seller_request_status = 'pending' '''
    ).fetchall()
    sellers = conn.execute(
        '''SELECT id, username, email FROM users WHERE role = 'seller' ORDER BY username'''
    ).fetchall()
    admin_user = conn.execute(
        '''SELECT id, username, email FROM users WHERE role = 'admin' LIMIT 1'''
    ).fetchone()
    conn.close()
    return render_template('admin_users.html', pending_requests=pending_requests, sellers=sellers, admin_user=admin_user)


@app.route('/admin/sellers/<int:user_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_seller(user_id):
    conn = get_db()
    user = conn.execute('SELECT id, role FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('Пользователь не найден', 'error')
        return redirect(url_for('admin_users'))
    
    conn.execute("UPDATE users SET role = 'seller', seller_request_status = 'none' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    if session.get('user_id') == user_id:
        session['role'] = 'seller'
    flash('Пользователь назначен продавцом', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/sellers/<int:user_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_seller(user_id):
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('Пользователь не найден', 'error')
        return redirect(url_for('admin_users'))
    
    conn.execute("UPDATE users SET seller_request_status = 'none' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('Заявка отклонена', 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/sellers/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_seller(user_id):
    conn = get_db()
    user = conn.execute('SELECT id, role FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('Пользователь не найден', 'error')
        return redirect(url_for('admin_users'))
    
    if user['role'] != 'seller':
        conn.close()
        flash('Пользователь не является продавцом', 'error')
        return redirect(url_for('admin_users'))
    
    # Удаляем роль продавца, возвращаем к покупателю
    conn.execute("UPDATE users SET role = 'buyer', seller_request_status = 'none' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    if session.get('user_id') == user_id:
        session['role'] = 'buyer'
    
    flash('Продавец удален, роль изменена на покупатель', 'success')
    return redirect(url_for('admin_users'))


@app.route('/product/<int:product_id>/approve', methods=['POST'])
@login_required
def approve_product(product_id):
    conn = get_db()
    product = conn.execute('SELECT id, created_by_user_id FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(url_for('account'))
    
    user_role = session.get('role')
    # Проверяем, что пользователь является создателем товара (и продавцом/админом) или админом
    is_creator = product['created_by_user_id'] == session['user_id']
    is_admin = user_role == 'admin'
    is_seller = user_role in ('seller', 'admin')
    
    if not is_admin and (not is_creator or not is_seller):
        conn.close()
        flash('Вы можете одобрять только свои товары', 'error')
        return redirect(url_for('account'))
    
    conn.execute('UPDATE products SET is_approved = 1 WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    
    flash('Товар одобрен', 'success')
    return redirect(url_for('account'))


@app.route('/product/<int:product_id>/unapprove', methods=['POST'])
@login_required
def unapprove_product(product_id):
    conn = get_db()
    product = conn.execute('SELECT id, created_by_user_id FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(url_for('account'))
    
    user_role = session.get('role')
    # Проверяем, что пользователь является создателем товара (и продавцом/админом) или админом
    is_creator = product['created_by_user_id'] == session['user_id']
    is_admin = user_role == 'admin'
    is_seller = user_role in ('seller', 'admin')
    
    if not is_admin and (not is_creator or not is_seller):
        conn.close()
        flash('Вы можете отменять одобрение только своих товаров', 'error')
        return redirect(url_for('account'))
    
    conn.execute('UPDATE products SET is_approved = 0 WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    
    flash('Одобрение товара отменено', 'info')
    return redirect(url_for('account'))

@app.route('/products/new', methods=['GET', 'POST'])
@login_required
def add_product():
    if session.get('role') not in ('seller', 'admin'):
        flash('Добавлять товары могут только продавцы', 'error')
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip().replace(',', '.')
        category = request.form.get('category', '').strip().lower()
        stock_raw = request.form.get('stock', '').strip() or '0'
        specifications = request.form.get('specifications', '').strip()

        if not all([name, description, price_raw, category]):
            flash('Заполните все обязательные поля', 'error')
            return render_template('product_form.html', product=None, is_edit=False, existing_images=[])

        if category not in ALLOWED_PRODUCT_CATEGORIES:
            flash('Выберите категорию из списка', 'error')
            return render_template('product_form.html', product=None, is_edit=False, existing_images=[])

        try:
            price = float(price_raw)
            if price < 0:
                raise ValueError
        except ValueError:
            flash('Некорректная цена', 'error')
            return render_template('product_form.html', product=None, is_edit=False, existing_images=[])

        try:
            stock = int(stock_raw)
            if stock < 0:
                raise ValueError
        except ValueError:
            flash('Некорректное количество на складе', 'error')
            return render_template('product_form.html', product=None, is_edit=False, existing_images=[])

        image_files = [f for f in request.files.getlist('images') if f and f.filename]
        saved_images = []
        for image_file in image_files:
            saved_path = save_uploaded_file(image_file, PRODUCT_UPLOAD_FOLDER)
            if saved_path:
                saved_images.append(saved_path)

        if not saved_images:
            flash('Добавьте хотя бы одно изображение в поддерживаемом формате (png, jpg, jpeg, gif, webp)', 'error')
            return render_template('product_form.html', product=None, is_edit=False, existing_images=[])

        primary_image = saved_images[0]

        conn = get_db()
        cursor = conn.execute(
            '''INSERT INTO products (name, description, price, image, category, stock, created_by_user_id, specifications, is_approved)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (name, description, price, primary_image, category, stock, session['user_id'], specifications, 0)
        )
        product_id = cursor.lastrowid
        for position, path in enumerate(saved_images):
            conn.execute(
                'INSERT INTO product_images (product_id, image_path, position) VALUES (?, ?, ?)',
                (product_id, path, position)
            )
        conn.commit()
        conn.close()

        flash('Товар успешно добавлен', 'success')
        return redirect(url_for('product', product_id=product_id))
    
    return render_template('product_form.html', product=None, is_edit=False, existing_images=[])

# Редактирование товара
@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    conn = get_db()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    product_images = conn.execute(
        'SELECT * FROM product_images WHERE product_id = ? ORDER BY position, id',
        (product_id,)
    ).fetchall()
    
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(url_for('index'))
    
    # Проверяем, что пользователь является создателем товара или администратором
    user_role = session.get('role')
    is_admin = user_role == 'admin'
    # Администратор может редактировать все товары
    if is_admin:
        pass  # Разрешаем редактирование
    else:
        # Обычные пользователи могут редактировать только свои товары
        is_creator = product['created_by_user_id'] is not None and product['created_by_user_id'] == session['user_id']
        if not is_creator:
            conn.close()
            flash('Вы можете редактировать только свои товары', 'error')
            return redirect(url_for('product', product_id=product_id))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip().replace(',', '.')
        category = request.form.get('category', '').strip().lower()
        stock_raw = request.form.get('stock', '').strip() or '0'
        specifications = request.form.get('specifications', '').strip()

        if not all([name, description, price_raw, category]):
            flash('Заполните все обязательные поля', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True, existing_images=product_images)

        if category not in ALLOWED_PRODUCT_CATEGORIES:
            flash('Выберите категорию из списка', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True, existing_images=product_images)

        try:
            price = float(price_raw)
            if price < 0:
                raise ValueError
        except ValueError:
            flash('Некорректная цена', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True, existing_images=product_images)

        try:
            stock = int(stock_raw)
            if stock < 0:
                raise ValueError
        except ValueError:
            flash('Некорректное количество на складе', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True, existing_images=product_images)

        new_image_files = [f for f in request.files.getlist('images') if f and f.filename]
        new_image_paths = []
        for file_storage in new_image_files:
            saved_path = save_uploaded_file(file_storage, PRODUCT_UPLOAD_FOLDER)
            if saved_path:
                new_image_paths.append(saved_path)

        if new_image_paths:
            max_pos_row = conn.execute(
                'SELECT COALESCE(MAX(position), -1) as max_pos FROM product_images WHERE product_id = ?',
                (product_id,)
            ).fetchone()
            start_pos = (max_pos_row['max_pos'] or -1) + 1
            for offset, path in enumerate(new_image_paths):
                conn.execute(
                    'INSERT INTO product_images (product_id, image_path, position) VALUES (?, ?, ?)',
                    (product_id, path, start_pos + offset)
                )

        primary_image_row = conn.execute(
            'SELECT image_path FROM product_images WHERE product_id = ? ORDER BY position, id LIMIT 1',
            (product_id,)
        ).fetchone()

        primary_image = primary_image_row['image_path'] if primary_image_row else product['image']

        if not primary_image:
            flash('Добавьте хотя бы одно изображение товара', 'error')
            conn.close()
            return render_template('product_form.html', product=product, is_edit=True, existing_images=product_images)

        conn.execute(
            '''UPDATE products SET name = ?, description = ?, price = ?, image = ?, category = ?, stock = ?, specifications = ?
               WHERE id = ?''',
            (name, description, price, primary_image, category, stock, specifications, product_id)
        )
        conn.commit()
        conn.close()

        flash('Товар успешно обновлен', 'success')
        return redirect(url_for('product', product_id=product_id))
    
    conn.close()
    return render_template('product_form.html', product=product, is_edit=True, existing_images=product_images)


@app.route('/product/<int:product_id>/images/<int:image_id>/delete', methods=['POST'])
@login_required
def delete_product_image(product_id, image_id):
    conn = get_db()
    product = conn.execute('SELECT id, created_by_user_id, image FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        conn.close()
        flash('Товар не найден', 'error')
        return redirect(url_for('index'))
    
    if product['created_by_user_id'] != session['user_id'] and session.get('role') != 'admin':
        conn.close()
        flash('У вас нет прав на удаление изображений этого товара', 'error')
        return redirect(url_for('product', product_id=product_id))
    
    image_row = conn.execute('SELECT * FROM product_images WHERE id = ? AND product_id = ?', (image_id, product_id)).fetchone()
    if not image_row:
        conn.close()
        flash('Изображение не найдено', 'error')
        return redirect(url_for('edit_product', product_id=product_id))
    
    total_images = conn.execute('SELECT COUNT(*) as total FROM product_images WHERE product_id = ?', (product_id,)).fetchone()
    if total_images and total_images['total'] <= 1:
        conn.close()
        flash('Нельзя удалить единственное изображение товара', 'error')
        return redirect(url_for('edit_product', product_id=product_id))
    
    conn.execute('DELETE FROM product_images WHERE id = ?', (image_id,))
    new_primary_row = conn.execute(
        'SELECT image_path FROM product_images WHERE product_id = ? ORDER BY position, id LIMIT 1',
        (product_id,)
    ).fetchone()
    conn.execute(
        'UPDATE products SET image = ? WHERE id = ?',
        (new_primary_row['image_path'] if new_primary_row else product['image'], product_id)
    )
    conn.commit()
    conn.close()
    delete_file(image_row['image_path'])
    flash('Изображение удалено', 'info')
    return redirect(url_for('edit_product', product_id=product_id))

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
    
    # Проверяем, что пользователь является создателем товара или админом
    if product['created_by_user_id'] is not None and product['created_by_user_id'] != session['user_id'] and session.get('role') != 'admin':
        conn.close()
        flash('Вы можете удалять только свои товары', 'error')
        return redirect(url_for('product', product_id=product_id))
    
    image_rows = conn.execute('SELECT image_path FROM product_images WHERE product_id = ?', (product_id,)).fetchall()
    
    # Удаляем связанные данные
    conn.execute('DELETE FROM cart WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM favorites WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM reviews WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM product_images WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    
    for row in image_rows:
        delete_file(row['image_path'])
    delete_file(product['image'])
    
    flash('Товар успешно удален', 'info')
    return redirect(url_for('index'))

# Редактирование баннера
@app.route('/banners/<int:banner_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
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
        link_url = request.form.get('link_url', '').strip() or None
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        image_file = request.files.get('image_file')
        new_image_path = None
        
        if image_file and image_file.filename:
            new_image_path = save_uploaded_file(image_file, BANNER_UPLOAD_FOLDER)
            if not new_image_path:
                flash('Недопустимый формат изображения', 'error')
                conn.close()
                return render_template('banner_form.html', banner=banner, is_edit=not is_new)
        elif is_new:
            flash('Загрузите изображение баннера', 'error')
            conn.close()
            return render_template('banner_form.html', banner=banner, is_edit=not is_new)
        
        if not title:
            flash('Введите название баннера', 'error')
            conn.close()
            return render_template('banner_form.html', banner=banner, is_edit=not is_new)
        
        if is_new:
            conn.execute(
                'INSERT INTO banners (title, image_url, link_url, is_active, created_by_user_id) VALUES (?, ?, ?, ?, ?)',
                (title, new_image_path, link_url, is_active, session['user_id'])
            )
            flash('Баннер добавлен', 'success')
        else:
            image_to_save = new_image_path or banner['image_url']
            if new_image_path and banner['image_url']:
                delete_file(banner['image_url'])
            conn.execute(
                'UPDATE banners SET title = ?, image_url = ?, link_url = ?, is_active = ? WHERE id = ?',
                (title, image_to_save, link_url, is_active, banner_id)
            )
            flash('Баннер обновлен', 'success')
        
        conn.commit()
        conn.close()
        return redirect(url_for('manage_banners'))
    
    conn.close()
    return render_template('banner_form.html', banner=banner, is_edit=not is_new)

# Подтверждение заказа продавцом
@app.route('/order/<int:order_id>/item/<int:order_item_id>/confirm', methods=['POST'])
@login_required
def confirm_order_item(order_id, order_item_id):
    conn = get_db()
    
    # Проверяем, что элемент заказа существует и принадлежит товару продавца
    order_item = conn.execute('''
        SELECT oi.*, o.user_id as buyer_id, oi.seller_id
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        WHERE oi.id = ? AND oi.order_id = ?
    ''', (order_item_id, order_id)).fetchone()
    
    if not order_item:
        conn.close()
        flash('Элемент заказа не найден', 'error')
        return redirect(url_for('account'))
    
    # Проверяем, что товар принадлежит текущему продавцу (только если кто-то заказал его товар)
    if order_item['seller_id'] != session['user_id']:
        conn.close()
        flash('Этот товар не принадлежит вам', 'error')
        return redirect(url_for('account'))
    
    # Проверяем, что заказ сделан другим пользователем (не самим продавцом)
    if order_item['buyer_id'] == session['user_id']:
        conn.close()
        flash('Вы не можете подтверждать заказы на свои товары, сделанные вами самим', 'error')
        return redirect(url_for('account'))
    
    # Проверяем, что элемент заказа еще не подтвержден
    if order_item['seller_confirmed']:
        conn.close()
        flash('Этот элемент заказа уже подтвержден', 'info')
        return redirect(url_for('account'))
    
    # Подтверждаем элемент заказа
    conn.execute('''
        UPDATE order_items 
        SET seller_confirmed = 1, confirmed_at = ?
        WHERE id = ?
    ''', (datetime.now(), order_item_id))
    conn.commit()
    conn.close()
    
    flash('Элемент заказа подтвержден', 'success')
    return redirect(url_for('account'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

