from flask import Flask, render_template, request, redirect
import sqlite3


app = Flask(__name__)
DATABASE = 'shop.db'


# База данных
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS positions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            price REAL NOT NULL,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()


# Список позиций
def list_positions():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM positions')
    positions = c.fetchall()
    conn.close()
    return positions

# Добавить позицию
def add_position(name, price, description):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO positions (name, price, description) VALUES (?, ?, ?)', (name, price, description))
    conn.commit()
    conn.close()

# Главная страница
@app.route('/')
def index():
    positions = list_positions()
    return render_template('index.html', positions=positions)

# Страница добавления позиций
@app.route('/add', methods=['POST'])
def add():
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']
        add_position(name, price, description)
        return redirect('/')
    else:
        return render_template('add.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
