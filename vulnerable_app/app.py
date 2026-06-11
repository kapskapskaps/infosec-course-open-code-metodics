import sqlite3
import os
import subprocess
import hashlib
from flask import (
    Flask, render_template, render_template_string,
    request, redirect, session, send_file, make_response,
    flash, abort
)

app = Flask(__name__)

# Секретный ключ для подписи сессий
app.secret_key = 'UltraSecretKey123!DoNotChange'
app.debug = True

# Настройки
DATABASE = 'school.db'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'exe', 'bat', 'scr', 'zip'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

# ─── Инициализация БД ───────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        bio TEXT,
        role TEXT DEFAULT 'user'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        is_public INTEGER DEFAULT 1
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        note_id INTEGER,
        author TEXT,
        text TEXT
    )''')
    # Администратор по умолчанию
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
              ('admin', 'admin123', 'admin'))
    # Тестовый пользователь
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
              ('student', 'student123', 'user'))
    # Демо-заметка
    c.execute("INSERT OR IGNORE INTO notes (id, user_id, title, content, is_public) VALUES (?, ?, ?, ?, ?)",
              (1, 1, 'Секретная заметка админа',
               'Флаг: HTB{c0ngr4ts_y0u_f0und_th3_fl4g}!', 1))
    conn.commit()
    conn.close()

init_db()

# ─── Вспомогательные функции ──────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def is_logged_in():
    return 'user_id' in session

# ─── МАРШРУТЫ ──────────────────────────────────────────────

# 1. Главная
@app.route('/')
def index():
    conn = get_db()
    cursor = conn.execute("SELECT * FROM notes WHERE is_public=1 ORDER BY id DESC")
    notes = cursor.fetchall()
    conn.close()
    return render_template('index.html', notes=notes)

# 2. Регистрация (УЯЗВИМОСТЬ: SQL-инъекция)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        bio = request.form.get('bio', '')
        conn = get_db()
        # УЯЗВИМОСТЬ 1: SQL-инъекция в регистрации
        cursor = conn.execute(
            f"INSERT INTO users (username, password, bio) VALUES ('{username}', '{password}', '{bio}')"
        )
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

# 3. Вход (УЯЗВИМОСТИ: SQL-инъекция, plaintext, user enumeration)
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db()
        # УЯЗВИМОСТЬ 2: SQL-инъекция в логине
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor = conn.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            # УЯЗВИМОСТЬ 3: User enumeration через redirect
            next_url = request.args.get('next')
            if next_url:
                return redirect(next_url)  # УЯЗВИМОСТЬ: Open Redirect
            return redirect('/dashboard')
        else:
            # УЯЗВИМОСТЬ 4: User enumeration — разное сообщение
            msg = 'Неверное имя пользователя или пароль'
    return render_template('login.html', msg=msg)

# 4. Aватар пользователя
@app.route('/avatar/<user_id>')
def user_avatar(user_id):
    conn = get_db()
    cursor = conn.execute(f"SELECT bio FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    conn.close()
    if not user:
        abort(404)
    bio = user['bio'] or ''
    # Ищем маркер [avatar:filename]
    import re
    m = re.search(r'\[avatar:([^\]]+)\]', bio)
    if m:
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], m.group(1))
        if os.path.exists(avatar_path):
            return send_file(avatar_path)
    abort(404)

# 5. Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# 5. Dashboard
@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect('/login')
    conn = get_db()
    cursor = conn.execute(
        f"SELECT * FROM notes WHERE user_id={session['user_id']} ORDER BY id DESC"
    )
    notes = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', notes=notes)

# 6. Создание заметки (УЯЗВИМОСТИ: CSRF, Stored XSS)
@app.route('/create', methods=['GET', 'POST'])
def create_note():
    if not is_logged_in():
        return redirect('/login')
    # УЯЗВИМОСТЬ 5: Нет CSRF-защиты
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        is_public = request.form.get('is_public', '1')
        conn = get_db()
        conn.execute(
            "INSERT INTO notes (user_id, title, content, is_public) VALUES (?, ?, ?, ?)",
            (session['user_id'], title, content, is_public)
        )
        conn.commit()
        conn.close()
        return redirect('/dashboard')
    return render_template('create_note.html')

# 7. Просмотр заметки (УЯЗВИМОСТИ: SQL-инъекция, Stored XSS)
@app.route('/note/<note_id>')
def view_note(note_id):
    conn = get_db()
    # УЯЗВИМОСТЬ 6: SQL-инъекция в ID заметки
    cursor = conn.execute(f"SELECT * FROM notes WHERE id={note_id}")
    note = cursor.fetchone()
    if not note:
        return "Заметка не найдена", 404
    # Получаем комментарии
    cursor = conn.execute(f"SELECT * FROM comments WHERE note_id={note_id}")
    comments = cursor.fetchall()
    conn.close()
    # УЯЗВИМОСТЬ 7: Stored XSS (контент не экранирован)
    return render_template('note.html', note=note, comments=comments)

# 8. Удаление заметки (УЯЗВИМОСТИ: CSRF, IDOR)
@app.route('/note/<note_id>/delete', methods=['POST'])
def delete_note(note_id):
    if not is_logged_in():
        return redirect('/login')
    # УЯЗВИМОСТЬ 8: IDOR — нет проверки owner
    # УЯЗВИМОСТЬ 9: CSRF — нет токена
    # УЯЗВИМОСТЬ 10: SQL-инъекция в delete
    conn = get_db()
    conn.execute(f"DELETE FROM notes WHERE id={note_id}")
    conn.commit()
    conn.close()
    return redirect('/dashboard')

# 9. Профиль пользователя (УЯЗВИМОСТИ: SQL-инъекция, XSS)
@app.route('/profile/<user_id>')
def profile(user_id):
    conn = get_db()
    # УЯЗВИМОСТЬ 11: SQL-инъекция в профиле
    cursor = conn.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    if not user:
        return "Пользователь не найден", 404
    cursor = conn.execute(f"SELECT * FROM notes WHERE user_id={user_id} AND is_public=1")
    notes = cursor.fetchall()
    conn.close()
    # УЯЗВИМОСТЬ 12: Stored XSS в bio (без экранирования)
    import re
    bio = user['bio'] or ''
    avatar_exists = bool(re.search(r'\[avatar:([^\]]+)\]', bio))
    return render_template('profile.html', user=user, notes=notes, avatar_exists=avatar_exists)

# 10. Поиск (УЯЗВИМОСТИ: SQL-инъекция, Reflected XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return render_template('search.html', results=[], query=query)
    conn = get_db()
    # УЯЗВИМОСТЬ 13: SQL-инъекция в поиске
    sql = f"SELECT * FROM notes WHERE is_public=1 AND (title LIKE '%{query}%' OR content LIKE '%{query}%')"
    cursor = conn.execute(sql)
    results = cursor.fetchall()
    conn.close()
    # УЯЗВИМОСТЬ 14: Reflected XSS (query вставляется без экранирования)
    return render_template('search.html', results=results, query=query)

# 11. Загрузка аватара (УЯЗВИМОСТИ: file upload, path traversal)
@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if not is_logged_in():
        return redirect('/login')
    file = request.files.get('avatar')
    if file:
        filename = file.filename
        # УЯЗВИМОСТЬ 15: Нет проверки расширения (пускаем .exe .bat)
        # УЯЗВИМОСТЬ 16: Path traversal в имени файла
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        # Сохраняем путь в БД
        conn = get_db()
        conn.execute(
            f"UPDATE users SET bio=bio || ' [avatar:{filename}]' WHERE id={session['user_id']}"
        )
        conn.commit()
        conn.close()
        return redirect('/profile/' + str(session['user_id']))
    return redirect('/dashboard')

# 12. Скачивание файла (УЯЗВИМОСТЬ: Path traversal)
@app.route('/download/<path:filename>')
def download_file(filename):
    # УЯЗВИМОСТЬ 17: Path traversal — можно скачать любой файл
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# 13. Эхо-страница (SSTI)
@app.route('/echo')
def echo():
    name = request.args.get('name', 'Guest')
    # УЯЗВИМОСТЬ 18: Server-Side Template Injection (SSTI)
    template = f"<h2>Привет, {name}!</h2><p>Страница эхо-запроса</p>"
    return render_template_string(template)

# 14. Админ-панель (УЯЗВИМОСТИ: broken access control)
@app.route('/admin')
def admin_panel():
    # УЯЗВИМОСТЬ 19: Broken Access Control — нет проверки роли
    if not is_logged_in():
        return redirect('/login')
    conn = get_db()
    cursor = conn.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor = conn.execute("SELECT * FROM notes")
    notes = cursor.fetchall()
    conn.close()
    return render_template('admin.html', users=users, notes=notes)

# 15. Админ-панель: выполнение команды ping (Command Injection)
@app.route('/admin/ping', methods=['POST'])
def admin_ping():
    if not is_logged_in():
        return redirect('/login')
    ip = request.form.get('ip', '127.0.0.1')
    # УЯЗВИМОСТЬ 20: Command Injection
    result = subprocess.check_output(f"ping -n 1 {ip}", shell=True)
    return render_template('admin.html', ping_result=result.decode('cp866', errors='replace'))

# 16. Экспорт данных (УЯЗВИМОСТЬ: IDOR + SQL-инъекция)
@app.route('/export')
def export_data():
    if not is_logged_in():
        return redirect('/login')
    user_id = request.args.get('user_id', session['user_id'])
    conn = get_db()
    # УЯЗВИМОСТЬ 21: IDOR — можно экспортировать чужие данные
    # УЯЗВИМОСТЬ 22: SQL-инъекция
    cursor = conn.execute(f"SELECT * FROM notes WHERE user_id={user_id}")
    data = cursor.fetchall()
    conn.close()
    return render_template('export.html', data=data)

# 17. Смена пароля (УЯЗВИМОСТЬ: CSRF, отсутствие проверки)
@app.route('/change_password', methods=['POST'])
def change_password():
    if not is_logged_in():
        return redirect('/login')
    new_password = request.form.get('new_password')
    # УЯЗВИМОСТЬ 23: CSRF — нет токена
    # УЯЗВИМОСТЬ 24: SQL-инъекция
    conn = get_db()
    conn.execute(f"UPDATE users SET password='{new_password}' WHERE id={session['user_id']}")
    conn.commit()
    conn.close()
    return redirect('/dashboard')

# 18. Комментарии (УЯЗВИМОСТИ: XSS, SQL-инъекция)
@app.route('/note/<note_id>/comment', methods=['POST'])
def add_comment(note_id):
    author = request.form.get('author', 'Аноним')
    text = request.form.get('text', '')
    # УЯЗВИМОСТЬ 25: SQL-инъекция в комментарии
    conn = get_db()
    conn.execute(
        f"INSERT INTO comments (note_id, author, text) VALUES ({note_id}, '{author}', '{text}')"
    )
    conn.commit()
    conn.close()
    return redirect(f'/note/{note_id}')

# 19. Ошибка 404 с user input
@app.errorhandler(404)
def not_found(e):
    # УЯЗВИМОСТЬ 26: Reflected XSS через путь
    path = request.path
    return f"<h1>404 — Страница не найдена</h1><p>Путь: {path}</p>"

# 20. API: статус пользователя (SQL-инъекция)
@app.route('/api/user_status')
def user_status():
    user_id = request.args.get('id')
    if not user_id:
        return {"error": "no id"}
    conn = get_db()
    # УЯЗВИМОСТЬ 27: SQL-инъекция
    cursor = conn.execute(f"SELECT username, role FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"username": user["username"], "role": user["role"]}
    return {"error": "user not found"}

# 21. Установка cookie вручную
@app.route('/set_theme')
def set_theme():
    theme = request.args.get('theme', 'light')
    resp = make_response(redirect('/'))
    # УЯЗВИМОСТЬ 28: Cookie без HttpOnly и Secure
    resp.set_cookie('theme', theme)
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
