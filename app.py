import os, sqlite3, secrets, time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, 'crm.sqlite3')
SECRET_PATH = os.path.join(APP_DIR, 'secret.key')

def load_secret():
    env_secret = os.environ.get('CRM_SECRET_KEY')
    if env_secret:
        return env_secret
    try:
        with open(SECRET_PATH, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except FileNotFoundError:
        value = secrets.token_urlsafe(48)
        with open(SECRET_PATH, 'w', encoding='utf-8') as f:
            f.write(value)
        try:
            os.chmod(SECRET_PATH, 0o600)
        except OSError:
            pass
        return value

app = Flask(__name__)
app.secret_key = load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', MAX_CONTENT_LENGTH=2 * 1024 * 1024)

STATUSES = ['Новый', 'Связались', 'Документы', 'Оформление', 'Вышел на работу', 'Отказ']

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop('db', None)
    if conn:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'recruiter',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS candidates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      phone TEXT DEFAULT '', nationality TEXT DEFAULT '', city TEXT DEFAULT '',
      vacancy TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Новый',
      recruiter TEXT DEFAULT '', notes TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      owner_id INTEGER REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS vacancies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL, city TEXT DEFAULT '', rate TEXT DEFAULT '',
      schedule TEXT DEFAULT '', warehouse_address TEXT DEFAULT '', housing TEXT DEFAULT '', transport TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Активна',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, username TEXT NOT NULL, action TEXT NOT NULL,
      candidate_id INTEGER, details TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    # Safe, additive migration for the first prototype database.
    cols = {r[1] for r in conn.execute('PRAGMA table_info(candidates)').fetchall()}
    if 'owner_id' not in cols:
        conn.execute('ALTER TABLE candidates ADD COLUMN owner_id INTEGER REFERENCES users(id)')
    user_cols = {r[1] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
    if 'active' not in user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1')
    if 'created_at' not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        conn.execute("UPDATE users SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL")
    vacancy_cols = {r[1] for r in conn.execute('PRAGMA table_info(vacancies)').fetchall()}
    for field in ('warehouse_address', 'transport'):
        if field not in vacancy_cols:
            conn.execute(f"ALTER TABLE vacancies ADD COLUMN {field} TEXT DEFAULT ''")
    conn.execute("CREATE TABLE IF NOT EXISTS app_pages (slug TEXT PRIMARY KEY, content TEXT NOT NULL DEFAULT '')")
    conn.commit(); conn.close()

@app.context_processor
def inject_globals():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return {'csrf_token': session['_csrf']}

@app.before_request
def protect_posts():
    if request.method == 'POST':
        supplied = request.form.get('_csrf', '')
        expected = session.get('_csrf', '')
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            abort(400, description='Проверка безопасности формы не пройдена. Обновите страницу и повторите.')

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'no-store'
    return response

def current_user():
    if not session.get('user_id'):
        return None
    return db().execute('SELECT id, username, role, active FROM users WHERE id=?', (session['user_id'],)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user['active']:
            session.clear()
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def audit(action, candidate_id=None, details=''):
    db().execute('INSERT INTO audit_log(user_id,username,action,candidate_id,details) VALUES(?,?,?,?,?)',
                 (session.get('user_id'), session.get('username',''), action, candidate_id, details[:500]))

def can_edit_candidate(candidate):
    return session.get('role') == 'admin' or candidate['owner_id'] == session.get('user_id')

@app.route('/setup', methods=['GET','POST'])
def setup():
    conn = db()
    if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if len(username) < 3 or len(password) < 12:
            flash('Логин — минимум 3 символа, пароль — минимум 12.')
        else:
            conn.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                         (username, generate_password_hash(password), 'admin'))
            conn.commit(); audit('Создан администратор')
            flash('Администратор создан. Войдите в систему.')
            return redirect(url_for('login'))
    return render_template('setup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = db().execute('SELECT * FROM users WHERE username=? AND active=1',
                            (request.form.get('username','').strip(),)).fetchone()
        if user and check_password_hash(user['password_hash'], request.form.get('password','')):
            session.clear()
            session['user_id'] = user['id']; session['username'] = user['username']; session['role'] = user['role']
            session['_csrf'] = secrets.token_urlsafe(32)
            return redirect(url_for('dashboard'))
        # Diagnostic output contains no password or password hash.
        print('[CRM LOGIN CHECK] database:', DB_PATH, flush=True)
        print('[CRM LOGIN CHECK] account_found:', bool(user), 'active:', (user['active'] if user else None), flush=True)
        print('[CRM LOGIN CHECK] username_length:', len(request.form.get('username','').strip()), flush=True)
        print('[CRM LOGIN CHECK] password_length:', len(request.form.get('password','')), flush=True)
        print('[CRM LOGIN CHECK] password_matches:', bool(user and check_password_hash(user['password_hash'], request.form.get('password',''))), flush=True)
        time.sleep(0.6)
        flash('Неверный логин или пароль.')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = db()
    total = conn.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]
    new = conn.execute("SELECT COUNT(*) FROM candidates WHERE status='Новый'").fetchone()[0]
    active = conn.execute("SELECT COUNT(*) FROM vacancies WHERE status='Активна'").fetchone()[0]
    recent = conn.execute('SELECT * FROM candidates ORDER BY id DESC LIMIT 6').fetchall()
    map_vacancies = [dict(row) for row in conn.execute('SELECT id, title, city, warehouse_address, status, rate FROM vacancies ORDER BY id DESC').fetchall()]
    return render_template('dashboard.html', total=total, active=active, new=new, recent=recent, map_vacancies=map_vacancies)

@app.route('/candidates')
@login_required
def candidates():
    q = request.args.get('q','').strip(); status = request.args.get('status','')
    sql = '''SELECT c.*, u.username AS owner_name FROM candidates c
             LEFT JOIN users u ON u.id=c.owner_id WHERE 1=1'''
    args = []
    if q:
        sql += ' AND (c.full_name LIKE ? OR c.phone LIKE ? OR c.city LIKE ? OR c.vacancy LIKE ?)'
        args += [f'%{q}%'] * 4
    if status in STATUSES:
        sql += ' AND c.status=?'; args.append(status)
    rows = db().execute(sql + ' ORDER BY c.id DESC', args).fetchall()
    return render_template('candidates.html', candidates=rows, q=q, status=status)

def candidate_values():
    data = {k: request.form.get(k,'').strip() for k in ['full_name','phone','nationality','city','vacancy','status','notes']}
    if not data['full_name']:
        return None
    if data['status'] not in STATUSES:
        data['status'] = 'Новый'
    return data

@app.route('/candidates/add', methods=['GET','POST'])
@login_required
def add_candidate():
    if request.method == 'POST':
        data = candidate_values()
        if not data:
            flash('Укажите имя кандидата.')
        else:
            cur = db().execute('''INSERT INTO candidates(full_name,phone,nationality,city,vacancy,status,recruiter,notes,owner_id)
                VALUES(?,?,?,?,?,?,?,?,?)''', (data['full_name'],data['phone'],data['nationality'],data['city'],data['vacancy'],data['status'],session['username'],data['notes'],session['user_id']))
            audit('Добавлен кандидат', cur.lastrowid, data['full_name']); db().commit()
            flash('Кандидат добавлен. Ответственный: ' + session['username'])
            return redirect(url_for('candidates'))
    return render_template('candidate_form.html', candidate=None, statuses=STATUSES, page_title='Новый кандидат')

@app.route('/candidates/<int:candidate_id>/edit', methods=['GET','POST'])
@login_required
def edit_candidate(candidate_id):
    conn = db()
    candidate = conn.execute('SELECT * FROM candidates WHERE id=?', (candidate_id,)).fetchone()
    if not candidate: abort(404)
    if not can_edit_candidate(candidate): abort(403)
    if request.method == 'POST':
        data = candidate_values()
        if not data:
            flash('Укажите имя кандидата.')
        else:
            conn.execute('''UPDATE candidates SET full_name=?,phone=?,nationality=?,city=?,vacancy=?,status=?,notes=? WHERE id=?''',
                         (data['full_name'],data['phone'],data['nationality'],data['city'],data['vacancy'],data['status'],data['notes'],candidate_id))
            audit('Изменён кандидат', candidate_id, data['full_name']); conn.commit()
            flash('Изменения сохранены.'); return redirect(url_for('candidates'))
    return render_template('candidate_form.html', candidate=candidate, statuses=STATUSES, page_title='Редактирование кандидата')

@app.route('/candidates/<int:candidate_id>/delete', methods=['POST'])
@admin_required
def delete_candidate(candidate_id):
    conn = db(); row = conn.execute('SELECT full_name FROM candidates WHERE id=?', (candidate_id,)).fetchone()
    if row:
        audit('Удалён кандидат', candidate_id, row['full_name'])
        conn.execute('DELETE FROM candidates WHERE id=?', (candidate_id,)); conn.commit()
        flash('Запись удалена.')
    return redirect(url_for('candidates'))

@app.route('/vacancies')
@login_required
def vacancies():
    rows = db().execute('SELECT * FROM vacancies ORDER BY id DESC').fetchall()
    return render_template('vacancies.html', vacancies=rows)

@app.route('/vacancies/add', methods=['GET','POST'])
@login_required
def add_vacancy():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        if title:
            db().execute('INSERT INTO vacancies(title,city,rate,schedule,warehouse_address,housing,transport,status) VALUES(?,?,?,?,?,?,?,?)',
                         (title,request.form.get('city','').strip(),request.form.get('rate','').strip(),request.form.get('schedule','').strip(),request.form.get('warehouse_address','').strip(),request.form.get('housing','').strip(),request.form.get('transport','').strip(),request.form.get('status','Активна')))
            audit('Добавлена вакансия', None, title); db().commit(); flash('Вакансия добавлена.')
            return redirect(url_for('vacancies'))
        flash('Укажите название вакансии.')
    return render_template('vacancy_form.html')

@app.route('/vacancies/<int:vacancy_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_vacancy(vacancy_id):
    conn = db()
    vacancy = conn.execute('SELECT * FROM vacancies WHERE id=?', (vacancy_id,)).fetchone()
    if vacancy is None:
        abort(404)
    if request.method == 'POST':
        fields = ['title', 'city', 'rate', 'schedule', 'warehouse_address', 'housing', 'transport', 'status']
        values = {field: request.form.get(field, '').strip() for field in fields}
        if not values['title']:
            flash('Укажите название вакансии.')
        else:
            conn.execute("UPDATE vacancies SET title=?, city=?, rate=?, schedule=?, warehouse_address=?, housing=?, transport=?, status=? WHERE id=?",
                         tuple(values[field] for field in fields) + (vacancy_id,))
            audit('Изменена вакансия', None, f"#{vacancy_id}: {values['title']}")
            conn.commit()
            flash('Вакансия обновлена.')
            return redirect(url_for('vacancies'))
    return render_template('vacancy_edit.html', vacancy=vacancy)

@app.route('/duties', methods=['GET', 'POST'])
@login_required
def duties_page():
    conn = db()
    if request.method == 'POST':
        if session.get('role') != 'admin':
            abort(403)
        content = request.form.get('content', '')
        if len(content) > 50000:
            abort(400, description='Слишком длинный текст.')
        conn.execute("INSERT INTO app_pages(slug,content) VALUES('duties',?) ON CONFLICT(slug) DO UPDATE SET content=excluded.content", (content,))
        audit('Изменены обязанности', None, 'Общая страница обязанностей')
        conn.commit()
        flash('Текст обязанностей сохранён.')
        return redirect(url_for('duties_page'))
    row = conn.execute("SELECT content FROM app_pages WHERE slug='duties'").fetchone()
    return render_template('duties.html', content=row['content'] if row else '', is_admin=session.get('role') == 'admin')

@app.route('/team')
@admin_required
def team():
    rows = db().execute('SELECT id,username,role,active,created_at FROM users ORDER BY id').fetchall()
    return render_template('team.html', users=rows)

@app.route('/team/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username','').strip(); password = request.form.get('password','')
    role = request.form.get('role','recruiter')
    if len(username) < 3 or len(password) < 12 or role not in ('admin','recruiter'):
        flash('Проверьте логин, пароль (минимум 12 символов) и роль.')
    else:
        try:
            db().execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)', (username,generate_password_hash(password),role))
            audit('Создан пользователь', None, username); db().commit(); flash('Пользователь создан.')
        except sqlite3.IntegrityError:
            flash('Такой логин уже существует.')
    return redirect(url_for('team'))

@app.route('/team/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    if user_id == session.get('user_id'):
        flash('Нельзя отключить собственный аккаунт.'); return redirect(url_for('team'))
    conn = db(); user = conn.execute('SELECT username,active FROM users WHERE id=?', (user_id,)).fetchone()
    if user:
        conn.execute('UPDATE users SET active=? WHERE id=?', (0 if user['active'] else 1, user_id))
        audit('Изменён доступ пользователя', None, user['username']); conn.commit()
        flash('Доступ сотрудника обновлён.')
    return redirect(url_for('team'))

@app.route('/audit')
@admin_required
def audit_page():
    rows = db().execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').fetchall()
    return render_template('audit.html', logs=rows)

@app.errorhandler(403)
def forbidden(_):
    return render_template('error.html', code=403, message='У вас нет прав для этого действия.'), 403

@app.errorhandler(404)
def not_found(_):
    return render_template('error.html', code=404, message='Запись или страница не найдена.'), 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
