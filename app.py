from flask import Flask, request, jsonify, render_template_string, make_response, redirect, send_file
import hmac, hashlib, time, sqlite3, secrets, os
from datetime import datetime, timedelta

app = Flask(__name__)

SHARED_SECRET = b'vrf-sign-8x92kd73mf04nzp1'
ADMIN_PASSWORD = "04pabome" 
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'licenses.db')

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         license_key TEXT UNIQUE, 
                         hwid TEXT, 
                         expires_at INTEGER, 
                         duration_hours INTEGER, 
                         is_used INTEGER DEFAULT 0,
                         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS trial_users (tg_id INTEGER PRIMARY KEY)''')
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database init error: {e}")

# Инициализация БД при запуске
init_db()

def generate_sig(is_valid, remaining_ms):
    data_str = f"{str(is_valid).lower()}:{remaining_ms}"
    return hmac.new(SHARED_SECRET, data_str.encode('utf-8'), hashlib.sha256).hexdigest()

@app.route('/')
def index():
    return jsonify({"status": "ok", "service": "Eidolon License Server"})

@app.route('/api/verify', methods=['POST'])
def api_verify():
    try:
        data = request.json
        user_key = data.get('key')
        user_hwid = data.get('hwid', 'default_hwid')
        user_tg_id = data.get('tg_id')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT hwid, expires_at, duration_hours, is_used FROM keys WHERE license_key = ?", (user_key,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return jsonify({"valid": False, "error": "Ключ не найден"}), 200
        
        db_hwid, db_expires, db_duration_hours, is_used = row
        
        if db_duration_hours == 0:
            if user_tg_id:
                cursor.execute("SELECT 1 FROM trial_users WHERE tg_id = ?", (user_tg_id,))
            else:
                cursor.execute("SELECT 1 FROM trial_users WHERE tg_id = ?", (user_hwid,))
                
            if cursor.fetchone():
                conn.close()
                return jsonify({"valid": False, "error": "Пробный период уже истек"}), 200

        if db_hwid and db_hwid != 'default_hwid' and db_hwid != user_hwid:
            conn.close()
            return jsonify({"valid": False, "error": "Ключ привязан к другому устройству"}), 200
        
        if not is_used or not db_expires:
            if db_duration_hours == 0:
                db_expires = int(time.time()) + 3600 
                try:
                    trial_id = user_tg_id if user_tg_id else user_hwid
                    cursor.execute("INSERT INTO trial_users (tg_id) VALUES (?)", (trial_id,))
                except sqlite3.IntegrityError: pass
            else:
                db_expires = int(time.time()) + (db_duration_hours * 3600)
            
            cursor.execute("UPDATE keys SET expires_at = ?, hwid = ?, is_used = 1 WHERE license_key = ?", 
                        (db_expires, user_hwid, user_key))
            conn.commit()
        
        conn.close()
        remaining_ms = (db_expires * 1000) - int(time.time() * 1000)
        sig = generate_sig(True, remaining_ms)
        return jsonify({"valid": True, "remaining_ms": remaining_ms, "sig": sig})
    except Exception as e:
        print(f"Error in verify: {e}")
        return jsonify({"valid": False, "error": "Server error"}), 500

@app.route('/api/check/<user_key>', methods=['GET'])
def check_license(user_key):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT expires_at FROM keys WHERE license_key = ?", (user_key,))
        row = cursor.fetchone()
        conn.close()
        if not row or not row[0]: return jsonify({"valid": False}), 404
        remaining_ms = (row[0] * 1000) - int(time.time() * 1000)
        if remaining_ms <= 0: return jsonify({"valid": False}), 200
        return jsonify({"valid": True, "remaining_ms": remaining_ms, "sig": generate_sig(True, remaining_ms)})
    except Exception as e:
        print(f"Error in check: {e}")
        return jsonify({"valid": False, "error": "Server error"}), 500

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Eidolon Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #f8f9fa; }
        .card { box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .login-container { max-width: 400px; margin: 100px auto; }
        th { cursor: pointer; }
        th:hover { background-color: #e9ecef; }
    </style>
</head>
<body>
{% if not authorized %}
    <div class="login-container card p-4">
        <h3 class="text-center mb-4">Вход в Админку</h3>
        {% if error %}
        <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="post" action="/IjhxBAQlUS3Q2yXYdY3C/login">
            <div class="mb-3">
                <input type="password" class="form-control" name="password" placeholder="Пароль" required>
            </div>
            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" name="remember" id="remember">
                <label class="form-check-label" for="remember">Запомнить меня</label>
            </div>
            <button type="submit" class="btn btn-primary w-100">Войти</button>
        </form>
    </div>
{% else %}
<div class="container-fluid">
    <div class="row">
        <main class="col-md-12 ms-sm-auto col-lg-12 px-md-4">
            <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h1 class="h2">Панель управления</h1>
                <div>
                    <a href="/IjhxBAQlUS3Q2yXYdY3C/db/export" class="btn btn-sm btn-outline-primary">Скачать БД</a>
                    <a href="/IjhxBAQlUS3Q2yXYdY3C/logout" class="btn btn-sm btn-outline-danger">Выйти</a>
                </div>
            </div>

            <div class="row mb-4">
                <div class="col-xl-4 col-md-6 mb-4">
                    <div class="card border-left-primary h-100 py-2">
                        <div class="card-body">
                            <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">Всего ключей</div>
                            <div class="h5 mb-0 font-weight-bold">{{ stats.total }}</div>
                        </div>
                    </div>
                </div>
                <div class="col-xl-4 col-md-6 mb-4">
                    <div class="card border-left-success h-100 py-2">
                        <div class="card-body">
                            <div class="text-xs font-weight-bold text-success text-uppercase mb-1">Активировано</div>
                            <div class="h5 mb-0 font-weight-bold">{{ stats.used }}</div>
                        </div>
                    </div>
                </div>
                <div class="col-xl-4 col-md-6 mb-4">
                    <div class="card border-left-warning h-100 py-2">
                        <div class="card-body">
                            <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">Свободно</div>
                            <div class="h5 mb-0 font-weight-bold">{{ stats.unused }}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card p-4 mb-4">
                <h5>Генерация ключей</h5>
                <form method="post" action="/IjhxBAQlUS3Q2yXYdY3C/generate" class="row g-3">
                    <div class="col-md-2">
                        <label class="form-label">Количество</label>
                        <input type="number" class="form-control" name="count" value="1" min="1" max="100">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Число</label>
                        <input type="number" class="form-control" name="duration_value" value="1" min="1" max="999">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Период</label>
                        <select name="duration_unit" class="form-select">
                            <option value="hours">Часы</option>
                            <option value="days">Дни</option>
                            <option value="weeks">Недели</option>
                            <option value="months">Месяцы</option>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <div class="form-check mt-4">
                            <input type="checkbox" class="form-check-input" name="trial" id="trial" value="1">
                            <label class="form-check-label" for="trial">Пробный</label>
                        </div>
                    </div>
                    <div class="col-md-2">
                        <label class="form-label">&nbsp;</label>
                        <button type="submit" class="btn btn-success w-100 mt-2">Генерировать</button>
                    </div>
                </form>
            </div>

            <div class="card p-4">
                <h5>Список ключей</h5>
                <div class="table-responsive">
                    <table class="table table-striped table-hover" id="keysTable">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Ключ</th>
                                <th>Срок</th>
                                <th>HWID</th>
                                <th>Статус</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for row in keys %}
                            <tr>
                                <td>{{ row[0] }}</td>
                                <td><code>{{ row[1] }}</code></td>
                                <td>
                                    {% if row[4] == 0 %}
                                        Пробный
                                    {% elif row[4] >= 720 %}
                                        ~{{ (row[4] / 720) | int }} мес.
                                    {% elif row[4] >= 168 %}
                                        {{ (row[4] / 168) | int }} нед.
                                    {% elif row[4] >= 24 %}
                                        {{ (row[4] / 24) | int }} дн.
                                    {% else %}
                                        {{ row[4] }} ч.
                                    {% endif %}
                                </td>
                                <td><small>{{ row[2] or 'Свободен' }}</small></td>
                                <td>
                                    {% if row[5] == 1 %}
                                        <span class="badge bg-success">Использован</span>
                                    {% else %}
                                        <span class="badge bg-secondary">Свободен</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <form method="post" action="/IjhxBAQlUS3Q2yXYdY3C/reset/{{ row[1] }}" style="display: inline;">
                                        <button type="submit" class="btn btn-sm btn-warning">Сброс</button>
                                    </form>
                                    <form method="post" action="/IjhxBAQlUS3Q2yXYdY3C/delete/{{ row[1] }}" style="display: inline;" onsubmit="return confirm('Удалить ключ?');">
                                        <button type="submit" class="btn btn-sm btn-danger">Удалить</button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>
</div>

<script>
    const ctx1 = document.getElementById('statusChart');
    if (ctx1) {
        new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['Использовано', 'Свободно'],
                datasets: [{
                    data: [{{ stats.used }}, {{ stats.unused }}],
                    backgroundColor: ['#28a745', '#ffc107']
                }]
            }
        });
    }
</script>
{% endif %}
</body>
</html>
"""

@app.route('/IjhxBAQlUS3Q2yXYdY3C', methods=['GET'])
def admin_page():
    try:
        auth_token = request.cookies.get('admin_token')
        authorized = (auth_token == ADMIN_PASSWORD)
        
        if not authorized:
            return render_template_string(HTML_TEMPLATE, authorized=False)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, license_key, hwid, expires_at, duration_hours, is_used FROM keys ORDER BY created_at DESC")
        rows = cursor.fetchall()
        
        cursor.execute("SELECT count(*) FROM keys")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM keys WHERE is_used = 1")
        used = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM keys WHERE is_used = 0")
        unused = cursor.fetchone()[0]
        
        stats = {'total': total, 'used': used, 'unused': unused}
        conn.close()
        
        return render_template_string(HTML_TEMPLATE, keys=rows, stats=stats, authorized=True)
    except Exception as e:
        print(f"Error in admin page: {e}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/IjhxBAQlUS3Q2yXYdY3C/login', methods=['POST'])
def login():
    password = request.form.get('password')
    remember = request.form.get('remember')
    
    if password == ADMIN_PASSWORD:
        resp = make_response(redirect('/IjhxBAQlUS3Q2yXYdY3C'))
        if remember:
            resp.set_cookie('admin_token', password, max_age=timedelta(days=30))
        else:
            resp.set_cookie('admin_token', password)
        return resp
    
    return render_template_string(HTML_TEMPLATE, authorized=False, error="Неверный пароль"), 403

@app.route('/IjhxBAQlUS3Q2yXYdY3C/logout')
def logout():
    resp = make_response(redirect('/IjhxBAQlUS3Q2yXYdY3C'))
    resp.delete_cookie('admin_token')
    return resp

@app.route('/IjhxBAQlUS3Q2yXYdY3C/generate', methods=['POST'])
def generate_keys():
    if request.cookies.get('admin_token') != ADMIN_PASSWORD:
        return "Unauthorized", 403
    
    try:
        count = int(request.form.get('count', 1))
        is_trial = request.form.get('trial') == '1'
        
        if is_trial:
            duration_hours = 0
        else:
            duration_value = int(request.form.get('duration_value', 1))
            duration_unit = request.form.get('duration_unit', 'hours')
            
            if duration_unit == 'hours':
                duration_hours = duration_value
            elif duration_unit == 'days':
                duration_hours = duration_value * 24
            elif duration_unit == 'weeks':
                duration_hours = duration_value * 168
            elif duration_unit == 'months':
                duration_hours = duration_value * 720
            else:
                duration_hours = 24
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        generated_keys = []
        for _ in range(count):
            k = '-'.join(''.join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4)) for _ in range(3))
            cursor.execute("INSERT INTO keys (license_key, duration_hours) VALUES (?, ?)", (k, duration_hours))
            generated_keys.append(k)
        
        conn.commit()
        conn.close()
        return redirect('/IjhxBAQlUS3Q2yXYdY3C')
    except Exception as e:
        print(f"Error generating keys: {e}")
        return f"Error: {str(e)}", 500

@app.route('/IjhxBAQlUS3Q2yXYdY3C/db/export', methods=['GET'])
def export_db():
    if request.cookies.get('admin_token') != ADMIN_PASSWORD:
        return "Unauthorized", 403
    
    try:
        return send_file(DB_PATH, as_attachment=True, download_name=f"backup_{int(time.time())}.db")
    except Exception as e:
        print(f"Error exporting DB: {e}")
        return f"Error: {str(e)}", 500

@app.route('/IjhxBAQlUS3Q2yXYdY3C/db/import', methods=['POST'])
def import_db():
    if request.cookies.get('admin_token') != ADMIN_PASSWORD:
        return "Unauthorized", 403
    
    try:
        file = request.files.get('db_file')
        if file and file.filename.endswith('.db'):
            file.save(DB_PATH)
            return redirect('/IjhxBAQlUS3Q2yXYdY3C')
        return "Неверный файл", 400
    except Exception as e:
        print(f"Error importing DB: {e}")
        return f"Error: {str(e)}", 500

@app.route('/IjhxBAQlUS3Q2yXYdY3C/reset/<key>', methods=['POST'])
def reset_key(key):
    if request.cookies.get('admin_token') != ADMIN_PASSWORD:
        return "Unauthorized", 403
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE keys SET hwid = NULL, expires_at = NULL, is_used = 0 WHERE license_key = ?", (key,))
        conn.commit()
        conn.close()
        return redirect('/IjhxBAQlUS3Q2yXYdY3C')
    except Exception as e:
        print(f"Error resetting key: {e}")
        return f"Error: {str(e)}", 500

@app.route('/IjhxBAQlUS3Q2yXYdY3C/delete/<key>', methods=['POST'])
def delete_key(key):
    if request.cookies.get('admin_token') != ADMIN_PASSWORD:
        return "Unauthorized", 403
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys WHERE license_key = ?", (key,))
        conn.commit()
        conn.close()
        return redirect('/IjhxBAQlUS3Q2yXYdY3C')
    except Exception as e:
        print(f"Error deleting key: {e}")
        return f"Error: {str(e)}", 500

# Обработчик ошибок
@app.errorhandler(500)
def internal_error(error):
    return f"Internal Server Error: {str(error)}", 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
