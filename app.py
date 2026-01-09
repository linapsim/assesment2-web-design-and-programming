from flask import Flask, render_template, request, flash, session, redirect, url_for
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "lksdbdksadb sakdaslkjdsajkdh ajskdh sakjdsajdhasldhlajsh"


#DATABASE

def get_db():
    conn = sqlite3.connect('crm.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            role TEXT CHECK(role IN ('admin','manager','employee')) NOT NULL,
            status TEXT CHECK(status IN ('active','disabled')) DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            category TEXT,
            status TEXT CHECK(status IN ('Active','Disabled')) DEFAULT 'Active',
            last_contact TEXT
        )
    """)

    conn.commit()
    conn.close()



#AUTH 

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, password_hash):
    return hash_password(password) == password_hash


def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def role_required(role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))

            if session.get('user_role') != role:
                flash('Access denied', 'danger')
                return redirect(url_for('login'))

            return f(*args, **kwargs)

        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

#PUBLIC

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

#REGISTER

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        full_name = request.form['full_name']
        role = request.form['role']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        conn = get_db()
        cursor = conn.cursor()

        if cursor.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            flash('Email already exists')
            conn.close()
            return redirect(url_for('register'))

        cursor.execute("""
            INSERT INTO users (email,password_hash,full_name,role)
            VALUES (?,?,?,?)
        """, (email, hash_password(password), full_name, role))

        conn.commit()
        conn.close()
        return redirect(url_for('login'))

    return render_template('signup.html')



#LOGIN

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        selected_role = request.form.get('login_role')

        conn = get_db()
        user = conn.execute("""
            SELECT * FROM users 
            WHERE email=? AND status='active'
        """, (email,)).fetchone()
        conn.close()

        if not user or not verify_password(password, user['password_hash']):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

        if selected_role != user['role']:
            flash('You are not allowed to log in as this role', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user['id']
        session['user_role'] = user['role']

        if user['role'] == 'admin':
            return redirect(url_for('admin_dash'))
        if user['role'] == 'manager':
            return redirect(url_for('manager_dashboard'))
        return redirect(url_for('employee_dash'))

    return render_template('login.html')

#ADMIN

@app.route('/admin/dashboard')
@login_required

@role_required('admin')

def admin_dash():
    if session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    users = conn.execute("""
        SELECT id, full_name, email, role, status
        FROM users
    """).fetchall()
    conn.close()

    return render_template('admin_dash.html', users=users)


@app.route('/admin/users/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_users_search():
    if session.get('user_role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    user = None
    q = request.args.get('q', '').strip()

    if q:
        user = cursor.execute("""
            SELECT id, full_name, email, phone, role, status
            FROM users
            WHERE email = ? OR full_name LIKE ?
        """, (q, f'%{q}%')).fetchone()

    if request.method == 'POST':
        cursor.execute("""
            UPDATE users
            SET full_name=?, email=?, phone=?, role=?, status=?
            WHERE id=?
        """, (
            request.form['full_name'],
            request.form['email'],
            request.form['phone'],
            request.form['role'],
            request.form['status'],
            request.form['user_id']
        ))

        conn.commit()
        conn.close()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_edit_users'))

    conn.close()
    return render_template(
        'admin_edit_users.html',
        user=user,
        q=q
    )



@app.route('/admin/users/edit/<int:user_id>', methods=['GET','POST'])
@login_required
def admin_edit_users(user_id):
    if session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    user = cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if request.method == 'POST':
        cursor.execute("""
            UPDATE users
            SET full_name=?, phone=?, role=?, status=?
            WHERE id=?
        """, (
            request.form['full_name'],
            request.form['phone'],
            request.form['role'],
            request.form['status'],
            user_id
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_edit_users'))

    conn.close()
    return render_template('admin_edit_users.html', user_id=user_id)


@app.route('/admin/users/activate/<int:user_id>')
@login_required
def activate_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dash', user_id=user_id))


@app.route('/admin/users/disable/<int:user_id>')
@login_required
def disable_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET status='disabled' WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dash', user_id=user_id))


@app.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    password = request.form['password']
    confirm = request.form['confirm_password']

    if password != confirm:
        flash('Passwords do not match')
        return redirect(url_for('admin_edit_users', user_id=user_id))

    conn = get_db()
    conn.execute("""
        UPDATE users SET password_hash=? WHERE id=?
    """, (hash_password(password), user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_edit_users', user_id=user_id))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    return render_template('admin_settings.html')

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def admin_add_users():
    if session.get('user_role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']
        password = request.form['password']

        conn = get_db()
        conn.execute("""
            INSERT INTO users (full_name, email, phone, role, password_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (full_name, email, phone, role, hash_password(password)))

        conn.commit()
        conn.close()

        flash('User added successfully', 'success')
        return redirect(url_for('admin_dash'))

    return render_template('admin_add_users.html')

#MANAGER

@app.route('/manager/dashboard')
@login_required

@role_required('manager')

def manager_dashboard():
    return render_template('manager_dash.html')

@app.route('/manager/employee')
@login_required
def manager_employee():
    if session.get('user_role') != 'manager':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    return render_template('manager_employee.html')

@app.route('/manager/clients')
@login_required
def manager_clients():
    if session.get('user_role') != 'manager':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    return render_template('manager_clients.html')

@app.route('/manager/settings')
@login_required
def manager_settings():
    if session.get('user_role') != 'manager':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    return render_template('manager_settings.html')

#EMPLOYEE

@app.route('/employee/dash')
@login_required

@role_required('employee')

def employee_dash():
    conn = get_db()
    cursor = conn.cursor()

    tables = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    print("TABLES:", tables)

    clients = cursor.execute("""
        SELECT id, full_name, phone, last_contact, status
        FROM clients
    """).fetchall()

    print("CLIENTS:", clients)

    conn.close()
    return render_template('employee_dash.html', clients=clients)


@app.route('/employee/client/activate/<int:client_id>')
@login_required
def employee_activate_client(client_id):
    conn = get_db()
    conn.execute(
        "UPDATE clients SET status='Active' WHERE id=?",
        (client_id,)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('employee_dash'))


@app.route('/employee/client/deactivate/<int:client_id>')
@login_required
def employee_deactivate_client(client_id):
    conn = get_db()
    conn.execute(
        "UPDATE clients SET status='Disabled' WHERE id=?",
        (client_id,)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('employee_dash'))

@app.route('/employee/clients/add', methods=['GET', 'POST'])
@login_required
def employee_add_clients():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        category = request.form['category']
        status = request.form['status']

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO clients (full_name, email, phone, category, status)
            VALUES (?, ?, ?, ?, ?)
        """, (full_name, email, phone, category, status))

        conn.commit()
        conn.close()

        flash('Client added successfully!', 'success')
        return redirect(url_for('employee_dash'))

    return render_template('employee_add_clients.html')

@app.route('/employee/client/edit/<int:client_id>', methods=['GET', 'POST'])
@login_required
def employee_edit_client(client_id):
    conn = get_db()
    cursor = conn.cursor()

    client = cursor.execute(
        "SELECT * FROM clients WHERE id=?",
        (client_id,)
    ).fetchone()

    if request.method == 'POST':
        cursor.execute("""
            UPDATE clients
            SET full_name=?, phone=?, email=?, category=?, status=?
            WHERE id=?
        """, (
            request.form['full_name'],
            request.form['phone'],
            request.form['email'],
            request.form['category'],
            request.form['status'],
            client_id
        ))

        conn.commit()
        conn.close()
        flash('Client updated successfully', 'success')
        return redirect(url_for('employee_dash'))

    conn.close()
    return render_template('employee_edit_client.html', client=client)

@app.route('/employee/client/view/<int:client_id>')
@login_required
def employee_view_client(client_id):
    conn = get_db()
    client = conn.execute(
        "SELECT * FROM clients WHERE id=?",
        (client_id,)
    ).fetchone()
    conn.close()

    return render_template(
        'employee_view_customer.html',
        client=client
    )

@app.route('/employee/clients/edit', methods=['GET', 'POST'])
@login_required
def employee_edit_clients():
    conn = get_db()
    cursor = conn.cursor()

    q = request.args.get('q', '').strip()
    client_id = request.args.get('client_id')
    mode = request.args.get('mode', 'view')

    clients = []
    selected_client = None

    if q:
        clients = cursor.execute("""
            SELECT * FROM clients
            WHERE full_name LIKE ?
               OR phone LIKE ?
               OR email LIKE ?
        """, (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()

    if client_id:
        selected_client = cursor.execute(
            "SELECT * FROM clients WHERE id=?",
            (client_id,)
        ).fetchone()

    if request.method == 'POST':
        cursor.execute("""
            UPDATE clients
            SET full_name=?, phone=?, email=?, status=?, category=?
            WHERE id=?
        """, (
            request.form['full_name'],
            request.form['phone'],
            request.form['email'],
            request.form['status'],
            request.form['category'],
            request.form['client_id']
        ))
        conn.commit()
        conn.close()
        flash('Client updated successfully', 'success')
        return redirect(url_for('employee_edit_clients'))

    conn.close()

    return render_template(
        'employee_edit_clients.html',
        clients=clients,
        client=selected_client,
        q=q,
        mode=mode
    )

#RUN

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)
