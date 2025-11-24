# app.py — Combined & fixed version
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func
import os
from datetime import datetime

# ---------- Config ----------
app = Flask(__name__)
app.secret_key = "buzzard_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///buzzard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ---------- Models ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True)   # username
    password = db.Column(db.String(200))
    role = db.Column(db.String(50))  # admin, finance, head, it
    department = db.Column(db.String(100), nullable=True)

    # optional profile fields
    last_name = db.Column(db.String(100))
    given_name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    address = db.Column(db.String(200))
    contact_number = db.Column(db.String(50))
    birthday = db.Column(db.String(20))
    email = db.Column(db.String(150))
    pin = db.Column(db.String(10), default="0000")
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def full_name(self):
        parts = [self.given_name, self.middle_name, self.last_name]
        return ' '.join([p for p in parts if p]) or self.name

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    date = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="Pending")  # Pending, Approved, Rejected
    submitted_by = db.Column(db.String(150), nullable=False)  # username
    department = db.Column(db.String(100), nullable=True)
    purpose = db.Column(db.Text, nullable=True)
    receipt = db.Column(db.String(300), nullable=True)
    coa = db.Column(db.String(300), nullable=True)
    reviewed_by = db.Column(db.String(150), nullable=True)  # who approved/rejected

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100), unique=True)
    allocated = db.Column(db.Float, default=0.0)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ---------- Utility ----------
def save_uploaded_file(fileobj):
    if not fileobj or fileobj.filename == "":
        return None
    filename = secure_filename(fileobj.filename)
    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    # if same filename exists, generate a unique suffix
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(dest):
        filename = f"{base}_{counter}{ext}"
        dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        counter += 1
    fileobj.save(dest)
    return filename

# ---------- Routes ----------
@app.route('/')
def home():
    return redirect(url_for('login'))

# ---- Auth ----
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Please enter both username and password", "error")
            return redirect(url_for('login'))
        user = User.query.filter(func.lower(User.name) == username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.full_name}!", "success")
            # role redirect
            if user.role == 'admin':
                return redirect(url_for('dashboard_admin'))
            if user.role == 'finance':
                return redirect(url_for('dashboard_finance'))
            if user.role == 'head':
                return redirect(url_for('dashboard_head'))
            if user.role == 'it':
                return redirect(url_for('dashboard_it'))
            # fallback
            return redirect(url_for('login'))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---- Uploads (serve receipts) ----
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # only authenticated users can access receipts
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# ---- IT dashboard (and user mgmt) ----
@app.route("/it")
@login_required
def dashboard_it():
    if current_user.role.lower() not in ["it", "admin"]:
        flash("Access Denied", "error")
        return redirect(url_for("login"))
    users = User.query.order_by(User.id.desc()).all()
    return render_template("dashboard_it.html", users=users)

@app.route("/admin")
@login_required
def dashboard_admin():
    if current_user.role.lower() != "admin":
        flash("Access Denied", "error")
        return redirect(url_for("login"))

    # COA Mapping
    coa_map = {
        'Software Licenses & Subscriptions': 6230,
        'Hardware Maintenance & Upgrades': 6240,
        'Recruitment & Hiring Costs': 6250,
        'Employee Training & Development': 6260,
        'Logistics & Transportation': 6270,
        'Office Supplies & Utilities': 6280,
        'Customer Support Tools & Software': 6290,
        'Staff Overtime & Incentives': 5011,
        'Advertising & Promotions': 6300,
        'Event & Campaign Costs': 6310,
        'Research Materials & Equipment': 6320,
        'Prototyping & Testing Costs': 6330,
        'Others': 6399
    }

    # Expense Summary Stats
    total_expenses = Expense.query.count()
    total_pending = Expense.query.filter_by(status="Pending").count()
    total_approved = Expense.query.filter_by(status="Approved").count()
    total_rejected = Expense.query.filter_by(status="Rejected").count()

    # CATEGORY CHART DATA
    category_data = db.session.query(
        Expense.category,
        db.func.sum(Expense.amount)
    ).group_by(Expense.category).all()
    category_labels = [row[0] for row in category_data] if category_data else []
    category_values = [float(row[1]) for row in category_data] if category_data else []

    # MONTHLY EXPENSE CHART DATA
    monthly_data = db.session.query(
        db.func.strftime("%Y-%m", Expense.date),
        db.func.sum(Expense.amount)
    ).group_by(db.func.strftime("%Y-%m", Expense.date)).all()
    monthly_labels = [row[0] for row in monthly_data] if monthly_data else []
    monthly_values = [float(row[1]) for row in monthly_data] if monthly_data else []

    # WEEKLY EXPENSE CHART DATA
    weekly_data = db.session.query(
        db.func.strftime("%Y-%W", Expense.date),
        db.func.sum(Expense.amount)
    ).group_by(db.func.strftime("%Y-%W", Expense.date)).all()
    weekly_labels = [row[0] for row in weekly_data] if weekly_data else []
    weekly_values = [float(row[1]) for row in weekly_data] if weekly_data else []

    # DEPARTMENT CHART DATA
    department_data = db.session.query(
        Expense.department,
        db.func.sum(Expense.amount)
    ).group_by(Expense.department).all()
    department_labels = [row[0] for row in department_data] if department_data else []
    department_values = [float(row[1]) for row in department_data] if department_data else []

    # Expenses lists for tables
    pending_expenses = Expense.query.filter_by(status="Pending").order_by(Expense.id.desc()).all()
    done_expenses = Expense.query.filter(Expense.status.in_(["Approved","Rejected"])).order_by(Expense.id.desc()).all()

    # Budgets
    budgets = []
    for b in Budget.query.all():
        used = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.department==b.department, Expense.status=="Approved"
        ).scalar() or 0
        budgets.append({
            "id": b.id,
            "department": b.department,
            "allocated": b.allocated,
            "used": used,
            "remaining": b.allocated - used
        })

    # Users
    users = User.query.all()

    # Render template with all chart & table data
    return render_template(
        "dashboard_admin.html",
        total_expenses=total_expenses,
        total_pending=total_pending,
        total_approved=total_approved,
        total_rejected=total_rejected,
        category_labels=category_labels,
        category_values=category_values,
        monthly_labels=monthly_labels,
        monthly_values=monthly_values,
        weekly_labels=weekly_labels,
        weekly_values=weekly_values,
        department_labels=department_labels,
        department_values=department_values,
        pending_expenses=pending_expenses,
        done_expenses=done_expenses,
        budgets=budgets,
        users=users,
        coa_map=coa_map  # <---- Pass COA map to template
    )



@app.route("/head")
@login_required
def dashboard_head():
    if current_user.role.lower() != "head":
        flash("Access Denied", "error")
        return redirect(url_for("login"))
    expenses = Expense.query.filter_by(submitted_by=current_user.name).order_by(Expense.id.desc()).all()
    categories = [
        "Software Licenses & Subscriptions","Hardware Maintenance & Upgrades",
        "Recruitment & Hiring Costs","Employee Training & Development",
        "Logistics & Transportation","Office Supplies & Utilities",
        "Customer Support Tools & Software","Staff Overtime & Incentives",
        "Advertising & Promotions","Event & Campaign Costs",
        "Research Materials & Equipment","Prototyping & Testing Costs","Others"
    ]
    return render_template("dashboard_dept.html", expenses=expenses, categories=categories)

# ---- Finance dashboard ----
@app.route("/finance")
@login_required
def dashboard_finance():
    if current_user.role.lower() not in ["finance", "admin"]:
        flash("Access Denied", "error")
        return redirect(url_for("login"))
    
    # COA MAP (ADD THIS)
    coa_map = {
        'Software Licenses & Subscriptions': 6230,
        'Hardware Maintenance & Upgrades': 6240,
        'Recruitment & Hiring Costs': 6250,
        'Employee Training & Development': 6260,
        'Logistics & Transportation': 6270,
        'Office Supplies & Utilities': 6280,
        'Customer Support Tools & Software': 6290,
        'Staff Overtime & Incentives': 5011,
        'Advertising & Promotions': 6300,
        'Event & Campaign Costs': 6310,
        'Research Materials & Equipment': 6320,
        'Prototyping & Testing Costs': 6330,
        'Others': 6399
    }

    # EXPENSES
    pending_expenses = Expense.query.filter(Expense.status == "Pending").order_by(Expense.id.desc()).all()
    expenses = Expense.query.order_by(Expense.id.desc()).all()

    # APPLY COA CODE FOR DISPLAY (FIX N/A ISSUE)
    for e in expenses:
        e.coa = coa_map.get(e.category, "N/A")

    # BUDGETS
    budgets = []
    for b in Budget.query.all():
        used = db.session.query(func.sum(Expense.amount)).filter(
            Expense.department == b.department,
            Expense.status == "Approved"
        ).scalar() or 0
      
        budgets.append({
            "id": b.id,
            "department": b.department,
            "allocated": b.allocated,
            "used": used,
            "remaining": b.allocated - used
        })

    # CHARTS
    category_data = db.session.query(Expense.category, func.sum(Expense.amount)).filter(Expense.status=="Approved").group_by(Expense.category).all()
    category_labels = [c[0] for c in category_data]
    category_values = [c[1] for c in category_data]

    dept_data = db.session.query(Expense.department, func.sum(Expense.amount)).filter(Expense.status=="Approved").group_by(Expense.department).all()
    dept_labels = [d[0] for d in dept_data]
    dept_values = [d[1] for d in dept_data]

    weekly_data = db.session.query(func.strftime("%Y-%W", Expense.date), func.sum(Expense.amount)).filter(Expense.status=="Approved").group_by(func.strftime("%Y-%W", Expense.date)).all()
    weekly_labels = [w[0] for w in weekly_data]
    weekly_values = [w[1] for w in weekly_data]

    monthly_data = db.session.query(func.strftime("%Y-%m", Expense.date), func.sum(Expense.amount)).filter(Expense.status=="Approved").group_by(func.strftime("%Y-%m", Expense.date)).all()
    monthly_labels = [m[0] for m in monthly_data]
    monthly_values = [m[1] for m in monthly_data]

    charts = {
        "category": {"labels": category_labels, "data": category_values},
        "dept": {"labels": dept_labels, "data": dept_values},
        "weekly": {"labels": weekly_labels, "data": weekly_values},
        "monthly": {"labels": monthly_labels, "data": monthly_values},
        "budget": {"labels": [b['department'] for b in budgets], "data": [b['remaining'] for b in budgets]}
    }

    return render_template(
        'dashboard_finance.html',
        pending_expenses=pending_expenses,
        expenses=expenses,
        done_expenses=[e for e in expenses if e.status in ("Approved","Rejected")],
        budgets=budgets,
        charts=charts
    )


# ---- Create user (admin & it) ----
@app.route('/create_user', methods=['GET','POST'])
@login_required
def create_user():
    # Only Admin and IT can create users
    if current_user.role.lower() not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        if User.query.filter_by(name=username).first():
            flash("Username already exists", "error")
            return redirect(url_for('create_user'))

        # Hash the password
        password_hash = generate_password_hash(request.form['password'].strip())

        # Role & department
        role = request.form['role']
        department = request.form.get('department', '')

        # Handle PIN
        pin_input = request.form.get('pin')
        if not pin_input:
            pin_input = '6969'  # default PIN
        hashed_pin = generate_password_hash(pin_input)

        # Create the user
        user = User(
            name=username,
            password=password_hash,
            role=role,
            department=department,
            last_name=request.form.get('last_name', ''),
            given_name=request.form.get('given_name', ''),
            middle_name=request.form.get('middle_name', ''),
            address=request.form.get('address', ''),
            contact_number=request.form.get('contact_number', ''),
            birthday=request.form.get('birthday', ''),
            email=request.form.get('email', ''),
            pin=hashed_pin
        )

        db.session.add(user)
        db.session.commit()

        flash("User created successfully", "success")
        # Redirect depending on creator's role
        return redirect(url_for('dashboard_it') if current_user.role.lower() == 'it' else url_for('dashboard_admin'))

    return render_template('create_user.html')

# ---- Edit user (admin & it) ----
@app.route('/edit_user/<int:user_id>', methods=['GET','POST'])
@login_required
def edit_user(user_id):
    if current_user.role.lower() not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.name = request.form['username'].strip()
        
        if request.form.get('password'):
            user.password = generate_password_hash(request.form['password'].strip())
        
        user.role = request.form.get('role', user.role)
        user.department = request.form.get('department', user.department)
        user.last_name = request.form.get('last_name', user.last_name)
        user.given_name = request.form.get('given_name', user.given_name)
        user.middle_name = request.form.get('middle_name', user.middle_name)
        user.address = request.form.get('address', user.address)
        user.contact_number = request.form.get('contact_number', user.contact_number)
        user.birthday = request.form.get('birthday', user.birthday)
        user.email = request.form.get('email', user.email)
        
        # Optionally allow admin/IT to set PIN
        pin_input = request.form.get('pin')
        if pin_input:
            pin_input = pin_input.strip()
            if pin_input.isdigit() and len(pin_input) == 4:
                user.pin = generate_password_hash(pin_input)
        
        db.session.commit()
        flash("User updated successfully", "success")
        return redirect(url_for('dashboard_it') if current_user.role.lower() == 'it' else url_for('dashboard_admin'))
    
    return render_template('edit_user.html', user=user)


# ---- Delete user (admin & it) with PIN confirmation ----
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role.lower() not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))
    
    pin_input = request.form.get('pin', '').strip()
    if not current_user.pin or not check_password_hash(current_user.pin, pin_input):
        flash("Invalid PIN", "error")
        return redirect(request.referrer or url_for('dashboard_admin'))

    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting yourself
    if user.id == current_user.id:
        flash("You cannot delete yourself", "error")
        return redirect(request.referrer or url_for('dashboard_admin'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash("User deleted", "success")
    return redirect(url_for('dashboard_admin'))


# ---- Change PIN (admin, it, finance) via JSON API (used by JS) ----
@app.route("/change_pin", methods=["GET", "POST"])
@login_required
def change_pin():
    user = current_user

    # Only allow Admin, IT, Finance roles
    if user.role.lower() not in ["admin", "it", "finance"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("dashboard_admin" if user.role=="admin" else "dashboard_it"))

    if request.method == "POST":
        current_pin = request.form.get("current_pin", "").strip()
        new_pin = request.form.get("new_pin", "").strip()
        confirm_pin = request.form.get("confirm_pin", "").strip()

        # Check if current PIN is correct
        if not current_pin or not check_password_hash(user.pin, current_pin):
            flash("Current PIN is incorrect.", "danger")
            return redirect(url_for("change_pin"))

        # Check new PIN confirmation
        if new_pin != confirm_pin:
            flash("New PIN and confirmation do not match.", "danger")
            return redirect(url_for("change_pin"))

        # Update PIN in database (hashed)
        user.pin = generate_password_hash(new_pin)
        db.session.commit()

        flash("PIN changed successfully!", "success")

        # Redirect based on role
        if user.role == "admin":
            return redirect(url_for("dashboard_admin"))
        elif user.role == "it":
            return redirect(url_for("dashboard_it"))
        else:  # finance
            return redirect(url_for("dashboard_finance"))

    return render_template("change_pin.html", user=user)


# ---- Submit new expense (head & finance) ----
@app.route('/new_expense', methods=['GET','POST'])
@login_required
def new_expense():
    if current_user.role not in ['head', 'finance']:
        flash("Access Denied: Only Head and Finance can submit expenses.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        category = request.form.get('category', 'Others')
        amount = float(request.form.get('amount', 0))
        date = request.form.get('date') or datetime.utcnow().strftime("%Y-%m-%d")
        purpose = request.form.get('purpose', '')
        receipt_file = request.files.get('receipt')
        filename = save_uploaded_file(receipt_file)

        department = current_user.department or "Finance" if current_user.role=='finance' else (current_user.department or "")
        new_exp = Expense(
            title=title,
            category=category,
            amount=amount,
            date=date,
            purpose=purpose,
            receipt=filename,
            submitted_by=current_user.name,
            department=department
        )
        db.session.add(new_exp)
        db.session.commit()
        flash("Expense submitted successfully!", "success")
        return redirect(url_for('dashboard_head') if current_user.role=='head' else url_for('dashboard_finance'))

    # categories shown on the submission form
    categories = [
        "Software Licenses & Subscriptions","Hardware Maintenance & Upgrades",
        "Recruitment & Hiring Costs","Employee Training & Development",
        "Logistics & Transportation","Office Supplies & Utilities",
        "Customer Support Tools & Software","Staff Overtime & Incentives",
        "Advertising & Promotions","Event & Campaign Costs",
        "Research Materials & Equipment","Prototyping & Testing Costs","Others"
    ]
    return render_template('new_expense.html', categories=categories)

# ---- Edit expense (only own & pending, head & finance) ----
@app.route('/edit_expense/<int:expense_id>', methods=['GET','POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if current_user.role not in ['head', 'finance']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))
    # only owner can edit
    if expense.submitted_by != current_user.name:
        flash("Access Denied: You can only edit your own expenses.", "error")
        return redirect(url_for('dashboard_head') if current_user.role=='head' else url_for('dashboard_finance'))
    # only pending can be edited
    if expense.status != "Pending":
        flash("Cannot edit an expense that is already processed.", "error")
        return redirect(url_for('dashboard_head') if current_user.role=='head' else url_for('dashboard_finance'))

    if request.method == 'POST':
        expense.title = request.form.get('title', expense.title)
        expense.category = request.form.get('category', expense.category)
        expense.amount = float(request.form.get('amount', expense.amount))
        expense.date = request.form.get('date', expense.date)
        expense.purpose = request.form.get('purpose', expense.purpose)
        receipt_file = request.files.get('receipt')
        if receipt_file and receipt_file.filename:
            filename = save_uploaded_file(receipt_file)
            expense.receipt = filename
        db.session.commit()
        flash("Expense updated successfully!", "success")
        return redirect(url_for('dashboard_head') if current_user.role=='head' else url_for('dashboard_finance'))

    categories = [
        "Software Licenses & Subscriptions","Hardware Maintenance & Upgrades",
        "Recruitment & Hiring Costs","Employee Training & Development",
        "Logistics & Transportation","Office Supplies & Utilities",
        "Customer Support Tools & Software","Staff Overtime & Incentives",
        "Advertising & Promotions","Event & Campaign Costs",
        "Research Materials & Equipment","Prototyping & Testing Costs","Others"
    ]
    return render_template('edit_expense.html', expense=expense, categories=categories)

# ---- Approve expense (finance/admin) ----
@app.route('/approve_expense/<int:expense_id>', methods=['POST'])
@login_required
def approve_expense(expense_id):
    if current_user.role not in ['finance', 'admin', 'it']:
        flash("❌ Only Finance/Admin/IT can approve.", "error")
        return redirect(url_for('login'))

    exp = Expense.query.get_or_404(expense_id)

    if exp.submitted_by == current_user.name:
        flash("You cannot approve your own submitted expense.", "error")
        return redirect(request.referrer or url_for('dashboard_finance'))

    pin = request.form.get('pin', '').strip()
    
    # Check if the entered PIN matches the current user's PIN
    if not current_user.pin or not check_password_hash(current_user.pin, pin):
        flash("Invalid PIN. Access denied.", "error")
        return redirect(request.referrer or url_for('dashboard_finance'))

    coa_map = {
        'Software Licenses & Subscriptions': 6230,
        'Hardware Maintenance & Upgrades': 6240,
        'Recruitment & Hiring Costs': 6250,
        'Employee Training & Development': 6260,
        'Logistics & Transportation': 6270,
        'Office Supplies & Utilities': 6280,
        'Customer Support Tools & Software': 6290,
        'Staff Overtime & Incentives': 5011,
        'Advertising & Promotions': 6300,
        'Event & Campaign Costs': 6310,
        'Research Materials & Equipment': 6320,
        'Prototyping & Testing Costs': 6330,
        'Others': 6399
    }

    exp.coa = coa_map.get(exp.category, 6399)
    exp.status = "Approved"
    exp.reviewed_by = current_user.name
    db.session.commit()

    flash(f"Expense #{exp.id} approved.", "success")
    return redirect(request.referrer or url_for('dashboard_finance'))


# ---- Reject expense (finance/admin) ----
@app.route('/reject_expense/<int:expense_id>', methods=['POST'])
@login_required
def reject_expense(expense_id):
    if current_user.role not in ['finance', 'admin', 'it']:
        flash("❌ Only Finance/Admin/IT can reject.", "error")
        return redirect(url_for('login'))

    exp = Expense.query.get_or_404(expense_id)

    if exp.submitted_by == current_user.name:
        flash("You cannot reject your own submitted expense.", "error")
        return redirect(request.referrer or url_for('dashboard_finance'))

    pin = request.form.get('pin', '').strip()

    # Check if the entered PIN matches the current user's PIN
    if not current_user.pin or not check_password_hash(current_user.pin, pin):
        flash("Invalid PIN. Access denied.", "error")
        return redirect(request.referrer or url_for('dashboard_finance'))

    exp.status = "Rejected"
    exp.reviewed_by = current_user.name
    db.session.commit()

    flash(f"Expense #{exp.id} rejected.", "success")
    return redirect(request.referrer or url_for('dashboard_finance'))

@app.route('/expense_action/<action>/<int:expense_id>', methods=['POST'])
@login_required
def expense_action(action, expense_id):
    # Get PIN from JSON or form
    pin = request.json.get('pin') if request.is_json else request.form.get('pin', '').strip()
    
    if not check_password_hash(current_user.pin, pin):
        return jsonify({"message": "Invalid PIN. Please try again."}), 400

    expense = Expense.query.get(expense_id)
    if not expense:
        return jsonify({"message": "Expense not found."}), 404

    coa_map = {
        'Software Licenses & Subscriptions': 6230,
        'Hardware Maintenance & Upgrades': 6240,
        'Recruitment & Hiring Costs': 6250,
        'Employee Training & Development': 6260,
        'Logistics & Transportation': 6270,
        'Office Supplies & Utilities': 6280,
        'Customer Support Tools & Software': 6290,
        'Staff Overtime & Incentives': 5011,
        'Advertising & Promotions': 6300,
        'Event & Campaign Costs': 6310,
        'Research Materials & Equipment': 6320,
        'Prototyping & Testing Costs': 6330,
        'Others': 6399
    }

    if action == 'approve':
        expense.status = 'Approved'
        expense.reviewed_by = current_user.name
        expense.coa = coa_map.get(expense.category, 6399)
    elif action == 'reject':
        expense.status = 'Rejected'
        expense.reviewed_by = current_user.name

    db.session.commit()
    return jsonify({"message": f"Expense {action}d successfully."}), 200



# ---- Manage budgets (admin/finance) ----
@app.route('/update_budget/<int:budget_id>', methods=['POST'])
@login_required
def update_budget(budget_id):
    if current_user.role not in ['admin', 'finance', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))
    budget = Budget.query.get_or_404(budget_id)
    try:
        new_alloc = float(request.form.get('allocated') or request.values.get('allocated') or 0)
        budget.allocated = new_alloc
        db.session.commit()
        flash(f"{budget.department} budget updated", "success")
    except Exception as e:
        flash("Invalid allocated amount", "error")
    # if AJAX call, ok to return simple
    return redirect(request.referrer or url_for('dashboard_admin'))

# ---- Reset password (simple) ----
@app.route('/reset_password', methods=['POST'])
@login_required
def reset_password():
    username = request.form.get('username')
    if username != current_user.name:
        flash("Username mismatch", "error")
        return redirect(request.referrer or url_for('login'))
    cur = request.form.get('current_password','')
    new = request.form.get('new_password','')
    if not check_password_hash(current_user.password, cur):
        flash("Current password incorrect", "error")
        return redirect(request.referrer or url_for('login'))
    current_user.password = generate_password_hash(new)
    db.session.commit()
    flash("Password updated", "success")
    # redirect based on role
    if current_user.role == 'head':
        return redirect(url_for('dashboard_head'))
    if current_user.role == 'finance':
        return redirect(url_for('dashboard_finance'))
    if current_user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    if current_user.role == 'it':
        return redirect(url_for('dashboard_it'))
    return redirect(url_for('login'))

# ---------- DB Init ----------
def init_db():
    with app.app_context():
        db.create_all()

        # Default budgets
        default_budgets = [
            ("Finance", 500000),
            ("HR", 120000),
            ("IT", 200000),
            ("Marketing", 150000),
            ("Operations", 180000),
            ("Customer Service", 100000),
            ("R&D", 250000),
            ("Head Department", 300000)
        ]
        for dept, amt in default_budgets:
            if not Budget.query.filter_by(department=dept).first():
                db.session.add(Budget(department=dept, allocated=amt))

        # Default users (PINs hashed)
        if not User.query.filter_by(name="admin").first():
            db.session.add_all([
                User(
                    name="admin",
                    password=generate_password_hash("admin123"),
                    role="admin",
                    last_name="Admin",
                    given_name="Super",
                    middle_name="A",
                    address="123 Admin St",
                    contact_number="09123456789",
                    birthday="1980-01-01",
                    email="admin@buzzard.com",
                    pin=generate_password_hash("6969"),
                    department=""
                ),
                User(
                    name="finance",
                    password=generate_password_hash("finance123"),
                    role="finance",
                    last_name="Finance",
                    given_name="Fin",
                    middle_name="B",
                    address="456 Finance Ave",
                    contact_number="09123456780",
                    birthday="1985-02-15",
                    email="finance@buzzard.com",
                    pin=generate_password_hash("6969"),
                    department="Finance"
                ),
                User(
                    name="head",
                    password=generate_password_hash("head123"),
                    role="head",
                    last_name="Head",
                    given_name="Dept",
                    middle_name="C",
                    address="789 Head Rd",
                    contact_number="09123456781",
                    birthday="1990-03-20",
                    email="head@buzzard.com",
                    pin=generate_password_hash("4321"),
                    department="Head Department"
                ),
                User(
                    name="itstaff",
                    password=generate_password_hash("itstaff123"),
                    role="it",
                    last_name="IT",
                    given_name="Tech",
                    middle_name="D",
                    address="321 IT Blvd",
                    contact_number="09123456782",
                    birthday="1992-04-10",
                    email="it@buzzard.com",
                    pin=generate_password_hash("6969"),
                    department="IT"
                )
            ])
        db.session.commit()
        print("DB Initialized (tables + defaults).")


# ---------- Run ----------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
