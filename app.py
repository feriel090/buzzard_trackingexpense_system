from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "buzzard_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///buzzard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/receipts'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ===== Database Models =====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(50))  # admin, finance, head, it
    department = db.Column(db.String(50), nullable=True)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    category = db.Column(db.String(50))
    amount = db.Column(db.Float)
    date = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Pending")
    submitted_by = db.Column(db.String(150))
    department = db.Column(db.String(50))
    purpose = db.Column(db.Text)
    receipt = db.Column(db.String(150), nullable=True)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100), unique=True)
    allocated = db.Column(db.Float)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===== Routes =====
@app.route('/')
def home():
    return redirect(url_for('login'))

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
            flash(f"Welcome {user.name}!", "success")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'finance':
                return redirect(url_for('dashboard_finance'))
            elif user.role == 'head':
                return redirect(url_for('dashboard_dept'))
            elif user.role == 'it':
                return redirect(url_for('dashboard_it'))
            else:
                flash("Unknown role. Access denied.", "error")
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

# ===== IT Dashboard =====
@app.route('/it')
@login_required
def dashboard_it():
    if current_user.role not in ['it', 'admin']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('dashboard_it.html', users=users)

# ===== Admin Dashboard =====
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    users = User.query.all()
    expenses = Expense.query.order_by(Expense.id.desc()).all()
    head_expenses = Expense.query.filter_by(department="Head Department").order_by(Expense.id.desc()).all()

    reports = db.session.query(
        Expense.department,
        func.sum(Expense.amount).label("total"),
        func.count(Expense.id).label("count")
    ).filter(Expense.status=="Approved").group_by(Expense.department).all()

    budgets = []
    all_budgets = Budget.query.all()
    for b in all_budgets:
        used = db.session.query(func.sum(Expense.amount)).filter(
            Expense.department==b.department,
            Expense.status=="Approved"
        ).scalar() or 0
        budgets.append({
            "department": b.department,
            "allocated": b.allocated,
            "used": used,
            "remaining": b.allocated - used
        })

    category_data = db.session.query(
        Expense.category,
        func.sum(Expense.amount)
    ).filter(Expense.status=="Approved").group_by(Expense.category).all()
    category_labels = [c[0] for c in category_data]
    category_values = [c[1] for c in category_data]

    dept_labels = [r.department for r in reports]
    dept_values = [r.total for r in reports]

    weekly_data = db.session.query(
        func.strftime("%W", Expense.date),
        func.sum(Expense.amount)
    ).filter(Expense.status=="Approved").group_by(func.strftime("%W", Expense.date)).all()
    weekly_labels = [w[0] for w in weekly_data]
    weekly_values = [w[1] for w in weekly_data]

    monthly_data = db.session.query(
        func.strftime("%m", Expense.date),
        func.sum(Expense.amount)
    ).filter(Expense.status=="Approved").group_by(func.strftime("%m", Expense.date)).all()
    monthly_labels = [m[0] for m in monthly_data]
    monthly_values = [m[1] for m in monthly_data]

    return render_template('dashboard_admin.html',
                           users=users,
                           expenses=expenses,
                           reports=reports,
                           budgets=budgets,
                           head_expenses=head_expenses,
                           category_labels=category_labels,
                           category_values=category_values,
                           dept_labels=dept_labels,
                           dept_values=dept_values,
                           weekly_labels=weekly_labels,
                           weekly_values=weekly_values,
                           monthly_labels=monthly_labels,
                           monthly_values=monthly_values)

# ===== Finance Dashboard =====
@app.route('/finance')
@login_required
def dashboard_finance():
    if current_user.role not in ['finance', 'admin']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    approved_expenses = Expense.query.filter_by(submitted_by=current_user.name).filter(
        Expense.status.in_(["Pending","Approved"])
    ).all()

    pending_expenses = Expense.query.filter(Expense.department!="Finance",
                                            Expense.status=="Pending").all()

    head_expenses = Expense.query.filter_by(department="Head Department").order_by(Expense.id.desc()).all()

    reports = db.session.query(
        Expense.department,
        func.sum(Expense.amount).label("total"),
        func.count(Expense.id).label("count")
    ).filter(Expense.status=="Approved").group_by(Expense.department).all()

    budgets = []
    all_budgets = Budget.query.all()
    for b in all_budgets:
        used = db.session.query(func.sum(Expense.amount)).filter(
            Expense.department==b.department,
            Expense.status=="Approved"
        ).scalar() or 0
        budgets.append({
            "department": b.department,
            "allocated": b.allocated,
            "used": used,
            "remaining": b.allocated - used
        })

    category_data = db.session.query(
        Expense.category,
        func.sum(Expense.amount)
    ).filter(Expense.status=="Approved").group_by(Expense.category).all()
    category_labels = [c[0] for c in category_data]
    category_values = [c[1] for c in category_data]

    dept_labels = [r.department for r in reports]
    dept_values = [r.total for r in reports]

    weekly_data = db.session.query(
        func.strftime("%W", Expense.date),
        func.sum(Expense.amount)
    ).filter(Expense.status=="Approved").group_by(func.strftime("%W", Expense.date)).all()
    weekly_labels = [w[0] for w in weekly_data]
    weekly_values = [w[1] for w in weekly_data]

    monthly_data = db.session.query(
        func.strftime("%m", Expense.date),
        func.sum(Expense.amount)
    ).filter(Expense.status=="Approved").group_by(func.strftime("%m", Expense.date)).all()
    monthly_labels = [m[0] for m in monthly_data]
    monthly_values = [m[1] for m in monthly_data]

    return render_template('dashboard_finance.html',
                           approved_expenses=approved_expenses,
                           pending_expenses=pending_expenses,
                           reports=reports,
                           budgets=budgets,
                           head_expenses=head_expenses,
                           category_labels=category_labels,
                           category_values=category_values,
                           dept_labels=dept_labels,
                           dept_values=dept_values,
                           weekly_labels=weekly_labels,
                           weekly_values=weekly_values,
                           monthly_labels=monthly_labels,
                           monthly_values=monthly_values)

# ===== Head Dashboard =====
@app.route('/head')
@login_required
def dashboard_dept():
    if current_user.role != 'head':
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    expenses = Expense.query.filter_by(submitted_by=current_user.name).order_by(Expense.id.desc()).all()

    categories = [
        "Software Licenses & Subscriptions",
        "Hardware Maintenance & Upgrades",
        "Recruitment & Hiring Costs",
        "Employee Training & Development",
        "Logistics & Transportation",
        "Office Supplies & Utilities",
        "Customer Support Tools & Software",
        "Staff Overtime & Incentives",
        "Advertising & Promotions",
        "Event & Campaign Costs",
        "Research Materials & Equipment",
        "Prototyping & Testing Costs",
        "Others"
    ]

    # Optional: aggregate data for charts
    category_data = db.session.query(
        Expense.category,
        func.sum(Expense.amount)
    ).filter(
        Expense.submitted_by == current_user.name,
        Expense.status.in_(["Pending", "Approved", "Rejected"])
    ).group_by(Expense.category).all()
    category_labels = [c[0] for c in category_data]
    category_values = [float(c[1]) for c in category_data]

    weekly_data = db.session.query(
        func.strftime('%W', Expense.date),
        func.sum(Expense.amount)
    ).filter(
        Expense.submitted_by == current_user.name,
        Expense.status.in_(["Pending", "Approved", "Rejected"])
    ).group_by(func.strftime('%W', Expense.date)).all()
    weekly_labels = [f"Week {w[0]}" for w in weekly_data]
    weekly_values = [float(w[1]) for w in weekly_data]

    monthly_data = db.session.query(
        func.strftime('%m', Expense.date),
        func.sum(Expense.amount)
    ).filter(
        Expense.submitted_by == current_user.name,
        Expense.status.in_(["Pending", "Approved", "Rejected"])
    ).group_by(func.strftime('%m', Expense.date)).all()
    monthly_labels = [f"Month {m[0]}" for m in monthly_data]
    monthly_values = [float(m[1]) for m in monthly_data]

    return render_template(
        'dashboard_dept.html',
        expenses=expenses,
        categories=categories,
        category_labels=category_labels,
        category_values=category_values,
        weekly_labels=weekly_labels,
        weekly_values=weekly_values,
        monthly_labels=monthly_labels,
        monthly_values=monthly_values
    )


# ===== Submit New Expense (Finance & Head Only) =====
@app.route('/new_expense', methods=['GET','POST'])
@login_required
def new_expense():
    if current_user.role not in ['finance', 'head']:
        flash("❌ Only Finance or Head can submit expenses.", "error")
        return redirect(url_for('login'))

    # Shared category list
    categories = [
        "Software Licenses & Subscriptions",
        "Hardware Maintenance & Upgrades",
        "Recruitment & Hiring Costs",
        "Employee Training & Development",
        "Logistics & Transportation",
        "Office Supplies & Utilities",
        "Customer Support Tools & Software",
        "Staff Overtime & Incentives",
        "Advertising & Promotions",
        "Event & Campaign Costs",
        "Research Materials & Equipment",
        "Prototyping & Testing Costs",
        "Others"
    ]

    if request.method == 'POST':
        title = request.form['title']
        category = request.form.get('category', 'Others')
        amount = float(request.form['amount'])
        date = request.form['date']
        purpose = request.form.get('purpose', '')
        receipt_file = request.files.get('receipt')
        filename = None

        if receipt_file and receipt_file.filename != "":
            filename = secure_filename(receipt_file.filename)
            receipt_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Each user’s department is automatically linked
        department = current_user.department or "Finance"

        new_exp = Expense(
            title=title,
            category=category,
            amount=amount,
            date=date,
            submitted_by=current_user.name,
            department=department,
            purpose=purpose,
            receipt=filename
        )
        db.session.add(new_exp)
        db.session.commit()
        flash("✅ Expense submitted successfully!", "success")

        # Redirect based on role
        if current_user.role == 'head':
            return redirect(url_for('dashboard_dept'))
        else:
            return redirect(url_for('dashboard_finance'))

    return render_template('new_expense.html', categories=categories)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    
    # Predefined categories
    categories = [
        "Software Licenses & Subscriptions",
        "Hardware Maintenance & Upgrades",
        "Recruitment & Hiring Costs",
        "Employee Training & Development",
        "Logistics & Transportation",
        "Office Supplies & Utilities",
        "Customer Support Tools & Software",
        "Staff Overtime & Incentives",
        "Advertising & Promotions",
        "Event & Campaign Costs",
        "Research Materials & Equipment",
        "Prototyping & Testing Costs",
        "Others"
    ]
    
    if request.method == 'POST':
        # Update the expense
        expense.title = request.form['title']
        expense.category = request.form['category']
        expense.amount = request.form['amount']
        expense.date = request.form['date']
        expense.purpose = request.form.get('purpose')
        db.session.commit()
        flash('Expense updated successfully!', 'success')
        return redirect(url_for('dashboard_dept'))

    return render_template('edit_expense.html', expense=expense, categories=categories)




# ===== Approve / Reject Expense =====
@app.route('/approve_expense/<int:expense_id>', methods=['POST'])
@login_required
def approve_expense(expense_id):
    if current_user.role not in ['finance', 'admin']:
        flash("❌ Access Denied. Only Finance or Admin can approve expenses.", "error")
        return redirect(url_for('login'))

    pin = request.form.get('pin')
    if pin != "6969":
        flash("Invalid PIN. Access denied.", "error")
        return redirect(request.referrer or url_for('dashboard_finance'))

    exp = Expense.query.get_or_404(expense_id)
    exp.status = "Approved"
    db.session.commit()
    flash(f"Expense #{exp.id} approved.", "success")
    return redirect(request.referrer or url_for('dashboard_finance'))

@app.route('/reject_expense/<int:expense_id>', methods=['POST'])
@login_required
def reject_expense(expense_id):
    if current_user.role not in ['finance', 'admin']:
        flash("❌ Access Denied. Only Finance or Admin can reject expenses.", "error")
        return redirect(url_for('login'))

    pin = request.form.get('pin')
    if pin != "6969":
        flash("Invalid PIN. Access denied.", "error")
        return redirect(request.referrer or url_for('dashboard_finance'))

    exp = Expense.query.get_or_404(expense_id)
    exp.status = "Rejected"
    db.session.commit()
    flash(f"Expense #{exp.id} rejected.", "success")
    return redirect(request.referrer or url_for('dashboard_finance'))

# ===== User Management =====
@app.route('/create_user', methods=['GET','POST'])
@login_required
def create_user():
    if current_user.role not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        department = None
        if "head" in role:
            department = role.split("_")[1].upper()
            role = "head"
        elif "finance" in role:
            role = "finance"
        user = User(name=name, password=password, role=role, department=department)
        db.session.add(user)
        db.session.commit()
        flash(f"User {name} created successfully!", "success")
        return redirect(url_for('dashboard_it') if current_user.role == 'it' else url_for('admin_dashboard'))

    return render_template('create_user.html')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    pin = request.form.get('pin')
    if pin != "6969":
        flash("Invalid PIN. Cannot delete user.", "error")
        return redirect(request.referrer or url_for('dashboard_it'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(request.referrer or (url_for('dashboard_it') if current_user.role == 'it' else url_for('admin_dashboard')))

@app.route('/edit_user/<int:user_id>', methods=['GET'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    return render_template('edit_user.html', user=user)

@app.route('/update_user/<int:id>', methods=['POST'])
@login_required
def update_user(id):
    if current_user.role not in ['admin', 'it']:
        flash("Access Denied", "error")
        return redirect(url_for('login'))

    user = User.query.get_or_404(id)
    user.name = request.form.get('username')
    user.role = request.form.get('role')
    user.department = request.form.get('department')
    new_password = request.form.get('password')
    if new_password and new_password.strip():
        user.password = generate_password_hash(new_password.strip())
    db.session.commit()
    flash("User updated successfully!", "success")
    return redirect(url_for('dashboard_it') if current_user.role == 'it' else url_for('admin_dashboard'))

# ===== Reset Password =====
@app.route('/reset_password', methods=['POST'])
@login_required
def reset_password():
    username = request.form['username'].strip()
    current_pass = request.form['current_password'].strip()
    new_pass = request.form['new_password'].strip()

    user = User.query.filter_by(name=username).first()
    if not user:
        flash("Username not found.", "error")
        return redirect(url_for('dashboard_it') if current_user.role == 'it' else url_for('dashboard_dept'))

    if not check_password_hash(user.password, current_pass):
        flash("Current password is incorrect.", "error")
        return redirect(url_for('dashboard_it') if current_user.role == 'it' else url_for('dashboard_dept'))

    user.password = generate_password_hash(new_pass)
    db.session.commit()
    flash("Password successfully updated!", "success")
    return redirect(url_for('dashboard_it') if current_user.role == 'it' else url_for('dashboard_dept'))

# ===== Initialize DB =====
def init_db():
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(name="admin").first():
            admin = User(name="admin", password=generate_password_hash("admin123"), role="admin")
            finance = User(name="finance", password=generate_password_hash("finance123"), role="finance", department="Finance")
            head = User(name="head", password=generate_password_hash("head123"), role="head", department="Head Department")
            itstaff = User(name="itstaff", password=generate_password_hash("itstaff123"), role="it", department="IT")
            db.session.add_all([admin, finance, head, itstaff])
            db.session.commit()

        default_budgets = [
            Budget(department="Finance", allocated=500000),
            Budget(department="HR", allocated=120000),
            Budget(department="IT", allocated=200000),
            Budget(department="Marketing", allocated=150000),
            Budget(department="Operations", allocated=180000),
            Budget(department="Customer Service", allocated=100000),
            Budget(department="R&D", allocated=250000),
            Budget(department="Head Department", allocated=300000)
        ]
        for b in default_budgets:
            if not Budget.query.filter_by(department=b.department).first():
                db.session.add(b)
        db.session.commit()
        print("DB Initialized with default users and budgets.")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False)
