import io
from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import User, Expense
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
from flask import session, redirect, url_for
from flask import get_flashed_messages
from flask import Response
import csv
from io import StringIO
from datetime import datetime

main = Blueprint('main', __name__)

from . import login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def index():
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))  # Redirect if already logged in

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # ✅ Check if email or username already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please login or use another.', 'danger')
            return redirect(url_for('main.register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('main.register'))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_pw, income=0)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))  # Redirect if already logged in

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')


@main.route('/dashboard')
@login_required
def dashboard():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    total_income = sum(e.amount for e in expenses if e.type == 'Income')
    total_expense = sum(e.amount for e in expenses if e.type == 'Expense')
    
    

    # Combine categories for both Income and Expense
    categories = {}
    for e in expenses:
        key = f"{e.category} ({e.type})"  # Label example: Salary (Income), Food (Expense)
        categories[key] = categories.get(key, 0) + e.amount

    labels = list(categories.keys())
    values = list(categories.values())
    
    chart_data = [{
        "type": e.type,
        "category": e.category,
        "amount": e.amount
    } for e in expenses]
    types = [e.type for e in expenses]  # Or however you’re generating labels/values


    return render_template('dashboard.html',
                           income=total_income,
                           total_expense=total_expense,
                           labels=labels,
                           values=values,
                           chart_data=chart_data,
                           types=types,
                           expenses=expenses,
                           username=current_user.username)





@main.route('/calendar')
@login_required
def calendar_view():
    user_id = current_user.id
    expenses = Expense.query.filter_by(user_id=user_id).all()

    events = []
    for e in expenses:
        events.append({
            'title': f"{e.category} - ₹{e.amount}",
            'start': e.date.strftime('%Y-%m-%d'),
            'color': '#28a745' if e.type == 'Income' else '#dc3545'
        })

    print(events)

    return render_template('calendar.html', events=events)






@main.route('/export', methods=['GET'])
@login_required
def export_data():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Type', 'Category', 'Amount', 'Description', 'Date'])

    user_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    for e in user_expenses:
        cw.writerow([e.type, e.category, e.amount, e.description, e.date.strftime('%Y-%m-%d')])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = "attachment; filename=transactions.csv"
    return output



@main.route('/import', methods=['POST'])
@login_required
def import_data():
    file = request.files['file']
    if not file or not file.filename.endswith('.csv'):
        flash('Please upload a valid CSV file.', 'danger')
        return redirect(url_for('main.expenses'))

    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_input = csv.DictReader(stream)

    for row in csv_input:
        try:
            # Skip blank rows
            if not any(row.values()):
                continue

            new_expense = Expense(
                type=row['Type'],
                category=row['Category'],
                amount=float(row['Amount']),
                description=row['Description'],
                date=datetime.strptime(row['Date'], "%d-%m-%Y"),
                user_id=current_user.id
            )
            db.session.add(new_expense)
        except Exception as e:
            print(f"Error in row: {row} - {e}")

    db.session.commit()
    flash('Data imported successfully!', 'success')
    return redirect(url_for('main.expenses'))




# Edit Expense
@main.route('/edit/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('main.expenses'))

    if request.method == 'POST':
        expense.type = request.form['type']
        expense.category = request.form['category']
        expense.amount = request.form['amount']
        expense.description = request.form['description']
        db.session.commit()
        flash('Expense updated successfully!', 'success')
        return redirect(url_for('main.expenses'))

    return render_template('edit_expense.html', expense=expense)


# Delete Expense
@main.route('/delete/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('main.expenses'))

    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully!', 'success')
    return redirect(url_for('main.expenses'))



@main.route('/monthly-breakdown')
@login_required
def monthly_breakdown():
    from sqlalchemy import extract, func
    from collections import defaultdict
    import calendar

    # Step 1: Query to fetch monthly grouped data
    monthly_data = db.session.query(
        extract('year', Expense.date).label('year'),
        extract('month', Expense.date).label('month'),
        Expense.type,
        func.sum(Expense.amount).label('total')
    ).filter_by(user_id=current_user.id).group_by('year', 'month', Expense.type).order_by('year', 'month').all()

    # Step 2: Transform data for the chart
    monthly_summary = defaultdict(lambda: {'Income': 0, 'Expense': 0})
    for entry in monthly_data:
        label = f"{calendar.month_abbr[int(entry.month)]} {int(entry.year)}"
        monthly_summary[label][entry.type] = entry.total

    labels = list(monthly_summary.keys())
    income_data = [monthly_summary[month]['Income'] for month in labels]
    expense_data = [monthly_summary[month]['Expense'] for month in labels]

    # Step 3: Render the template with the chart data
    return render_template('monthly.html',
                           labels=labels,
                           income_data=income_data,
                           expense_data=expense_data)



@main.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    current = session.get('theme', 'light-mode')
    session['theme'] = 'dark-mode' if current == 'light-mode' else 'light-mode'
    return redirect(request.referrer or url_for('main.dashboard'))



@main.route('/expenses', methods=['GET', 'POST'])
@login_required
def expenses():
    if request.method == 'POST':
        # e = Expense(
        #     type=request.form['type'],
        #     category=request.form['category'],
        #     amount=request.form['amount'],
        #     description=request.form['description'],
        #     user_id=current_user.id
        # )
        e = Expense(
            type=request.form['type'],  # Income or Expense
            category=request.form['category'],
            amount=request.form['amount'],
            description=request.form['description'],
            user_id=current_user.id
            )

        db.session.add(e)
        db.session.commit()
    all_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('expenses.html', expenses=all_expenses)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
