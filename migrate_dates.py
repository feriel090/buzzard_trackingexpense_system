from app import db, Expense
from datetime import datetime

with db.app.app_context():
    expenses = Expense.query.all()
    for e in expenses:
        if e.date:
            try:
                # Assuming current format is 'YYYY-MM-DD'
                e.date = datetime.strptime(e.date, "%Y-%m-%d").date()
            except ValueError:
                print(f"Skipping invalid date format for expense ID {e.id}: {e.date}")
    db.session.commit()
    print("All expense.date fields converted to proper DATE format.")
