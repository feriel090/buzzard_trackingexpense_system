# Buzzard Expense Tracking System (Starter)

This is a ready-to-run Flask starter project for Buzzard's Expense Tracking System (department-head-only).

Features:
- Department heads submit expenses on behalf of their department
- Finance approves/rejects expenses
- Admin manages users
- Department budgets (set by admin) and enforcement
- CSRF protection with Flask-WTF
- Bootstrap 5 UI (responsive)
- Receipt uploads (jpg/png/pdf)
- SQLite database (buzzard.db)


## Run locally (quick)
1. Create venv and activate (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Open: http://127.0.0.1:5000

## Access from other devices / internet
- LAN: run `python app.py --host=0.0.0.0` or `flask run --host=0.0.0.0`. Then use `http://YOUR_LOCAL_IP:5000`.
- Internet (temporary): use ngrok: `ngrok http 5000` then use the provided ngrok URL.
- For production deploy to Render/Railway/Heroku/VM and enable HTTPS and proper secrets.


Demo users (seeded):
- admin / adminpass
- finance / financepass
- hr_head / hrpass (department HR)
- marketing_head / markpass (department Marketing)
- it_head / itpass (department IT)
