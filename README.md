# SafeSphere – Anti Ragging Protection Portal

SafeSphere is a Flask + SQLite web portal for RBVRR Womens College to manage anti-ragging complaints.

Quick start (Windows PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 in your browser.

Default seeded account (principal):
- username: `principal`
- password: `ChangeMe123!` (change after first login)

Notes:
- Principal must add teachers. Teachers create student accounts via `signup` route.
- Student accounts are limited to 80 in the DB.
- Uploaded files saved in `static/uploads/`.
