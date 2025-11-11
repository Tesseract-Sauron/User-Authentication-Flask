import sqlite3
from werkzeug.security import generate_password_hash

con = sqlite3.connect("LoginData.db")
cur = con.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS USERS(
    first_name TEXT NOT NULL,
    last_name  TEXT NOT NULL,
    email      TEXT PRIMARY KEY,
    password   TEXT NOT NULL,
    mobile     TEXT,
    address    TEXT
)
""")

# seed if not present
if not cur.execute("SELECT 1 FROM USERS WHERE email=?", ("tester@gmail.com",)).fetchone():
    cur.execute("""
    INSERT INTO USERS(first_name,last_name,email,password,mobile,address)
    VALUES (?,?,?,?,?,?)
    """, ("Tester", "User", "tester@gmail.com",
          generate_password_hash("Tester@123"),
          "9999999999",
          "Sample Address"))
    print("Seeded tester user: tester@gmail.com / Tester@123")

con.commit()
con.close()
print("DB ready.")
