import sqlite3
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "dev-secret-123"

@app.post("/login")
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = conn.execute(query).fetchone()
    return "Welcome" if user else ("Invalid credentials", 401)