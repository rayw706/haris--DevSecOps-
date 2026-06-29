import sqlite3

def get_user(name):
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    return cur.fetchall()
