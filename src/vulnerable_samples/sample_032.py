import sqlite3

def bad_query(name):
    q = 'SELECT * FROM users WHERE name = "%s"' % name
    conn = sqlite3.connect('db')
    conn.execute(q)
