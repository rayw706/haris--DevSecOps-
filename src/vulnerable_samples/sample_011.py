import sqlite3

def get_by_id(i):
    db = sqlite3.connect('db')
    cur = db.cursor()
    cur.execute('SELECT * FROM t WHERE id = ?', (i,))
    return cur.fetchall()
