import sqlite3

def q(a):
    cur = sqlite3.connect('d').cursor()
    cur.execute('SELECT * FROM t WHERE x=' + a)
