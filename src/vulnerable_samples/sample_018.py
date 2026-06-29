def concat_sql(name):
    q = f"SELECT * FROM users WHERE name = '{name}'"
    return q
