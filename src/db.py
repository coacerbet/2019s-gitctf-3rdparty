import sqlite3
from flask import current_app, g

from src import util


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DB'])
        g.db.row_factory = sqlite3.Row

    return g.db

def close_db(exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        sql = f.read().decode('utf-8')
        db.executescript(sql)

def query(query, data):
    err_codes = ['a']

    c = get_db()

    assert type(query) is str
    assert type(data) is list
    assert query.count('?') == len(data)

    try:
        r = c.execute(query, data).fetchall()
        c.commit()

        return r, None

    except sqlite3.OperationalError as e:
        err_codes.append('1')
        return None, util.make_result(str(e), err_codes)
