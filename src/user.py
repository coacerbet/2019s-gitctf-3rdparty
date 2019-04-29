import re
from hashlib import sha1
from flask import Blueprint, request, session

from src import db, util


bp = Blueprint('user', __name__, url_prefix='/user')


@bp.route('/register', methods=['POST'])
def cb_register():
    required_fields = {
            'type': 'form',
            'name': ['uid', 'lastname', 'firstname', 'email', 'passwd'],
            }
    return util.wrapper(required_fields, register, sess_chk=False)

@bp.route('/login', methods=['POST'])
def cb_login():
    required_fields = {
            'type': 'form',
            'name': ['uid', 'passwd'],
            }
    return util.wrapper(required_fields, login, sess_chk=False)

@bp.route('/logout', methods=['POST'])
def cb_logout():
    session.clear()

    msg = 'Logout'
    return util.make_result(msg, ['0'])

@bp.route('/change-info', methods=['POST'])
def cb_change_info():
    required_fields = {
            'type': 'form',
            'name': ['k', 'v'],
            }
    return util.wrapper(required_fields, change_info)


def register(form):
    err_codes = ['6']

    if not is_valid_email(form['email']):
        err_msg = "The given email has a bad format."
        err_codes.append('1')
        return util.make_result(err_msg, err_codes)

    q = 'SELECT uid FROM user WHERE uid=?'
    d = [form['uid']]
    r, err = db.query(q, d)
    if err is not None:
        return err

    if r != []:
        err_msg = 'uid "{}" is already taken.'.format(form['uid'])
        err_codes.append('2')
        return util.make_result(err_msg, err_codes)

    q = 'INSERT INTO user VALUES (?, ?, ?, ?, ?)'
    d = [form['uid'], form['lastname'], form['firstname'], form['email'], hash_pw(form['passwd'])]
    r, err = db.query(q, d)
    if err is not None:
        return err

    msg = 'Registered as {}'.format(form['uid'])
    return util.make_result(msg, ['0'])

def login(form):
    err_codes = ['7']
    
    q = 'SELECT * FROM user WHERE uid=? AND passwd=?'
    d = [form['uid'], hash_pw(form['passwd'])]
    r, err = db.query(q, d)
    if err is not None:
        return err

    if r == []:
        err_msg = 'uid or passwd is wrong'
        err_codes.append('1')
        return util.make_result(err_msg, err_codes)

    for k in r[0].keys():
        if k != 'passwd':
            session[k] = r[0][k]

    msg = 'Logined as {}'.format(session['uid'])
    return util.make_result(msg, ['0'])

def change_info(form):
    try:
        err = validate_change_info_form(form)
        if err is not None:
            return err
        
        v = hash_pw(form['v']) if form['k'] == 'passwd' else form['v']

        q = 'UPDATE user SET {}=? WHERE uid=?'.format(form['k'])
        d = [v, session['uid']]
        r, err = db.query(q, d)
        if err is not None:
            return err

        msg = 'Changed {} as {}, {}'.format(form['k'], form['v'], session['firstname'])
        return util.make_result(msg, ['0'])

    except:
        msg = "Unknown error occured, {}".format(session['firstname'])
        return util.make_result(msg)

def validate_change_info_form(form):
    err_codes = ['8']
    CHANGEABLE_COLUMNS = ['lastname', 'firstname', 'email', 'passwd']

    if not form['k'] in CHANGEABLE_COLUMNS:
        err_msg = 'You can only change {}, not {}'.format(CHANGEABLE_COLUMNS, form['k'])
        err_codes.append('1')
        return util.make_result(err_msg, err_codes)

    if form['k'] == 'email' and not is_valid_email(form['v']):
        err_msg = "The given email has a bad format."
        err_codes.append('2')
        return util.make_result(err_msg, err_codes)

def hash_pw(passwd):
    return sha1(passwd.encode('utf-8')).hexdigest()

def is_valid_email(email):
    email_regexp = '^[a-z0-9.]+@[a-z0-9]+(.[a-z]+)+$'
    return re.match(email_regexp, email) is not None
