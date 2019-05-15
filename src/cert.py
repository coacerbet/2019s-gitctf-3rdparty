import re
import json
import time
from flask import Blueprint, request, session, current_app
from pgpy import PGPKey, PGPSignature
from pgpy.errors import PGPError

from src import db, util


bp = Blueprint('cert', __name__, url_prefix='/cert')


@bp.route('/upload-key', methods=['POST'])
def cb_upload_key():
    required_fields = {
            'type': 'files',
            'name': ['key'],
            }
    return util.wrapper(required_fields, upload_key)

@bp.route('/revoke-key', methods=['POST'])
def cb_revoke_key():
    required_fields = {
            'type': None,
            }
    return util.wrapper(required_fields, revoke_key)

@bp.route('/get-cert', methods=['POST'])
def cb_get_cert():
    required_fields = {
            'type': 'form',
            'name': ['is_activated', 'uid'],
            }
    return util.wrapper(required_fields, get_cert)

@bp.route('/verify-cert', methods=['POST'])
def cb_verify_cert():
    required_fields = {
            'type': 'form',
            'name': ['cert'],
            }
    return util.wrapper(required_fields, verify_cert, sess_chk=False)

def upload_key(form):
    try:
        key, err = load_pgp_key(form['key'])
        if err is not None:
            return err
            
        raw_r = revoke_key({})
        r = json.loads(raw_r)
        if r['code'] not in ['0', '111']:
            return raw_r

        uid = session['uid']

        q = 'SELECT lastname, firstname, email FROM user WHERE uid=?'
        d = [uid]
        r, err = db.query(q, d)
        if err is not None:
            return err

        assert r != []

        issued_time = get_time()
        key_str = str(key)

        cert, err = make_cert(issued_time, uid, key_str, 1, r[0]['lastname'], r[0]['firstname'], r[0]['email'])
        if err is not None:
            return err

        q = 'INSERT INTO cert VALUES (?, ?, ?, ?, ?)'
        d = [issued_time, None, uid, key_str, 1]
        r, err = db.query(q, d)
        if err is not None:
            return err

        msg = 'Uploaded and signed PGP key, {}'.format(session['firstname'])
        return util.make_result(msg, ['0'])

    except:
        msg = "Unknown error occured, {}".format(session['firstname'])
        return util.make_result(msg)

def revoke_key(form):
    try:
        err_codes = ['1']

        q = 'SELECT * FROM cert WHERE uid=? AND is_activated=1'
        d = [session['uid']]
        r, err = db.query(q, d)
        if err is not None:
            return err

        if r == []:
            err_msg = 'No activated certificate, {}'.format(session['uid'])
            err_codes.append('1')
            return util.make_result(err_msg, err_codes)

        revoked_time = get_time()
        if not validate_pgp_key_fmt(r[0]['key']):
            err_msg = 'Invalid PGP key format, {}'.format(session['uid'])
            err_codes.append('2')
            return util.make_result(err_msg, err_codes)

        q = 'UPDATE cert SET is_activated=0, revoked_time=? WHERE issued_time=? AND uid=? AND is_activated=1'
        d = [revoked_time, r[0]['issued_time'], session['uid']]
        r, err = db.query(q, d)
        if err is not None:
            return err

        msg = 'Revoked key, {}'.format(session['uid'])
        return util.make_result(msg, ['0'])

    except:
        msg = "Unknown error occured, {}".format(session['firstname'])
        return util.make_result(msg)
        
def get_cert(form):
    try:
        err_codes = ['2']

        if form['is_activated'] not in ['0', '1']:
            err_msg = "'is_activated' must be 0 or 1, {}".format(session['firstname'])
            err_codes.append('1')
            return util.make_result(err_msg, err_codes)

        if 'offset' in form:
            if not form['offset'].isdigit():
                err_msg = "'offset' must be int, {}".format(session['firstname'])
                err_codes.append('2')
                return util.make_result(err_msg, err_codes)
            else:
                offset = int(form['offset'])
                if offset < 0:
                    err_msg = "'offset' must be positive, {}".format(session['firstname'])
                    err_codes.append('3')
                    return util.make_result(err_msg, err_codes)
        else:
            offset = 0

        q = 'SELECT * FROM user WHERE uid=?'
        d = [form['uid']]
        r_users, err = db.query(q, d)
        if err is not None:
            return err

        if r_users == []:
            err_msg = "No user for the given uid, {}".format(session['firstname'])
            err_codes.append('4')
            return util.make_result(err_msg, err_codes)

        q = 'SELECT * FROM cert WHERE uid=? AND is_activated=? ORDER BY issued_time DESC LIMIT 10 OFFSET ?'
        d = [form['uid'], form['is_activated'], offset]
        r_certs, err = db.query(q, d)
        if err is not None:
            return err

        certs = []
        for r_cert in r_certs:
            cert, err = make_cert(
                    r_cert['issued_time'],
                    r_cert['uid'],
                    r_cert['key'],
                    r_cert['is_activated'],
                    r_users[0]['lastname'],
                    r_users[0]['firstname'],
                    r_users[0]['email']
                    )
            if err is not None:
                return err

            certs.append(cert)

        msg = json.dumps(certs)
        return util.make_result(msg, ['0'])

    except:
        msg = "Unknown error occured, {}".format(session['firstname'])
        return util.make_result(msg)

def verify_cert(form):
    try:
        err_codes = ['3']

        try:
            cert = json.loads(form['cert'])
            data = json.loads(cert['data'])
        except json.decoder.JSONDecodeError:
            err_msg = "Not in JSON format, {}".format(session['firstname'])
            err_codes.append('1')
            return util.make_result(err_msg, err_codes)

        missing_fields = util.get_missing_fields(get_cert_fields(), data)
        if missing_fields:
            err_msg = '{} is missing, {}'.format(missing_fields, session['firstname'])
            err_codes.append('2')
            return util.make_result(err_msg, err_codes)

        if not verify_by_ca(cert['data'], cert['sign']):
            err_msg = "Type is not acceptable, {}".format(session['firstname'])
            err_codes.append('3')
            return util.make_result(err_msg, err_codes)

        key, err = load_pgp_key(data['key'])
        if err is not None:
            return err

        q = 'SELECT * FROM cert WHERE issued_time=? AND uid=? AND key=? AND is_activated=?'
        d = [data['issued_time'], data['uid'], data['key'], data['is_activated']]
        r, err = db.query(q, d)
        if err is not None:
            return err

        assert r != []

        if data['is_activated'] == 0:
            err_msg = "Revoked cert, {}".format(session['firstname'])
            err_codes.append('4')
            return util.make_result(err_msg, err_codes)
        elif data['is_activated'] == 1:
            msg = "Valid cert, {}".format(session['firstname'])
            return util.make_result(msg, ['0'])
        else:
            assert False

    except:
        msg = "Unknown error occured, {}".format(session['firstname'])
        return util.make_result(msg)


def load_pgp_key(raw_key):
    err_codes = ['4']
    try:
        key, _ = PGPKey.from_blob(raw_key)
        return key, None
    except TypeError:
        err_msg = "Input key does not have a valid type, {}".format(session['firstname'])
        err_codes.append('1')
        return None, util.make_result(err_msg, err_codes)
    except ValueError:
        err_msg = "Input key is not a properly formed PGP block, {}".format(session['firstname'])
        err_codes.append('2')
        return None, util.make_result(err_msg, err_codes)
    except PGPError:
        err_msg = "De-armoring or parsing failed, {}".format(session['firstname'])
        err_codes.append('3')
        return None, util.make_result(err_msg, err_codes)

def sign_by_ca(data):
    ca_sec_key = current_app.config['CA_SEC_KEY']
    with ca_sec_key.unlock(current_app.config['CA_PASSPHRASE']):
        return str(ca_sec_key.sign(data))

def verify_by_ca(data, raw_sign):
    ca_pub_key = current_app.config['CA_PUB_KEY']
    sign = PGPSignature.from_blob(raw_sign)
    return ca_pub_key.verify(data, sign)

def make_cert(issued_time, uid, key, is_activated, lastname, firstname, email):
    err_codes = ['5']

    cert_data = {
            'is_activated': is_activated,
            'issued_time': issued_time,
            'uid': uid,
            'lastname': lastname,
            'firstname': firstname,
            'email': email,
            'key': key,
            }

    assert len(cert_data.keys()) == len(get_cert_fields())
    assert set(cert_data.keys()) == set(get_cert_fields())

    cert_data = json.dumps(cert_data)

    try:
        cert_sign = sign_by_ca(cert_data)
    except PGPError as e:
        err_codes.append('1')
        return None, util.make_result(str(e), err_codes)
    except ZeroDivisionError as e:
        err_codes.append('2')
        return None, util.make_result(str(e), err_codes)

    cert = {
            'data': cert_data,
            'sign': cert_sign,
            }
    return cert, None

def get_time():
    return str(time.time()).ljust(18, '0')[:15]

def validate_pgp_key_fmt(raw_key):
    raw_key = raw_key.replace('\n', '')

    header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    space = 'A-Za-z0-9/+=:. '
    footer = '-----END PGP PUBLIC KEY BLOCK-----'

    m = re.match('^{}[{}]+{}$'.format(header, space, footer), raw_key)
    return m is not None

def get_cert_fields():
    return [
            'is_activated',
            'issued_time',
            'uid',
            'lastname',
            'firstname',
            'email',
            'key',
            ]
