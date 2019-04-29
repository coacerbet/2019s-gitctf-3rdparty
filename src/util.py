import json
from flask import escape, request, session


# [Result Code]
# Success       :   '0'
# Unknown Error :   '1'
# Known Error   : '1XY' (X: Function ID, Y: Section ID in Function)
def make_result(msg, codes=[]):
    if codes != ['0']:
        codes.insert(0, '1')

    data = {'code': ''.join(codes), 'msg': escape(msg)}
    return json.dumps(data)

def get_missing_fields(names, form):
    return list(filter(lambda e: e not in form, names))

def wrapper(required_fields, func, sess_chk=True):
    err_codes = ['9']

    if sess_chk:
        if not 'uid' in session:
            err_msg = "Login first."
            err_codes.append('1')
            return make_result(err_msg, err_codes)

    field_type = required_fields['type']
    assert field_type in [None, 'form', 'files']
    if field_type:
        names = required_fields['name']
        data = getattr(request, field_type)

        missing_fields = get_missing_fields(names, data)
        if missing_fields:
            err_msg = '{} is missing.'.format(missing_fields)
            err_codes.append('2')
            return make_result(err_msg, err_codes)
        else:
            if field_type == 'files':
                files = {}
                for k in data:
                    files[k] = data[k].read().decode()
                data = files

            return func(data)
    else:
        return func([])
