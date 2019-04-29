import os
from flask import Flask
from pgpy import PGPKey

from src import db, user, cert

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    ca_pub_key, _ = PGPKey.from_file(os.path.join(app.root_path, '..', 'key', 'pub.asc'))
    ca_sec_key, _ = PGPKey.from_file(os.path.join(app.root_path, '..', 'key', 'sec.asc'))
    
    assert ca_sec_key.is_protected
    assert ca_sec_key.is_unlocked is False

    app.config.from_mapping(
        SECRET_KEY='sooO0O0Oo0O0oo0OoOOo-s3cur3',
        CA_PUB_KEY=ca_pub_key,
        CA_SEC_KEY=ca_sec_key,
        CA_PASSPHRASE='is521xyz!',
        DB=os.path.join(app.instance_path, 'ca.db'),
    )

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.register_blueprint(user.bp)
    app.register_blueprint(cert.bp)

    app.teardown_appcontext(db.close_db)

    if not os.path.isfile(app.config['DB']):
        with app.app_context():
            db.init_db()

    return app
