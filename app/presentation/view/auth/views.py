# -*- coding: utf-8 -*-

from flask import redirect, render_template, url_for, request
from flask_login import login_required, login_user, logout_user
from sqlalchemy import func

from app import log, db, flask_app
from . import auth
from .forms import LoginForm
from app.data.models import User
from app.presentation.layout import utils
import datetime, json

@auth.route('/', methods=['POST', 'GET'])
def login():
    form = LoginForm(request.form)
    if form.validate() and request.method == 'POST':
        user = User.query.filter_by(username=func.binary(form.username.data)).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            log.info(u'user {} logged in'.format(user.username))
            user.last_login = datetime.datetime.now()
            try:
                db.session.commit()
            except Exception as e:
                log.error(u'Could not save timestamp: {}'.format(e))
                utils.flash_plus(u'Fout in database', e)
                return redirect(url_for('auth.login'))
            # Ok, continue
            return redirect(url_for('registration.show'))
        else:
            utils.flash_plus(u'Ongeldige gebruikersnaam of paswoord')
            log.error(u'Invalid username/password')
    return render_template('auth/login.html', form=form, title='Login')


@auth.route('/logout')
@login_required
def logout():
    log.info(u'User logged out')
    logout_user()
    return redirect(url_for('auth.login'))


SMARTSCHOOL_ALLOWED_BASE_ROLES = [
    'Andere',
    'Leerkracht',
    'Directie'
]


@auth.route('/ss', methods=['POST', 'GET'])
def login_ss():
    if 'version' in request.args:
        profile = json.loads(request.args['profile'])

        if not 'username' in profile:  # not good
            log.error(f'Smartschool geeft een foutcode terug: {profile["error"]}')
            return redirect(url_for('auth.login'))

        if profile['basisrol'] in SMARTSCHOOL_ALLOWED_BASE_ROLES:
            # Students are NOT allowed to log in
            user = User.query.filter_by(username=func.binary(profile['username']), user_type=User.USER_TYPE.OAUTH).first()
            profile['last_login'] = datetime.datetime.now()
            if user:
                profile['first_name'] = profile['name']
                profile['last_name'] = profile['surname']
                user.email = profile['email']
                db.session.commit()
            else:
                profile['first_name'] = profile['name']
                profile['last_name'] = profile['surname']
                profile['user_type'] = User.USER_TYPE.OAUTH
                profile['level'] = 1
                db.session.add(user)
            login_user(user)
            log.info(u'OAUTH user {} logged in'.format(user.username))
            if not user:
                log.error('Could not save user')
                return redirect(url_for('auth.login'))
            # Ok, continue
            return render_template('base.html', default_view=True)
    else:
        redirect_uri = f'{flask_app.config["SMARTSCHOOL_OUATH_REDIRECT_URI"]}/ss'
        return redirect(f'{flask_app.config["SMARTSCHOOL_OAUTH_SERVER"]}?app_uri={redirect_uri}')
