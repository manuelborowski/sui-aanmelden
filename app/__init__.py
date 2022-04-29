from flask import Flask, render_template, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from flask_jsglue import JSGlue
from werkzeug.routing import IntegerConverter as OrigIntegerConvertor
import logging.handlers, os, sys
from functools import wraps
from flask_socketio import SocketIO
from flask_apscheduler import APScheduler
from flask_mail import Mail


flask_app = Flask(__name__, instance_relative_config=True, template_folder='presentation/templates/')

# Configuration files...
from config import app_config
config_name = os.getenv('FLASK_CONFIG')
config_name = config_name if config_name else 'production'
flask_app.config.from_object(app_config[config_name])
flask_app.config.from_pyfile('config.py')

# V0.1: copy from redeem-voucher V0.21
# V0.2: made generic adaptations
# V0.3: update systemfiles
# V0.4: make more generic
# V0.5: send all invite emails button did not work
# V0.6: reworked the reservations-list
# V0.7: small bugfix
# V0.8: added miscellaneous fields
# V0.9: small bugfix, default JSON value should be {}
# V0.10: enable search in misc_field
# V0.11: bugfix to make new reservations possible
# V0.12: small bugfix
# V0.13: remove yellow row color when invite or ack mail is sent
# V0.14: small bugfix with counters.  Added invitation reminder mail prefix
# V0.15: escape url specific characters in data
# V0.16: bugfix: when adding a new but empty registration, show error
# V0.17: update in logging: add correct app name
# V0.18: update in title of registration form
# V0.19: update in favicon of registration form
# V0.20: registration-ok html form can be set via admin settings
# V0.21: added message no-timeslot
# V0.22: bugifx timeslot-list
# V0.23: log when registration is cancelled
# V0.24: refactored callbacks in some Guest settings
# V0.25: implemented cancel-registration-mail
# V0.26: send cancel-registration-mail when guest pushes cancel registration button
# V0.27: copy from 0.26 and start to support opendag registrations
# V0.28: replaced reservation with registration
# V0.29: update copyright notice
# V0.30: backup, unified the html-pages
# V0.31: added email response, extended Guest-model, improved WEB response
# V0.32: student registration seems to work.  Reworked rendering of formio (more generic)
# V0.33: added buttons to show/hide columns
# V0.34: reworked celledit to support integers.  Re-use register-form to edit a registration.  Editing a registration is ok.
# V0.35: reworked registration table: improved feedback, addded filtering, added gauges
# V0.36: added datatables cell background coloring.  Implemented differentiation between registered and waiting-list students
# V0.37: registrations: make columns-visibility persistent.
# Bugfix algorithms to determine if a registration is ok or on the waiting list.
# Bug in socketio?  Sometimes a True at the sender is received as 'on'
# V0.38: implemented status (registered, waiting-list,...)
# Updated celledit and celltoggle
# V0.39: included correct columns when searching in database
# V0.40: implemented sending of confirmation emails
# updated list of registrations (more colors)
# update requirements.txt
# V0.41: bugfix registration list
# Implemented bool to send confirmation mail automatically
# V0.42: added email-confirmation-field.
# Bugfixed automatically-send-email-when-registering
# First code to register-timeslot
# V0.43: added support to reserve a timeslot and minor updates
# V0.44: filter and column-visibility: split out per page
# debugged timeslot and user pages
# V0.45: added setting (time/date) to allow prohibit timeslot registration.  Small cleanups
# V0.46: small bugfixes.  Improved handling of json-template-strings.  Clean up settings: delete unused and renamed.
# V0.47: clean up: removed unused functions and imports
# V0.48: added help page.  Minor updates
# V0.49: help files were not in git
# V0.50: update in help
# V0.51: update in help
# V0.52: update in help.  Added program to flatten timeslots
# V0.53: small updates.  Added registration-cache to speed up registrated/waiting-list issues
# V0.54: cosmetic update
# V0.55: if the register-settings are changed, rebuild the cache
# V0.56: when editing a registration, a print button is visible to print the confirmation document
# V0.57: bugix when adding a registration
# V0.58: optimization and added functionality to register in multiple registers
# V0.59: bugfix in checking timeslot
# V0.60: add todo's
# V0.61: add todo's
# V0.62: bugfix when retrieving a list of guest.  Implemented code to add pre-registers.  Added a column in the registration table.
# V0.63: bugfix: format of date returned from formio is not always the same
# V0.64: do not crash if date-of-birth is not filled in
# V0.65: supervisor can update timeslot of guest
# V0.66: bugfix in edit-registration: timeslot can be empty.  Translate field_of_study into Dutch
# V0.67: in a table, double click a row to edit
# V0.68: edit registration: condense form to improve overview
# V0.69: add sequence-numbers when on waiting-list.  Preempted empty integers (is a ''-string).  Added logging
# V0.70: removed test code# V0.71: add more details to logging
# V0.72: added over- and undercount to the registers.  Model: don't update properties when incorrect type.  Cleanup Guest callback
# V0.73: added warnings
# V0.74: log when registrationstatus is updated
# V0.75: settings: bugfix misc-settings and default settings for json-strings
# V0.76: added translation-settings to translate a key to dutch
# V0.77: push to github: sui-aanmelden.  Update logo's
# V0.78: esthetic updates.  Made a split between: no register + multiple fields of study and multiple registers + single field of study.
# Part of the datatables config-structure is now in settings so it can be changed easily.
# Translations is a setting (JSON).  Cached part of the settings to speed up access.
# V0.79: guest registration pages: extra css stored in settings
# V0.80: update in user-view
# V0.81: add logo to git
# V0.82: lowered werkzeug loglevel to get rid of traces.  Bugfixed socketio
# V0.83: bugfixed cell_edit in datatables.  Added comment to start uwsgi from commandline
# V0.84: update in uwsgi logging
# V0.85: updated logo.  Handle commit-exception.  Registration: introduced multiselect to select fields-of-study
# V0.86: color row depending on the status


#TODO: add sequence numbers when on the waiting list.  Add them on the confirmation document?
#TODO: add statistic counters, e.g. number per field-of-study, ...
#TODO: add note, when printing confirmation document, to print 2 copies
#TODO: after printing confirmation document, go to new registration automatically
#TODO: (preregistration) import list
#TODO: (preregistration) send personal registration link
#TODO: registration: allow access from certain ip-addresses only
#TODO: make it possible to print a detailed registration-form, to be updated by the parents when they close the registration
#TODO: login via smartschool
#TODO: pre-registration: send invitation link via smartschool
#TODO: detect overrun and underrun in regsiters (when a registered student moves from one register to another)
#TODO: add warnings page


@flask_app.context_processor
def inject_defaults():
    return dict(version='@ 2022 MB. V0.86', title=flask_app.config['HTML_TITLE'], site_name=flask_app.config['SITE_NAME'])


#  enable logging
log = logging.getLogger(flask_app.config['LOG_HANDLE'])


db = SQLAlchemy()
login_manager = LoginManager()


#  The original werkzeug-url-converter cannot handle negative integers (e.g. asset/add/-1/1)
class IntegerConverter(OrigIntegerConvertor):
    regex = r'-?\d+'
    num_convert = int


# support custom filtering while logging
class MyLogFilter(logging.Filter):
    def filter(self, record):
        record.username = current_user.username if current_user and current_user.is_active else 'NONE'
        return True


# set up logging
log_werkzeug = logging.getLogger('werkzeug')
log_werkzeug.setLevel(logging.ERROR)

LOG_FILENAME = os.path.join(sys.path[0], app_config[config_name].STATIC_PATH, f'log/{flask_app.config["LOG_FILE"]}.txt')
try:
    log_level = getattr(logging, app_config[config_name].LOG_LEVEL)
except:
    log_level = getattr(logging, 'INFO')
log.setLevel(log_level)
log.addFilter(MyLogFilter())
log_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=60 * 1024, backupCount=5)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(username)s - %(message)s')
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)

log.info(f"start {flask_app.config['SITE_NAME']}")

jsglue = JSGlue(flask_app)
db.app=flask_app  #  hack:-(
db.init_app(flask_app)

socketio = SocketIO(flask_app, async_mode=flask_app.config['SOCKETIO_ASYNC_MODE'], ping_timeout=10, ping_interval=5,
                    cors_allowed_origins=flask_app.config['SOCKETIO_CORS_ALLOWED_ORIGIN'])


def create_admin():
    from app.data.models import User
    find_admin = User.query.filter(User.username == 'admin').first()
    if not find_admin:
        admin = User(username='admin', password='admin', level=User.LEVEL.ADMIN, user_type=User.USER_TYPE.LOCAL)
        db.session.add(admin)
        db.session.commit()


flask_app.url_map.converters['int'] = IntegerConverter
login_manager.init_app(flask_app)
login_manager.login_message = 'Je moet aangemeld zijn om deze pagina te zien!'
login_manager.login_view = 'auth.login'

migrate = Migrate(flask_app, db)

# configure e-mailclient
email = Mail(flask_app)
send_emails = False

SCHEDULER_API_ENABLED = True
email_scheduler = APScheduler()
email_scheduler.init_app(flask_app)
email_scheduler.start()

if 'db' in sys.argv:
    from app.data import models
else:
    create_admin()  #  Only once

    # decorator to grant access to admins only
    def admin_required(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_at_least_admin:
                abort(403)
            return func(*args, **kwargs)
        return decorated_view


    # decorator to grant access to at least supervisors
    def supervisor_required(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_at_least_supervisor:
                abort(403)
            return func(*args, **kwargs)
        return decorated_view

    from app.presentation.view import auth, user, settings, guest, registration, timeslot, api, warning
    flask_app.register_blueprint(api.api)
    flask_app.register_blueprint(auth.auth)
    flask_app.register_blueprint(user.user)
    flask_app.register_blueprint(guest.guest)
    flask_app.register_blueprint(settings.settings)
    flask_app.register_blueprint(registration.registration)
    flask_app.register_blueprint(timeslot.timeslot)
    flask_app.register_blueprint(warning.warning)

    @flask_app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html', title='Forbidden'), 403

    @flask_app.errorhandler(404)
    def page_not_found(error):
        return render_template('errors/404.html', title='Page Not Found'), 404

    @flask_app.errorhandler(500)
    def internal_server_error(error):
        return render_template('errors/500.html', title='Server Error'), 500

    @flask_app.route('/500')
    def error_500():
        abort(500)


