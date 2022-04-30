from app import log, db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json
from babel.dates import get_day_names, get_month_names
from app.data import settings as msettings


# woensdag 24 februari om 14 uur
def datetime_to_dutch_datetime_string(date, include_seconds=False):
    try:
        time_string = f"%H.%M{':%S' if include_seconds else ''}"
        date_string = f'{get_day_names(locale="nl")[date.weekday()]} {date.day} {get_month_names(locale="nl")[date.month]} om {date.strftime(time_string)}'
        return date_string
    except:
        return ''

#24/2/2022 22:12:23
def datetime_to_dutch_short(date, include_seconds=False, include_time=True):
    try:
        in_string = "%d/%m/%Y"
        if include_time:
            in_string = f"{in_string} %H.%M{':%S' if include_seconds else ''}"
        return date.strftime(in_string)
    except:
        return ''


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    class USER_TYPE:
        LOCAL = 'local'
        OAUTH = 'oauth'

    @staticmethod
    def get_zipped_types():
        return list(zip(['local', 'oauth'], ['LOCAL', 'OAUTH']))

    class LEVEL:
        USER = 1
        SUPERVISOR = 3
        ADMIN = 5

        ls = ["GEBRUIKER", "SECRETARIAAT", "ADMINISTRATOR"]

        @staticmethod
        def i2s(i):
            if i == 1:
                return User.LEVEL.ls[0]
            elif i == 3:
                return User.LEVEL.ls[1]
            if i == 5:
                return User.LEVEL.ls[2]

    @staticmethod
    def get_zipped_levels():
        return list(zip(["1", "3", "5"], User.LEVEL.ls))

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256))
    username = db.Column(db.String(256))
    first_name = db.Column(db.String(256))
    last_name = db.Column(db.String(256))
    password_hash = db.Column(db.String(256))
    level = db.Column(db.Integer)
    user_type = db.Column(db.String(256))
    last_login = db.Column(db.DateTime())

    @property
    def is_local(self):
        return self.user_type == User.USER_TYPE.LOCAL

    @property
    def is_oauth(self):
        return self.user_type == User.USER_TYPE.OAUTH

    @property
    def is_at_least_user(self):
        return self.level >= User.LEVEL.USER

    @property
    def is_strict_user(self):
        return self.level == User.LEVEL.USER

    @property
    def is_at_least_supervisor(self):
        return self.level >= User.LEVEL.SUPERVISOR

    @property
    def is_at_least_admin(self):
        return self.level >= User.LEVEL.ADMIN

    @property
    def password(self):
        raise AttributeError('Paswoord kan je niet lezen.')

    @password.setter
    def password(self, password):
        if password:
            self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        else:
            return True

    def __repr__(self):
        return '<User: {}>'.format(self.username)

    def log(self):
        return '<User: {}/{}>'.format(self.id, self.username)

    def ret_dict(self):
        return {'id': self.id, 'DT_RowId': self.id, 'email': self.email, 'username': self.username,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'level': User.LEVEL.i2s(self.level), 'user_type': self.user_type, 'last_login': self.last_login,
                'chbx': ''}


field_of_study_to_dutch = msettings.get_translations('field_of_study')

class Guest(db.Model):
    __tablename__ = 'guests'

    class Status:
        E_REGISTERED = 'registered'     #ingeschreven
        E_WAITINGLIST = 'waiting-list'  #wachtlijst
        E_UNREGISTERED = 'unregistered' #uitgeschreven

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(256))
    last_login = db.Column(db.DateTime())

    invite_email_tx = db.Column(db.Boolean, default=True)   #invite email is sent
    invite_nbr_tx = db.Column(db.Integer(), default=0)      #nbr of invite emails sent
    reg_ack_email_tx = db.Column(db.Boolean, default=True)  #registration ack email is sent
    reg_ack_nbr_tx = db.Column(db.Integer(), default=0)     #nbr of registration ack emails sent
    tsl_ack_email_tx = db.Column(db.Boolean, default=True)  #timeslot registration ack email is sent
    tsl_ack_nbr_tx = db.Column(db.Integer(), default=0)     #nbr of timeslot registration ack emails sent
    cancel_email_tx = db.Column(db.Boolean, default=True)   #cancel email is sent
    cancel_nbr_tx = db.Column(db.Integer(), default=0)      #nbr of cancel emails sent
    email_tot_nbr_tx = db.Column(db.Integer(), default=0)   #nbr of emails-try-send

    enabled = db.Column(db.Boolean, default=True)
    code = db.Column(db.String(256), default='')
    timeslot = db.Column(db.DateTime())
    misc_field = db.Column(db.Text)

    register_timestamp = db.Column(db.DateTime())
    unregister_timestamp = db.Column(db.DateTime())
    status = db.Column(db.String(256), default='')      #ingeschreven/uitgeschreven/wachtlijst
    email = db.Column(db.String(256))
    phone = db.Column(db.String(256))
    first_name = db.Column(db.String(256))
    last_name = db.Column(db.String(256))
    child_last_name = db.Column(db.String(256))
    child_first_name = db.Column(db.String(256))
    date_of_birth = db.Column(db.DateTime())
    sex = db.Column(db.String(256), default='')
    street = db.Column(db.String(256), default='')
    house_number = db.Column(db.Integer(), default=0)
    town = db.Column(db.String(256), default='')
    postal_code = db.Column(db.String(256), default='')
    note = db.Column(db.Text)
    national_registration_number = db.Column(db.String(256), default='')
    field_of_study = db.Column(db.String(256), default='')
    indicator = db.Column(db.Boolean, default=False)   #kansarm
    reason_priority = db.Column(db.String(256), default='')   #reden van voorrang
    row_color = db.Column(db.String(256), default='none')   #give a row a color


    def get_register(self):
        return self.field_of_study.split('-')[0]
    register = property(get_register)

    property_changed_cb = {}
    def __setattr__(self, key, value):
        old_value = getattr(self, key) if key in Guest.__table__.columns else None
        super(Guest, self).__setattr__(key, value)
        if key not in Guest.__table__.columns or not self.id:
            return
        if old_value != value:
            if key in self.property_changed_cb:
                for cb in self.property_changed_cb[key]:
                    cb[0](key, value, cb[1])
            if '*' in self.property_changed_cb:
                for cb in self.property_changed_cb['*']:
                    cb[0]('*', value, cb[1])

    @staticmethod
    def subscribe(type, cb, opaque):
        if type not in Guest.property_changed_cb:
            Guest.property_changed_cb[type] = []
        Guest.property_changed_cb[type].append((cb, opaque))
        return True

    def flat(self):
        flat = {
        'id': self.id,
        'key': self.key,
        'last_login': self.last_login,
        'invite_email_tx': self.invite_email_tx,
        'invite_nbr_tx': self.invite_nbr_tx,
        'reg_ack_email_tx': self.reg_ack_email_tx,
        'reg_ack_nbr_tx': self.reg_ack_nbr_tx,
        'tsl_ack_email_tx': self.tsl_ack_email_tx,
        'tsl_ack_nbr_tx': self.tsl_ack_nbr_tx,
        'cancel_email_tx': self.cancel_email_tx,
        'cancel_nbr_tx': self.cancel_nbr_tx,
        'email_tot_nbr_tx': self.email_tot_nbr_tx,
        'enabled': self.enabled,
        'code': self.code,
        'misc_field': self.misc_field,
        'register_timestamp': self.register_timestamp,
        'register_timestamp_dutch': datetime_to_dutch_short(self.register_timestamp, include_seconds=True),

        'unregister_timestamp': self.unregister_timestamp,
        'unregister_timestamp_dutch': datetime_to_dutch_short(self.unregister_timestamp, include_seconds=True),

        'status': self.status,
        'email': self.email,
        'phone': self.phone,
        'first_name': self.first_name,
        'last_name': self.last_name,
        'child_last_name': self.child_last_name,
        'child_first_name': self.child_first_name,
        'date_of_birth': self.date_of_birth,
        'date_of_birth_dutch': datetime_to_dutch_short(self.date_of_birth, include_time=False),
        'sex': self.sex,
        'street': self.street,
        'house_number': self.house_number,
        'town': self.town,
        'postal_code': self.postal_code,
        'note': self.note,
        'national_registration_number': self.national_registration_number,
        'register': self.field_of_study.split('-')[0],
        'indicator': self.indicator,
        'indicator_dutch': 'I' if self.indicator else '',
        'reason_priority': self.reason_priority,

        'invite_email_sent': self.invite_email_tx,
        'nbr_invite_sent': self.invite_nbr_tx,
        'ack_email_sent': self.reg_ack_email_tx,
        'nbr_ack_sent': self.reg_ack_nbr_tx,
        'cancel_email_sent': self.cancel_email_tx,
        'nbr_cancel_sent': self.cancel_nbr_tx,
        'timeslot': self.timeslot,
        'timeslot_dutch_short': datetime_to_dutch_short(self.timeslot),
        'timeslot_dutch': datetime_to_dutch_datetime_string(self.timeslot),
        'full_name': f"{self.last_name} {self.first_name}",
        'child_name': f"{self.child_last_name} {self.child_first_name}",
        'row_color': self.row_color,
        'overwrite_cell_color': []
        }
        if msettings.use_register():
            flat.update({
                'field_of_study': self.field_of_study,
                'field_of_study_dutch': msettings.get_translations('field_of_study')[self.field_of_study],
            })
        else:
            field_of_study_dutch = ''
            fields = json.loads(self.field_of_study)
            for field in fields:
                field_of_study_dutch += msettings.get_translations('field_of_study')[field] + '<br>'
            flat.update({'field_of_study_dutch': field_of_study_dutch})
        misc_field = json.loads(self.misc_field) if self.misc_field else ''
        flat.update(misc_field)
        return flat


class TimeslotConfiguration(db.Model):
    __tablename__ = 'timeslot_configurations'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime())
    length = db.Column(db.Integer, default=15)  # in minutes
    nbr_of_timeslots = db.Column(db.Integer, default=20)
    items_per_timeslot = db.Column(db.Integer, default=8)
    active = db.Column(db.Boolean, default=True)

    def flat(self):
        return {
            'id': self.id,
            'active': self.active,
            'date': datetime_to_dutch_datetime_string(self.date),
            'overwrite_row_color': self.row_color(),
        }


class Warning(db.Model):
    __tablename__ = 'warnings'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime())
    message = db.Column(db.String(4096), default='')
    visible = db.Column(db.Boolean, default=True)

    def flat(self):
        return {
            'id': self.id,
            'visible': self.visible,
            'timestamp_dutch': datetime_to_dutch_datetime_string(self.timestamp),
            'message': self.message
        }

