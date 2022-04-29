import app.data.settings
from app.application import formio as mformio, util as mutil, timeslot_configuration as matc, warning as mwarning
from app.data import utils as mdutils, guest as mguest, settings as msettings, timeslot_configuration as mtc
from app.data.guest import get_guests, get_guest_register_last_timestamp
from app.data.models import Guest
from app import log
import datetime, json, sys
from json.decoder import JSONDecodeError

class MessageType:
    E_GENERIC = 'message-generic'
    E_ERROR = 'message-error'


class RegisterCache:
    class Register:
        def __init__(self, parent, register, max_regular, max_indicator, overflow_setting):
            self.parent = parent
            self.register = register
            self.max_regular = max_regular
            self.max_indicator = max_indicator
            self.overflow = not overflow_setting == 'none'
            self.overflow_r2i = overflow_setting == 'regular-to-indicator'
            self.overflow_i2r = overflow_setting == 'indicator-to-regular'
            self.overflow_both = overflow_setting == 'both'
            self.regular_ok = []
            self.regular_wait = []
            self.indicator_ok = []
            self.indicator_wait = []

        def _check_overflow_one_direction(self, guest, is_i2r):
            check1 = self.check_indicator if is_i2r else self.check_regular
            check2 = self.check_regular if is_i2r else self.check_indicator
            indicator = guest.indicator if is_i2r else not guest.indicator
            list1_ok = self.indicator_ok if is_i2r else self.regular_ok
            list2_ok = self.regular_ok if is_i2r else self.indicator_ok
            list1_wait = self.indicator_wait if is_i2r else self.regular_wait
            list2_wait = self.regular_wait if is_i2r else self.indicator_wait
            if indicator:
                if check1:
                    list1_ok.append(guest.id)
                    return True
                elif self.check_both:
                    list2_ok.append(guest.id)
                    return True
                list1_wait.append(guest.id)
                list2_wait.append(guest.id)
                return False
            if self.check_both and check2:
                list2_ok.append(guest.id)
                return True
            list2_wait.append(guest.id)
            return False

        def _check_overflow_both_directions(self, guest):
            check1 = self.check_indicator if guest.indicator else self.check_regular
            list1_ok = self.indicator_ok if guest.indicator else self.regular_ok
            list2_ok = self.regular_ok if guest.indicator else self.indicator_ok
            list1_wait = self.indicator_wait if guest.indicator else self.regular_wait
            list2_wait = self.regular_wait if guest.indicator else self.indicator_wait
            if check1:
                list1_ok.append(guest.id)
                return True
            elif self.check_both:
                list2_ok.append(guest.id)
                return True
            list1_wait.append(guest.id)
            list2_wait.append(guest.id)
            return False

        def _check_overflow_none(self, guest):
            check1 = self.check_indicator if guest.indicator else self.check_regular
            list1_ok = self.indicator_ok if guest.indicator else self.regular_ok
            list1_wait = self.indicator_wait if guest.indicator else self.regular_wait
            if check1:
                list1_ok.append(guest.id)
                return True
            list1_wait.append(guest.id)
            return False

        def add_guest(self, guest):
            self.check_regular = len(self.regular_ok) < self.max_regular
            self.check_indicator = len(self.indicator_ok) < self.max_indicator
            self.check_both = len(self.regular_ok) + len(self.indicator_ok) < self.max_regular + self.max_indicator
            self.parent.guest_cache[guest.id] = guest
            if self.overflow:
                if self.overflow_i2r:
                    return self._check_overflow_one_direction(guest, True)
                elif self.overflow_r2i:
                    return self._check_overflow_one_direction(guest, False)
                else:
                    return self._check_overflow_both_directions(guest)
            else:
                return self._check_overflow_none(guest)

        def get_guest_status_indication(self, guest):
            if guest.id in self.regular_ok:
                return (True, 'regular', self.regular_ok.index(guest.id))
            if guest.id in self.indicator_ok:
                return (True, 'indicator', self.indicator_ok.index(guest.id))
            if guest.id in self.regular_wait:
                return (False, 'regular', self.regular_wait.index(guest.id))
            if guest.id in self.indicator_wait:
                return (False, 'indicator', self.indicator_wait.index(guest.id))
            return (False, 'wait', -1)

        def delete_guest(self, guest):
            if guest.id in self.parent.guest_cache:
                del self.parent.guest_cache[guest.id]
            if guest.id in self.regular_ok:
                self.regular_ok.remove(guest.id)
                try:
                    id = self.regular_wait.pop(0)
                    self.regular_ok.append(id)
                except:
                    pass #waiting list is empty
            if guest.id in self.indicator_ok:
                self.indicator_ok.remove(guest.id)
                try:
                    id = self.indicator_wait.pop(0)
                    self.indicator_ok.append(id)
                except:
                    pass #waiting list empty
            if guest.id in self.regular_wait:
                self.regular_wait.remove(guest.id)
            if guest.id in self.indicator_wait:
                self.indicator_wait.remove(guest.id)

        def purge(self):
            self.regular_ok = []
            self.regular_wait = []
            self.indicator_ok = []
            self.indicator_wait = []

        def get_status(self):
            status = {
                'max_regular': self.max_regular,
                'nbr_regular': len(self.regular_ok),
                'max_indicator': self.max_indicator,
                'nbr_indicator': len(self.indicator_ok),
                'overflow': self.overflow,
                'overflow_r2i': self.overflow_r2i,
                'overflow_i2r': self.overflow_i2r,
                'overflow_both': self.overflow_both,
            }
            return status


    guest_cache = {}
    register_cache = {}
    def __init__(self): #read the database and the register settings and initialize the caches
        try:
            register_settings = app.data.settings.get_json_template('student-register-settings')
            for r, d in register_settings.items():
                self.register_cache[r] = RegisterCache.Register(self, r, d['max-number-regular-registrations'],
                                          d['max-number-indicator-registrations'],
                                          d['overflow'])

            guests = mguest.get_guests({'enabled': True}, order_by='register_timestamp')
            for guest in guests:
                self.register_cache[guest.register].add_guest(guest)
        except Exception as e:
            log.error(f'{sys._getframe().f_code.co_name}: {e}')

    def add_guest(self, guest):
        return self.register_cache[guest.register].add_guest(guest)


    def delete_guest(self, guest):
        return self.register_cache[guest.register].delete_guest(guest)

    # return true if a guest is in the register, return false if a guest is on the waiting list
    def get_guest_status_indicaton(self, guest):
        return self.register_cache[guest.register].get_guest_status_indication(guest)

    def check_register_change(self, guest):
        guest_cached = self.guest_cache[guest.id]
        if guest_cached.register == guest.register:
            return
        mwarning.new_warning(f'{guest.child_last_name} {guest.child_first_name}, {guest.email} is veranderd van register: {guest_cached.register} -> {guest.register}')
        self.delete_guest(guest_cached) # remove from old register
        self.refresh_cache(guest)       # add to new register


    def refresh_cache(self, guest):
        reg_label = guest.register
        self.register_cache[reg_label].purge()
        guests = mguest.get_guests({'enabled': True}, {'field_of_study_like': reg_label}, order_by='register_timestamp')
        for guest in guests:
            self.register_cache[reg_label].add_guest(guest)

    def restart_cache(self):
        self.__init__()

    def get_status(self):
        status = {}
        for r, d in self.register_cache.items():
            status[r] = d.get_status()
        return status

    def get_registers_info(self):
        out = []
        for register_label, register in self.register_cache.items():
            out_register = {
                'name': register_label,
                'max-regular': register.max_regular,
                'nbr-regular-ok': len(register.regular_ok),
                'nbr-regular-wait': len(register.regular_wait),
                'max-indicator': register.max_indicator,
                'nbr-indicator-ok': len(register.indicator_ok),
                'nbr-indicator-wait': len(register.indicator_wait),
                'guests': []
            }
            for g in register.regular_ok:
                out_register['guests'].append({'list': 'regular-ok', 'register_timestamp': mdutils.datetime_to_dutch_datetime_string(g.register_timestamp, True),'status': g.status,})
            for g in register.regular_wait:
                out_register['guests'].append({'list': 'regular-wait', 'register_timestamp': mdutils.datetime_to_dutch_datetime_string(g.register_timestamp, True),'status': g.status,})
            for g in register.indicator_ok:
                out_register['guests'].append({'list': 'indicator-ok', 'register_timestamp': mdutils.datetime_to_dutch_datetime_string(g.register_timestamp, True),'status': g.status,})
            for g in register.indicator_wait:
                out_register['guests'].append({'list': 'indicator-wait', 'register_timestamp': mdutils.datetime_to_dutch_datetime_string(g.register_timestamp, True),'status': g.status,})

            out.append(out_register)
        return out

try:
    if msettings.use_register():
        register_cache = RegisterCache()
except Exception as e:
    log.error(f'{sys._getframe().f_code.co_name}: {e}')


def prepare_registration():
    try:
        return {'template': app.data.settings.get_json_template('student-register-template')}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e


def prepare_edit_registration_form(code):
    try:
        guest = mguest.get_first_guest({"code": code})
        template = app.data.settings.get_json_template('student-register-template')
        available_timeslots = get_available_timeslots(guest.timeslot)
        mformio.update_available_timeslots(available_timeslots, template, 'radio-timeslot')
        template = mformio.prepare_for_edit(template, guest.flat())
        return {'template': template,
                'defaults': guest.flat()}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e


def prepare_add_registration_form():
    try:
        template = app.data.settings.get_json_template('student-register-template')
        template = mformio.prepare_for_add(template)
        return {'template': template}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e


def get_confirmation_document(code):
    try:
        template = app.data.settings.get_json_template('student-web-response-template')
        guest = mguest.get_first_guest({'code': code})
        if _check_register_status(guest):
            template = mformio.prepare_sub_component(template, 'register-child-ack-document-ok', guest)
        else:
            template = mformio.prepare_sub_component(template, 'register-child-ack-document-waiting-list', guest)
        return {'template': template}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        log.error(code)
        raise e


def registration_done(code):
    try:
        template = app.data.settings.get_json_template('student-web-response-template')
        guest = mguest.get_first_guest({'code': code})
        #check the register settings to see if the student is registered or is on the waiting list
        if _check_register_status(guest):
            template = mformio.prepare_sub_component(template, 'register-child-ack-ok', guest)
        else:
            template = mformio.prepare_sub_component(template, 'register-child-ack-waiting-list', guest)
        # send confirmation e-mail
        if msettings.get_configuration_setting('student-register-arm-send-ack-mail'):
            mguest.update_guest(guest, {"reg_ack_nbr_tx": 0, "reg_ack_email_tx": False})
        return {'template': template}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        log.error(code)
        raise e


def timeslot_registration_done(code):
    try:
        template = app.data.settings.get_json_template('timeslot-web-response-template')
        guest = mguest.get_first_guest({'code': code})
        template = mformio.prepare_sub_component(template, 'timeslot-register-ack-ok', guest)
        # send confirmation e-mail
        if msettings.get_configuration_setting('timeslot-register-arm-send-ack-mail'):
            mguest.update_guest(guest, {"tsl_ack_nbr_tx": 0, "tsl_ack_email_tx": False})
        return {'template': template}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        log.error(code)
        raise e


def check_register_status(code):
    try:
        guest = mguest.get_first_guest({'code': code})
        #check the register settings to see if the student is registered or is on the waiting list
        return {'status': True, 'data': _check_register_status(guest)}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        log.error(code)
        return {"status": False, "data": f'generic error {e}'}


def registration_add(data):
    try:
        if 'date_of_birth_dutch' in data:
            if data['date_of_birth_dutch'] == '':
                del data['date_of_birth_dutch']
            else:
                data['date_of_birth'] = mformio.formiodate_to_date(data['date_of_birth_dutch'])
        if 'field_of_study' in data and data['field_of_study'] == '':
            return {"status": False, "data": 'Fout, u moet een keuzepakket opgeven'}

        translations = app.data.settings.get_translations('field_of_study')
        field_of_study = []
        #multiple select buttons on the form, each selected button is in 'data"
        for k, v in translations.items():
            if k in data and data[k]:
                field_of_study.append(k)
        #multiselect components on the form, each selected item is in a list, named after the component
        if 'multiselect-field-of-study' in data and data['multiselect-field-of-study']:
            for _, selections in data['multiselect-field-of-study'].items():
                for selection in selections:
                    field_of_study.append(selection)

        data['field_of_study'] = json.dumps(field_of_study)

        if 'pre_register' in data and data['pre_register']:
            if 'code' not in data:
                data['code'] = mutil.create_random_string()
            if 'register_timestamp' in data and data['register_timestamp'] != '':
                register_settings = app.data.settings.get_json_template('student-register-settings')
                register = data['field_of_study'].split('-')[0]
                register_type = 'max-number-indicator-registrations' if data['indicator'] else 'max-number-regular-registrations'
                register_settings[register][register_type] += 1
                app.data.settings.set_json_template('student-register-settings', register_settings)
                data['register_timestamp'] = mformio.formiodate_to_datetime(data['register_timestamp'])
            if 'radio-timeslot' in data and data['radio-timeslot'] != '':
                matc.flatten_timeslots()
                ts = mformio.formiodate_to_datetime(data['timeslot'])
                timeslot_compare = {'year': ts.year, 'month': ts.month, 'day': ts.day, 'hour': ts.hour, 'minute': ts.minute}
                timeslot_settings = app.data.settings.get_json_template('timeslot-config-timeslots-template')
                found = False
                for ts in timeslot_settings:
                    if timeslot_compare.items() <= ts.items():
                        found = True
                        ts['places'] += 1
                        break
                if not found:
                    return {"status": False, "data": f'error: timeslot {data["timeslot"]} not found for {data["email"]}'}
                app.data.settings.set_json_template('timeslot-config-timeslots-template', timeslot_settings)
            data['status'] = Guest.Status.E_REGISTERED
            guest = mguest.add_guest(data)
            log.info(f"New pre-registration: {guest.email}, {data}")
            return {"status": True, "data": guest.code}

        data_selection = {  #duplicates are detetected when email AND childs name are already in database
            'email': data['email'],
            'child_first_name': data['child_first_name'],
            'child_last_name': data['child_last_name']
        }
        duplicate_guest = mguest.get_first_guest(data_selection)
        if duplicate_guest:
            #check if a guest can register on multiple registers
            register_settings = app.data.settings.get_json_template('student-register-settings')
            new_register = data['field_of_study'].split('-')[0]
            if 'multiple-registrations' not in register_settings[duplicate_guest.register] or new_register not in register_settings[duplicate_guest.register]['multiple-registrations']:
                return {"status": False, "data": f"Fout, de student {duplicate_guest.child_first_name} {duplicate_guest.child_last_name} en mailadres {duplicate_guest.email}\n is reeds geregistreerd."}
        misc_config = app.data.settings.get_json_template('import-misc-fields')
        extra_fields = [c['veldnaam'] for c in misc_config]
        extra_field = {f: '' for f in extra_fields}
        data['misc_field'] = json.dumps(extra_field)
        data['code'] = mutil.create_random_string()
        data['register_timestamp'] = datetime.datetime.now()
        guest = mguest.add_guest(data)
        if not guest:
            return {"status": False, "data": f'fout, kan registratie niet vervolledigen'}
        registration_ok = register_cache.add_guest(guest) if msettings.use_register() else True
        mguest.update_guest(guest, {'status': guest.Status.E_REGISTERED if registration_ok else guest.Status.E_WAITINGLIST})
        log.info(f"New registration: {guest.email}, {data}")
        return {"status": True, "data": guest.code}
    except JSONDecodeError as e:
        return {"status": False, "data": f'error: JSON decoder: {e}'}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        log.error(data)
        return {"status": False, "data": f'generic error {e}'}


# return True if the guest is not in the waiting-list
def _check_register_status(guest):
    return guest.status != guest.Status.E_WAITINGLIST


def prepare_timeslot_registration(code=None):
    try:
        guest = mguest.get_first_guest({'code': code})
        if not guest:
            template = app.data.settings.get_json_template('timeslot-web-response-template')
            template = mformio.prepare_sub_component(template, 'timeslot-register-error-wrong-code')
            return {'template': template}
        now = datetime.datetime.now()
        timeslot_registration_open = msettings.get_configuration_setting('timeslot-open-registration-at')
        timeslot_registration_open = mformio.formiodate_to_datetime(timeslot_registration_open)
        if now < timeslot_registration_open:
            template = app.data.settings.get_json_template('timeslot-web-response-template')
            template = mformio.prepare_sub_component(template, 'timeslot-registration-not-open',
                                                     additional_fields={'timeslot_registration_open_dutch': mdutils.datetime_to_dutch_datetime_string(timeslot_registration_open)})
            return {'template': template}
        available_timeslots = get_available_timeslots(guest.timeslot)
        template = app.data.settings.get_json_template('timeslot-register-template')
        mformio.update_available_timeslots(available_timeslots, template, 'radio-timeslot')
        data = {'template': template,'defaults': guest.flat()}
        return data
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')


def registration_update(code, data):
    try:
        guest = mguest.get_first_guest({"code": code})
        if 'date_of_birth_dutch' in data:
            if data['date_of_birth_dutch'] == '':
                del data['date_of_birth_dutch']
            else:
                data['date_of_birth'] = mformio.formiodate_to_date(data['date_of_birth_dutch'])
        if 'status' in data:
            data['reg_ack_nbr_tx'] = 0
            if data['status'] == Guest.Status.E_UNREGISTERED:
                data['unregister_timestamp'] = datetime.datetime.now()
                data['enabled'] = False
            if data['status'] == Guest.Status.E_REGISTERED or data['status'] == Guest.Status.E_WAITINGLIST:
                data['enabled'] = True
            log.info(f'{guest.child_last_name} {guest.child_first_name}, {guest.email} has changed status: {guest.status} -> {data["status"]}')
        if 'radio-timeslot' in data and data['radio-timeslot'] != '':
            timeslot = mformio.formiodate_to_datetime(data['radio-timeslot'])
            if timeslot != guest.timeslot and not _check_requested_timeslot(timeslot):
                return {"status": False, "data": "Opgepast, het gekozen tijdslot is zojuist volzet geraakt.\nGelieve een nieuw tijdslot te kiezen."}
            data['timeslot'] = timeslot
        mguest.update_guest(guest, data)
        if 'field_of_study' in data and msettings.use_register():
            register_cache.check_register_change(guest)
        if 'enabled' in data and msettings.use_register():
            if data['enabled']:
                register_cache.refresh_cache(guest)
            else:
                register_cache.delete_guest(guest)
        log.info(f"Update registration: {guest.email}, {data}")
        return {"status": True, "data": guest.code}
    except JSONDecodeError as e:
        return {"status": False, "data": f'error: JSON decoder: {e}'}
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        log.error(data)
        return {"status": False, "data": f'generic error {e}'}


def registration_delete(codes):
    if msettings.use_register():
        for code in codes:
            guest = mguest.get_first_guest({"code": code})
            register_cache.delete_guest(guest)
    mguest.delete_guest(codes)


registration_changed_cb = []
def registration_subscribe_changed(cb, opaque):
    try:
        registration_changed_cb.append((cb, opaque))
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')


def guest_any_property_changed_cb(type, value, opaque):
    for cb in registration_changed_cb:
        cb[0](value, cb[1])

Guest.subscribe('*', guest_any_property_changed_cb, None)


def display_register_counters():
    display = []
    if msettings.use_register():
        status = register_cache.get_status()
        for reg_label, register in status.items():
            nbr_regular = mguest.get_guest_register_count(reg_label, indicator=False)
            nbr_indicator = mguest.get_guest_register_count(reg_label, indicator=True)
            nbr_ok = mguest.get_guest_register_count(reg_label, status='registered')
            both_ok = nbr_regular + nbr_indicator <= register['max_regular'] + register['max_indicator']
            if register['overflow']:
                if register['overflow_both']:
                    regular_ok = both_ok
                    indicator_ok = both_ok
                    overflow_symbol = ' (R <-> I)'
                elif register['overflow_i2r']:
                    regular_ok = both_ok and nbr_regular <= register['max_regular']
                    indicator_ok  = both_ok
                    overflow_symbol = ' (R <- I)'
                else:
                    regular_ok = both_ok
                    indicator_ok = both_ok and nbr_indicator <= register['max_indicator']
                    overflow_symbol = ' (R -> I)'
            else:
                regular_ok = nbr_regular <= register['max_regular']
                indicator_ok = nbr_indicator <= register['max_indicator']
                overflow_symbol = ' '
            overcount = nbr_ok - register['max_regular'] -register['max_indicator']
            overcount_style = "style='background: lightcoral;'" if overcount > 0 else "style='background: lightgreen;'"
            regular_style = "" if regular_ok else "style='background: Moccasin;'"
            indicator_style = "" if indicator_ok else "style='background: Moccasin;'"
            display.append(f"{reg_label}{overflow_symbol}, <span style='background: aqua;'> regulier:</span> "
                           f"<span {overcount_style}>({overcount:+})</span> "
                           f"<span {regular_style}>{nbr_regular}/{register['max_regular']}</span>, "
                           f"<span style='background: turquoise;'>indicator:</span> "
                           f"<span {indicator_style}>{nbr_indicator}/{register['max_indicator']}</span>")
    else:
        guest_count = mguest.get_guest_count({'enabled': True})
        display.append(f'Aantal: {guest_count}')
    return display


def get_available_timeslots(default_date=None, ignore_availability=False):
    try:
        timeslots = []
        id = 0
        timeslot_configs = mtc.get_timeslot_configurations()
        for timeslot_config in timeslot_configs:
            date = timeslot_config.date
            for i in range(timeslot_config.nbr_of_timeslots):
                nbr_guests = mguest.get_guest_count({'enabled': True, 'timeslot': date})
                available = timeslot_config.items_per_timeslot - nbr_guests
                default_flag = default_date and date == default_date
                if default_flag:
                    available += 1
                if available > 0 or ignore_availability:
                    timeslots.append({
                        'label':  f"({available}) {mutil.datetime_to_dutch_datetime_string(date)}",
                        'value': mformio.datetime_to_formio_datetime(date),
                        'available': available,
                        'default': default_flag,
                        'maximum': timeslot_config.items_per_timeslot,
                        'id': id
                    })
                date += datetime.timedelta(minutes=timeslot_config.length)
                id += 1
        return timeslots
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
    return []


def datatable_get_timeslots():
    out = []
    timeslots = get_available_timeslots(ignore_availability=True)
    for timeslot in timeslots:
        em = {
            'row_action': timeslot["id"],
            'id': timeslot["id"],
            'DT_RowId': timeslot["id"],
            'timeslot': timeslot['label'],
            'nbr_total': timeslot['maximum'],
            'nbr_open': timeslot['available'],
            'nbr_reserved': timeslot['maximum'] - timeslot['available']
        }
        out.append(em)
    return out


# return true if the current number of guests is less than the maximum
def _check_requested_timeslot(date):
    try:
        tcs = mtc.get_timeslot_configurations()
        for tc in tcs:
            start_date = tc.date
            end_date = tc.date + datetime.timedelta(minutes=(tc.nbr_of_timeslots * tc.length))
            if start_date <= date < end_date:
                guest_count = mguest.get_guest_count({'timeslot': date, 'enabled': True})
                return guest_count < tc.items_per_timeslot
        return False
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
    return False


def format_data(db_list):
    out = []
    for guest in db_list:
        em = guest.flat()
        em.update({
            'row_action': guest.code,
            'id': guest.id,
            'DT_RowId': guest.code
        })
        if msettings.use_register():
            em['sequence_counter'] = ""
            if guest.enabled:
                status_indication, register, index = register_cache.get_guest_status_indicaton(guest)
                em['sequence_counter'] = index + 1
                if status_indication:
                    em['overwrite_cell_color'].append(['register_timestamp_dutch', 'greenyellow'])
                    em['overwrite_cell_color'].append(['sequence_counter', 'aqua' if register == 'regular' else 'turquoise'])
                else:
                    em['overwrite_cell_color'].append(['register_timestamp_dutch', 'yellow'])
                if guest.status == Guest.Status.E_REGISTERED:
                    em['overwrite_cell_color'].append(['status', 'greenyellow'])
                else:
                    em['overwrite_cell_color'].append(['status', 'yellow'])
            else:
                em['overwrite_cell_color'].append(['enabled', 'red'])
            if guest.reg_ack_nbr_tx == 0:
                em['overwrite_cell_color'].append(['reg_ack_nbr_tx', 'orange'])
                em['overwrite_cell_color'].append(['reg_ack_email_tx', 'orange'])
            if guest.tsl_ack_nbr_tx == 0:
                em['overwrite_cell_color'].append(['tsl_ack_nbr_tx', 'orange'])
                em['overwrite_cell_color'].append(['tsl_ack_email_tx', 'orange'])
        else:
            em['sequence_counter'] = "NA"
            if guest.status != 'none' and guest.status != 'registered':
                em['overwrite_row_color'] = guest.status
        out.append(em)
    return out


def register_settings_changed_cb(value, null):
    if msettings.use_register():
        register_cache.restart_cache()
        log.info(f'register settings are changed')

msettings.subscribe_setting_changed('student-register-settings', register_settings_changed_cb, None)