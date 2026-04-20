import app.data.settings
from app.data import settings as msettings, guest as mguest
from app.application import formio as mformio, util as mutil
from app.data.entra import entra
from app import email, log, email_scheduler, flask_app
import datetime, time, sys
from flask_mail import Message

def send_email(to_list, subject, content):
    log.info(f'{sys._getframe().f_code.co_name}: send_email to: {to_list}, subject: {subject}')
    enable = msettings.get_configuration_setting('email-enable-send-email')
    if enable:
        try:
            # microsoft does not support sending email via SMTP anymore.  Use of graph api is required
            return entra.send_mail(to_list, subject, content)
        except Exception as e:
            log.error(f'{sys._getframe().f_code.co_name}: send_email: ERROR, could not send email: {e}')
        return False
    else:
        log.info('{sys._getframe().f_code.co_name}: email server is not enabled')
        return False


def send_register_ack(**kwargs):
    try:
        if not msettings.get_configuration_setting('generic-enable-send-ack-email'):
            return False
        guest = mguest.get_first_not_sent_register_ack()
        if not guest:
            return False
        email_send_max_retries = msettings.get_configuration_setting('email-send-max-retries')
        if guest.reg_ack_nbr_tx >= email_send_max_retries:
            guest.enabled = False
            return False

        template = app.data.settings.get_json_template('student-email-response-template')
        if guest.status == guest.Status.E_REGISTERED:
            link = f'{msettings.get_configuration_setting("email-base-url")}/timeslot/register?code={guest.code}'
            email_subject = mformio.extract_sub_component(template, 'register-child-ack-ok-subject')['html']
            email_content = mformio.extract_sub_component(template, 'register-child-ack-ok-content', guest,
                                                      {'timeslot_registration_link': link})['html']
        elif guest.status == guest.Status.E_WAITINGLIST:
            email_subject = mformio.extract_sub_component(template, 'register-child-ack-waiting-list-subject')['html']
            email_content = mformio.extract_sub_component(template, 'register-child-ack-waiting-list-content', guest)['html']
        else:
            email_subject = mformio.extract_sub_component(template, 'register-child-ack-unregister-subject')['html']
            email_content = mformio.extract_sub_component(template, 'register-child-ack-unregister-content', guest)['html']
        email_subject = mformio.strip_html(email_subject)

        log.info(f'"{email_subject}" to {guest.email}, {guest.id}')
        ret = send_email(guest.email, email_subject, email_content)
        if ret:
            mguest.update_guest(guest, {"reg_ack_email_tx": True})
            mguest.update_guest(guest, {"reg_ack_nbr_tx": guest.reg_ack_nbr_tx + 1})
            return ret
        return False
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
    return False


def send_timeslot_register_ack(**kwargs):
    try:
        if not msettings.get_configuration_setting('generic-enable-send-ack-email'):
            return False
        guest = mguest.get_first_not_sent_timeslot_register_ack()
        if not guest:
            return False
        email_send_max_retries = msettings.get_configuration_setting('email-send-max-retries')
        if guest.tsl_ack_nbr_tx >= email_send_max_retries:
            guest.enabled = False
            return False

        template = app.data.settings.get_json_template('timeslot-email-response-template')
        link = f'{msettings.get_configuration_setting("email-base-url")}/timeslot/register?code={guest.code}'
        email_subject = mformio.extract_sub_component(template, 'timeslot-register-ack-ok-subject', guest)['html']
        email_content = mformio.extract_sub_component(template, 'timeslot-register-ack-ok-content', guest,
                                                      {'timeslot_registration_link': link})['html']
        email_subject = mformio.strip_html(email_subject)

        log.info(f'"{email_subject}" to {guest.email}')
        ret = send_email(guest.email, email_subject, email_content)
        if ret:
            mguest.update_guest(guest, {"tsl_ack_email_tx": True})
            mguest.update_guest(guest, {"tsl_ack_nbr_tx": guest.tsl_ack_nbr_tx + 1})
            return ret
        return False
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
    return False


def send_register_cancel(**kwargs):
    try:
        if not msettings.get_configuration_setting('generic-enable-send-ack-email'):
            return False
        guest = mguest.get_first_not_sent_cancel()
        if not guest:
            return False
        email_send_max_retries = msettings.get_configuration_setting('email-send-max-retries')
        if guest.email_tot_nbr_tx >= email_send_max_retries:
            guest.enabled = False
            return False
        guest.email_tot_nbr_tx += 1

        email_subject = msettings.get_configuration_setting('cancel-mail-subject-template')
        email_content = msettings.get_configuration_setting('cancel-mail-content-template')
        log.info(f'"{email_subject}" to {guest.email}')
        ret = send_email(guest.email, email_subject, email_content)
        if ret:
            guest.set('cancel_email_tx', True)
            guest.set('cancel_nbr_tx', guest.cancel_nbr_tx + 1)
            return ret
        return False
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
    return False


send_email_config = [
    {'function': send_register_ack, 'args': {}},
    {'function': send_timeslot_register_ack, 'args': {}},
    {'function': send_register_cancel, 'args': {}},
]


run_email_task = True
def send_email_task():
    nbr_sent_per_minute = 0
    while run_email_task:
        with flask_app.app_context():
            at_least_one_email_sent = True
            start_time = datetime.datetime.now()
            job_interval = msettings.get_configuration_setting('email-task-interval')
            emails_per_minute = msettings.get_configuration_setting('emails-per-minute')
            while at_least_one_email_sent:
                at_least_one_email_sent = False
                for send_email in send_email_config:
                    if run_email_task and msettings.get_configuration_setting('email-enable-send-email'):
                        ret = send_email['function'](**send_email['args'])
                        if ret:
                            nbr_sent_per_minute += 1
                            now = datetime.datetime.now()
                            delta = now - start_time
                            if (nbr_sent_per_minute >= emails_per_minute) and (delta < datetime.timedelta(seconds=60)):
                                time_to_wait = 60 - delta.seconds + 1
                                log.info(f'send_email_task: have to wait for {time_to_wait} seconds')
                                time.sleep(time_to_wait)
                                nbr_sent_per_minute = 0
                                start_time = datetime.datetime.now()
                            at_least_one_email_sent = True
        if run_email_task:
                now = datetime.datetime.now()
                delta = now - start_time
                if delta < datetime.timedelta(seconds=job_interval):
                    time_to_wait = job_interval - delta.seconds
                    time.sleep(time_to_wait)


def set_base_url(url):
    msettings.set_configuration_setting('email-base-url', url)


def stop_send_email_task():
    global run_email_task
    run_email_task = False


def start_send_email_task():
    running_job = email_scheduler.get_job('send_email_task')
    if running_job:
        email_scheduler.remove_job('send_email_task')
    email_scheduler.add_job('send_email_task', send_email_task)

start_send_email_task()

