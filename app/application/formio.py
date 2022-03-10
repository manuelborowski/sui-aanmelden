import re, datetime
# noinspection PyUnresolvedReferences
from bleach.sanitizer import Cleaner


# iterate over the container, if a component contains a html or content property, replace the TAG(...) with
# the data provided by 'tag'
def fill_in_tags(component, flat):
    if component['type'] == 'container':
        for sub_component in component['components']:
            fill_in_tags(sub_component, flat)
    for key in ['html', 'content']:
        if key in component:
            all_tags = re.findall('TAG\([^(]*\)', component[key])
            for tag in all_tags:
                field = tag.split('(')[1].split(')')[0]
                link = None
                if '|' in field:
                    link, field = field.split('|')
                if field in flat:
                    if link:
                        component[key] = component[key].replace(tag, f"<a href='{str(flat[field])}'>{link}</a>")
                    else:
                        component[key] = component[key].replace(tag, str(flat[field]))


# find the given sub-component and update its tags.  Return the form because it is used to render the webpage
def prepare_sub_component(form, key, item ={}, additional_fields = {}):
    extract_sub_component(form, key, item, additional_fields)
    return form


# find the given sub-component and update its tags.  Return the component because it is used to send an email
def extract_sub_component(form, key, item ={}, additional_fields = {}):
    component = search_component(form, key)
    flat = item.flat() if item else {}
    flat.update(additional_fields)
    fill_in_tags(component, flat)
    component['hidden'] = False
    return component


# update the register-form:
# -hide the 'header'
# -unhide additional components
# -make all components 'not required'
# display the print-document-button
# update the url in the print-document-iframe
def prepare_for_edit(form, flat={}):
    def cb(component):
        if component['key'] == 'header':
            component['hidden'] = True
        if component['key'] == 'mail-confirm':
            component['hidden'] = True
            component['disabled'] = True
        if component['key'] == 'button-print-document':
            component['hidden'] = False
        if 'validate' in component and 'required' in component['validate']:
            component['validate']['required'] = False
        if 'tags' in component and 'show-when-edit' in component['tags']:
            component['hidden'] = False

    iterate_components_cb(form, cb)
    iframe = search_component(form, 'container-iframe-document')
    fill_in_tags(iframe, flat)
    iframe['hidden'] = False
    return form


def update_available_timeslots(timeslots, form, key):
    components = form['components']
    for component in components:
        if 'key' in component and component['key'] == key:
            values = []
            # component['components'] = []
            for timeslot in timeslots:
                if timeslot['available'] <= 0:
                    continue
                new = {
                    'label': timeslot['label'],
                    'value': timeslot['value'],
                    'shortcut': '',
                }
                values.append(new)
                if timeslot['default']:
                    component['defaultValue'] = timeslot['value']
            component['values'] = values
            return
        if 'components' in component:
            update_available_timeslots(timeslots, component, key)
    return


# search, in a given hierarchical tree of components, for a component with the given 'key'
def search_component(form, key):
    components = form['components']
    for component in components:
        if 'key' in component and component['key'] == key:
            return component
        if 'components' in component:
            found_component = search_component(component, key)
            if found_component: return found_component
    return None


#in a form, iterate over all components and execute callback for each component
def iterate_components_cb(form, cb):
    c_iter = iterate_components(form)
    try:
        while True:
            c = next(c_iter)
            cb(c)
    except StopIteration as e:
        pass


def iterate_components(form):
    components = form['components'] if 'components' in form else form['columns']
    for component in components:
        if 'components' in component or 'columns' in component:
            yield from iterate_components(component)
        else:
            yield component




def formiodate_to_datetime(formio_date):
    date_time = datetime.datetime.strptime(formio_date.split('+')[0], '%Y-%m-%dT%H:%M:%S')
    # date_time = datetime.datetime.strptime(':'.join(formio_date.split(':')[:2]), '%d/%m/%YT%H:%M')
    return date_time



def formiodate_to_date(formio_date):
    try:
        date = datetime.datetime.strptime(formio_date, "%Y-%m-%d") #bug in datetime component of formio?
    except:
        date = datetime.datetime.strptime(formio_date, "%d/%m/%Y")
    return date


def datetime_to_formio_datetime(date):
    string = f"{datetime.datetime.strftime(date, '%Y-%m-%dT%H:%M')}:00+01:00"
    return string


def strip_html(input):
    cleaner = Cleaner(tags=[], attributes={}, styles=[], protocols=[], strip=True, strip_comments=True, filters=None)
    return cleaner.clean(input)