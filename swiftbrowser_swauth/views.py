# -*- coding: utf-8 -*-
import json
import locale
import logging
import random
import string

import requests

from django.conf import settings
from django.contrib import messages
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.utils.translation import ugettext as _

from swiftbrowser_swauth import forms
from swiftclient import client

from swiftbrowser.forms import LoginForm
from swiftbrowser.utils import replace_hyphens
from swiftbrowser.views import containerview


logger = logging.getLogger(__name__)


def login(request):
    request.session.flush()
    form = LoginForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        try:
            (storage_url, auth_token) = client.get_auth(
                settings.SWIFT_AUTH_URL, username, password)
            request.session['auth_token'] = auth_token
            request.session['storage_url'] = storage_url
            request.session['username'] = username

            if _is_reseller_admin(username, password):
                request.session['is_reseller'] = True
            return redirect(containerview)

        except client.ClientException as e:
            messages.add_message(request, messages.ERROR, ("Login failed."))
            logger.error("Cannot login: %s" % str(e))

    return render_to_response('login.html', {'form': form, },
                              context_instance=RequestContext(request))


def create_user(request, account=None):
    chars = string.ascii_letters + string.digits
    random_username = ''.join(random.choice(chars) for x in range(8))
    random_password = ''.join(random.choice(chars) for x in range(16))

    form = forms.CreateUserForm(request.POST or None)

    if form.is_valid():
        new_username = form.cleaned_data['new_username']
        new_password = form.cleaned_data['new_password']
        new_password2 = form.cleaned_data['new_password2']

        if new_password != new_password2:
            message = "New passwords are not the same."
            messages.add_message(request, messages.ERROR, message)
        else:
            account_password = form.cleaned_data['account_password']
            admin = form.cleaned_data['admin']

            user = request.session.get('username', '')

            if account is None:
                account = user.split(':')[0]

            url = "%s/%s/%s" % (settings.SWAUTH_URL, account, new_username)

            headers = {'X-Auth-Admin-User': user,
                       'X-Auth-Admin-Key': account_password,
                       'X-Auth-User-Key': new_password}
            if admin:
                headers['X-Auth-User-Admin'] = 'true'

            success = True
            try:
                resp = requests.put(url, headers=headers, verify=False)
                if resp.status_code == 403:
                    message = "Access denied. User creation failed."
                    messages.add_message(request, messages.ERROR, message)
                    success = False
                if resp.status_code == 201:
                    message = "User created."
                    messages.add_message(request, messages.INFO, message)
            except requests.RequestException as e:
                logger.error("Cannot create user %s. Reason: %s" % (new_username, str(e)))
                messages.add_message(request, messages.ERROR,  "Cannot create user. Internal error.")
                success = False

            if success:
                return userlist(request, account_password, account)

    return render_to_response(
        'create_user.html', {
            'form': form,
            'random_username': random_username,
            'random_password': random_password,
            'session': request.session,
            'account': account,
        }, context_instance=RequestContext(request))


def create_account(request):
    chars = string.ascii_letters + string.digits
    random_account = ''.join(random.choice(chars) for x in range(8))

    form = forms.CreateAccountForm(request.POST or None)

    if form.is_valid():
        new_account = form.cleaned_data['new_account']
        account_password = form.cleaned_data['account_password']
        quota = form.cleaned_data['quota']
        if quota:
            quota *= 1024*1024*1024

        user = request.session.get('username', '')

        url = "%s/%s" % (settings.SWAUTH_URL, new_account)

        headers = {'X-Auth-Admin-User': user,
                   'X-Auth-Admin-Key': account_password}

        success = True
        try:
            resp = requests.put(url, headers=headers, verify=False)
            if resp.status_code == 403:
                message = "Access denied. Account creation failed."
                messages.add_message(request, messages.ERROR, message)
                success = False
            if resp.status_code == 201:
                message = "Account created."
                messages.add_message(request, messages.INFO, message)
        except request.RequestException as e:
            logger.error("Cannot create account %s. Reason: %s" % (new_account, str(e)))
            message = "Account creation failed due to an internal error."
            messages.add_message(request, messages.ERROR, message)
            success = False

        if success and quota:
            try:
                auth_token = request.session['auth_token']
                result = _set_quota(quota, new_account, user, account_password, auth_token)
                if not result:
                    messages.add_message(request, messages.ERROR, _("Can't set quota."))
            except KeyError:
                message = "User is not logged in."
                messages.add_message(request, messages.ERROR, message)

        if success:
            return accountlist(request, account_password)

    return render_to_response(
        'create_account.html', {
            'form': form,
            'random_account': random_account,
            'session': request.session,
        }, context_instance=RequestContext(request))


def change_password(request):
    form = forms.ChangePasswordForm(request.POST or None)
    if form.is_valid():
        old_password = form.cleaned_data['old_password']
        new_password = form.cleaned_data['new_password']

        new_password2 = form.cleaned_data['new_password2']

        if new_password != new_password2:
            message = "New passwords are not the same."
            messages.add_message(request, messages.ERROR, message)
        else:
            account = request.session.get('username', '').split(':')[0]
            username = request.session.get('username', '').split(':')[1]

            url = "%s/%s/%s" % (settings.SWAUTH_URL, account, username)

            headers = {'X-Auth-User-Key':  new_password,
                       'X-Auth-User-Admin': 'true'}

            resp = None
            try:
                if 'is_reseller' in request.session:
                    #check if old password is correct
                    if _is_reseller_admin("%s:%s" % (account, username), old_password):
                        super_admin_username = settings.SUPER_ADMIN_USER.split(':')[1]
                        headers.update(
                            {'X-Auth-Admin-User': super_admin_username,
                             'X-Auth-Admin-Key':  settings.SUPER_ADMIN_KEY,
                             'X-Auth-User-Reseller-Admin': 'true'})
                        resp = requests.put(url, headers=headers, verify=False)
                    else:
                        message = "Access denied. Password change failed."
                        messages.add_message(request, messages.ERROR, message)
                else:
                    headers.update(
                        {'X-Auth-Admin-User': request.session['username'],
                         'X-Auth-Admin-Key': old_password})
                    resp = requests.put(url, headers=headers, verify=False)

                if resp and resp.status_code == 403:
                    message = "Access denied. Password change failed."
                    messages.add_message(request, messages.ERROR, message)

                if resp and resp.status_code == 201:
                    message = "Password changed"
                    messages.add_message(request, messages.INFO, message)
            except request.RequestException as e:
                logger.error("Cannot change password for user %s:%s. Reason: %s" % (account, username, str(e)))
                message = "Password change failed due to an internal error."
                messages.add_message(request, messages.ERROR, message)

    return render_to_response(
        'change_password.html', {
            'form': form,
            'session': request.session,
        }, context_instance=RequestContext(request))


def delete_account(request):
    user = request.session['username']

    form = forms.DeleteAccountForm(request.POST or None)
    if form.is_valid():
        account = form.cleaned_data['account']
        password = form.cleaned_data['password']

        url = "%s/%s" % (settings.SWAUTH_URL, account)

        headers = {'X-Auth-Admin-User': user, 'X-Auth-Admin-Key': password}

        success = True
        try:
            resp = requests.delete(url, headers=headers, verify=False)
            if resp.status_code == 204:
                message = "Account <u>%s</u> deleted." % (account, )
                messages.add_message(request, messages.INFO, message)
            else:
                message = "Deletion of account <u>%s</u> failed." % (account, )
                messages.add_message(request, messages.ERROR, message)
                success = False
        except request.RequestException as e:
            logger.error("Cannot delete account %s. Reason: %s" % (account, str(e)))
            message = "Deletion of account <u>%s</u> failed due to an internal error." % (account, )
            messages.add_message(request, messages.ERROR, message)
            success = False

        if success:
            return accountlist(request, password)

    return redirect('/')


def delete_user(request, account=None):
    username = request.session['username']

    form = forms.DeleteUserForm(request.POST or None)
    if form.is_valid():
        user = form.cleaned_data['username']
        password = form.cleaned_data['password']

        if account is None:
            account = username.split(':')[0]

        url = "%s/%s/%s" % (settings.SWAUTH_URL, account, user)

        headers = {'X-Auth-Admin-User': username, 'X-Auth-Admin-Key': password}

        success = True
        try:
            resp = requests.delete(url, headers=headers, verify=False)
            if resp.status_code == 204:
                message = "User <u>%s</u> deleted." % (user, )
                messages.add_message(request, messages.INFO, message)
            else:
                message = "Deletion of user <u>%s</u> failed." % (user, )
                messages.add_message(request, messages.ERROR, message)
                success = False
        except request.RequestException as e:
            logger.error("Cannot delete user %s. Reason: %s" % (user, str(e)))
            message = "Deletion of user <u>%s</u> failed due to an internal error." % (user, )
            messages.add_message(request, messages.ERROR, message)
            success = False

        if success:
            return userlist(request, password, account)

    return redirect('/')


def accountlist_data(request, password):
    accounts = None

    try:
        username = request.session['username']
        auth_token = request.session['auth_token']
    except KeyError:
        return redirect('/')

    disk_usage = {}

    #get list of all accounts, if the password is valid
    if password:
        if _is_reseller_admin(username, password):
            try:
                url = "%s" % (settings.SWAUTH_URL)
                headers = {'X-Auth-Admin-User': username, 'X-Auth-Admin-Key': password}
                resp = requests.get(url, headers=headers, verify=settings.VERIFY_SSL)
                userdata = json.loads(resp.content)

                accounts = {}
                for a in userdata['accounts']:
                    if a['name'][0] != '.':
                        accounts[a['name']] = {}

                disk_usage['space_used'] = 0
                for account in accounts:
                    account_stat = _get_account_stat(account, username, password, auth_token)
                    if account_stat:
                        accounts[account] = account_stat
                        disk_usage['space_used'] += int(account_stat['x_account_bytes_used'])
                disk_usage['space_total'] = int(settings.DISK_SPACE) * 0.9 / 3
                disk_usage['percentage'] = 100 * float(disk_usage['space_used']) / disk_usage['space_total']
            except client.ClientException as e:
                logger.error("Cannot authenticate as super_admin. Reason: %s" % str(e))
                messages.add_message(request, messages.ERROR, "Can't get account list due to an internal error.")
        else:
            messages.add_message(request, messages.ERROR, "Can't get account list.")
    return render_to_response(
        'accountlist.html', {
            'accounts': accounts,
            'session': request.session,
            'username': username.split(':')[1],
            'disk_usage': disk_usage,
        }, context_instance=RequestContext(request))


def accountlist(request, password=None):
    form = forms.PasswordForm()
    if request.method == 'POST':
        form = forms.PasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']

    return accountlist_data(request, password)


def userlist(request, password=None, account=None):
    form = forms.PasswordForm()
    if request.method == 'POST':
        form = forms.PasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']

    return userlist_data(request, password, account)


def userlist_data(request, password, account):
    users = None
    access = False

    try:
        admin_user = request.session['username']
    except KeyError:
        return redirect('/')

    if account is None:
        account = admin_user.split(':')[0]

    if password:
        account_url = "%s/%s" % (settings.SWAUTH_URL, account)

        headers = {'X-Auth-Admin-User': admin_user, 'X-Auth-Admin-Key': password}

        try:
            resp = requests.get(account_url, headers=headers, verify=False)

            if resp.status_code != 200:
                message = "Can't get user list."
                messages.add_message(request, messages.ERROR, message)
            else:
                data = json.loads(resp.content)['users']
                users = []
                access = True

                for user in data:
                    user_url = "%s/%s" % (account_url, user['name'])
                    try:
                        resp = requests.get(user_url, headers=headers, verify=False)
                        if 'is_reseller' in request.session:
                            if resp.status_code == 200:
                                userdata = json.loads(resp.content)
                                label = ''
                                if '.admin' in (g['name'] for g in userdata['groups']):
                                    label = 'Admin'
                                users.append((user['name'], label))
                            else:
                                users.append((user['name'], 'Reseller'))
                        else:
                            if resp.status_code == 200:
                                users.append((user['name'], ''))
                            else:
                                users.append((user['name'], 'Admin'))
                    except requests.RequestException as e:
                        logger.error("Cannot retrieve userdata of user %s. Reason %s" % (user['name'], str(e)))
        except requests.RequestException as e:
                logger.error("Cannot retrieve account_url %s. Reason %s" % (account_url, str(e)))
                message = "Can't get user list."
                messages.add_message(request, messages.ERROR, message)

    return render_to_response(
        'userlist.html', {
            'users': users,
            'session': request.session,
            'username': admin_user.split(':')[1],
            'account': account,
            'access': access
        }, context_instance=RequestContext(request))


def set_quota(request, account):
    user = request.session['username']

    form = forms.SetQuotaForm(request.POST or None)
    if form.is_valid():
        quota = form.cleaned_data['quota']

        if quota:
            quota *= 1024*1024*1024
        else:
            quota = ''

        password = form.cleaned_data['password']

        success = True
        try:
            auth_token = request.session['auth_token']
            success = _set_quota(quota, account, user, password, auth_token)
            if not success:
                messages.add_message(request, messages.ERROR, _("Can't set quota."))
        except KeyError:
            message = "User is not logged in."
            messages.add_message(request, messages.ERROR, message)
            success = False

        if success:
            return accountlist(request, password)

    return redirect('/')


def get_storage_url(username, password, account):
    url = "%s/%s" % (settings.SWAUTH_URL, account)
    headers = {'X-Auth-Admin-User': username, 'X-Auth-Admin-Key': password}
    try:
        resp = requests.get(url, headers=headers, verify=False)
    except (requests.RequestException) as e:
        logger.error("Cannot retrieve storage url. %s" % str(e))
        return None
    # By default swauth uses
    # default_swift_cluster = local#http://127.0.0.1:8080/v1
    # If you use a different setting, you need to define the clustername here
    # In the default settings this is local
    if hasattr(settings, 'CLUSTERNAME'):
        clustername = settings.CLUSTERNAME
    else:
        clustername = 'local'
    return json.loads(resp.content).get('services', {}).get('storage', {}).get(clustername)

 
def _get_account_stat(account, admin_username, admin_password, auth_token):
    storage_url = get_storage_url(admin_username, admin_password, account)
    try:
        account_stat, _ = client.get_account(storage_url, auth_token)
    except client.ClientException as e:
        logger.error("Cannot retrieve account data. %s" % str(e))
        return None
    return replace_hyphens(account_stat)


def _set_quota(quota, account, admin_username, admin_password, auth_token):
    storage_url = get_storage_url(admin_username, admin_password, account)
    try:
        client.post_account(
            storage_url,
            auth_token,
            {'x-account-meta-quota-bytes': str(quota)})
    except client.ClientException as e:
        logger.error(
            "Cannot set quota for account %s. Error: %s" % (account, str(e)))
        return False
    return True


def _is_reseller_admin(user, password):
    headers = {'X-Auth-Admin-User': user, 'X-Auth-Admin-Key': password}
    try:
        get_storage_url(user, password, account='')
        return True
    except requests.RequestException as e:
        logger.error("Cannot verify if user is reseller. %s" % str(e))
    return False
