# -*- coding: utf-8 -*-
import string
import random
import json

import requests

from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.conf import settings
from django.contrib import messages

from swiftbrowser_swauth.forms import CreateUserForm, PasswordForm, DeleteUserForm, ChangePasswordForm


def create_user(request):
    """ Creates a new swauth account. """
    chars=string.ascii_letters + string.digits
    random_username = ''.join(random.choice(chars) for x in range(8))
    random_password = ''.join(random.choice(chars) for x in range(16))
    
    form = CreateUserForm(request.POST or None)

    if form.is_valid():
        new_username = form.cleaned_data['new_username']
        new_password = form.cleaned_data['new_password']

        account_password = form.cleaned_data['account_password']
        admin = form.cleaned_data['admin']

        username = request.session.get('username', '')
 
        account = username.split(':')[0]
        url = "%s/%s/%s" % (settings.SWAUTH_URL, account, new_username)

        headers = {'X-Auth-Admin-User': username,
                   'X-Auth-Admin-Key': account_password,
                   'X-Auth-User-Key': new_password}
        if admin:
            headers['X-Auth-User-Admin'] = 'true'
 
        resp = requests.put(url, headers=headers, verify=False)
        if resp.status_code == 403:
            message = "Access denied. Account creation failed."
            messages.add_message(request, messages.ERROR, message)
        if resp.status_code == 201:
            message = "Account created."
            messages.add_message(request, messages.INFO, message)
        return userlist_data(request, account_password)

    return render_to_response('create_user.html',
                              {'form': form, 
                               'random_username': random_username,
                               'random_password': random_password,
                               'session': request.session,
                              },
                              context_instance=RequestContext(request))


def change_password(request):
    """ Creates a new swauth account. """
    form = ChangePasswordForm(request.POST or None)
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

            headers = {'X-Auth-Admin-User': request.session['username'],
                       'X-Auth-Admin-Key': old_password,
                       'X-Auth-User-Key': new_password,
                       'X-Auth-User-Admin': 'true'}
 
            resp = requests.put(url, headers=headers, verify=False)
            
            if resp.status_code == 403:
                message = "Access denied. Password change failed."
                messages.add_message(request, messages.ERROR, message)
            
            if resp.status_code == 201:
                message = "Password changed"
                messages.add_message(request, messages.INFO, message)

    return render_to_response('change_password.html',
                              {'form': form, 
                               'session': request.session,
                              },
                              context_instance=RequestContext(request))


def delete_user(request):
    """ Tries to login user and sets session data """
    username = request.session['username']

    form = DeleteUserForm(request.POST or None)
    if form.is_valid():
        user = form.cleaned_data['username']
        password = form.cleaned_data['password']

        account = username.split(':')[0]
        url = "%s/%s/%s" % (settings.SWAUTH_URL, account, user)

        headers = {'X-Auth-Admin-User': username, 'X-Auth-Admin-Key': password}

        resp = requests.delete(url, headers=headers, verify=False)
        if resp.status_code == 204:
            message = "User <u>%s</u> deleted." % (user, )
            messages.add_message(request, messages.INFO, message)
        else:
            message = "Deletion of user <u>%s</u> failed." % (user, )
            messages.add_message(request, messages.ERROR, message)
        return userlist_data(request, password)

    return redirect(userlist)

def userlist_data(request, password=None):
    """ Tries to login user and sets session data"""
    users = None

    try:
        username = request.session['username']
    except KeyError:
        return redirect('/')
    
    if password:
        account = username.split(':')[0]
        account_url = "%s/%s" % (settings.SWAUTH_URL, account)
    
        headers = {'X-Auth-Admin-User': username,
                   'X-Auth-Admin-Key': password}

        resp = requests.get(account_url, headers=headers, verify=False)
        if resp.status_code != 200:
            message = "Can't get user list."
            messages.add_message(request, messages.ERROR, message)  
        else:
            data = json.loads(resp.content)['users']
            users = []
    
            for user in data:
                user_url = "%s/%s" % (account_url, user['name'])
                resp = requests.get(user_url, headers=headers, verify=False)
                if resp.status_code == 200:
                    users.append((user['name'], False))
                else:
                    users.append((user['name'], True))

    return render_to_response('userlist.html',
                              {'users': users,
                               'session': request.session,
                               'username': username.split(':')[1]},
                              context_instance=RequestContext(request))


def userlist(request):
    """ Tries to login user and sets session data"""
    password = None

    form = PasswordForm()
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']

    return userlist_data(request, password)
