#!/usr/bin/python
# -*- coding: utf8 -*-
#pylint:disable=E1103

import mock
import random

from django.test import TestCase
from django.core.urlresolvers import reverse
from django.test.client import Client
from django.contrib.auth.models import User

import requests
import swiftclient
import swiftbrowser


class DummyResponse(object):
    def __init__(self, status_code=None, content=None):
        self._status_code = status_code
        self._content = content

    def status_code(self):
        return self._status_code

    def content(self):
        return self._content


class MockTest(TestCase):
    """ Basic unit tests for swiftbrowser-swauth """
    
    def setUp(self):
        self.client = Client()

        # Need a logged in user to modify the session
        User.objects.create_superuser('user', 'user@none.com', 'password')
        self.client.login(username='user', password='password')

        session = self.client.session
        session['username'] = 'account:user'
        session.save()

    def test_create_user(self):

        requests.put = mock.Mock(return_value=DummyResponse(201))
        requests.get = mock.Mock(return_value=DummyResponse(201, content="{}"))
        resp = self.client.post(reverse('create_user'), {
            'new_username': "new_username",
            'new_password': 'new_password',
            'account_password': 'account_password',
            'admin': 'Off',
            })
        
        requests.put.assert_called_with('http://127.0.0.1:8080/v2//account/new_username', 
                                        verify=False,
                                        headers={'X-Auth-User-Key': u'new_password',
                                                 'X-Auth-Admin-Key': u'account_password',
                                                 'X-Auth-User-Admin': 'true',
                                                 'X-Auth-Admin-User': 'account:user'})
        
    def test_change_password(self):

        requests.put = mock.Mock(return_value=DummyResponse(201))
        resp = self.client.post(reverse('change_password'), {
            'old_password': 'old_password',
            'new_password': 'new_password',
            'new_password2': 'new_password',
            })
        
        requests.put.assert_called_with('http://127.0.0.1:8080/v2//account/user', 
                                        verify=False,
                                        headers={'X-Auth-User-Key': u'new_password',
                                                 'X-Auth-Admin-Key': u'old_password',
                                                 'X-Auth-User-Admin': 'true',
                                                 'X-Auth-Admin-User': 'account:user'})
        

    def test_delete_user(self):

        requests.delete = mock.Mock(return_value=DummyResponse(204))
        requests.get = mock.Mock(return_value=DummyResponse(201, content="{}"))
        resp = self.client.post(reverse('delete_user'), {
            'password': 'password',
            'username': 'username',
            })
        
        requests.delete.assert_called_with('http://127.0.0.1:8080/v2//account/username', 
                                        verify=False,
                                        headers={'X-Auth-Admin-Key': u'password',
                                                 'X-Auth-Admin-User': 'account:user'})
 

