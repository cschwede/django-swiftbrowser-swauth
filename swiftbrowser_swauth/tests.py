#!/usr/bin/python
# -*- coding: utf8 -*-
#pylint:disable=E1103

import json
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
        self.status_code = status_code
        self.content = content
        

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
        resp = self.client.post(reverse('create_user', kwargs={'account': 'account'}), {
            'new_username': "new_username",
            'new_password': 'new_password',
            'new_password2': 'new_password',
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
        resp = self.client.post(reverse('delete_user', kwargs={'account': 'account'}), {
            'password': 'password',
            'username': 'username',
            })
        
        requests.delete.assert_called_with('http://127.0.0.1:8080/v2//account/username', 
                                        verify=False,
                                        headers={'X-Auth-Admin-Key': u'password',
                                                 'X-Auth-Admin-User': 'account:user'})
 

class AccountTest(TestCase):
    def setUp(self):
        self.client = Client()

        # Need a logged in user to modify the session
        User.objects.create_superuser('user', 'user@none.com', 'password')
        self.client.login(username='user', password='password')

        session = self.client.session
        session['username'] = 'test:tester'
        session['auth_token'] = '123'
        session['is_reseller'] = True
        session.save()
    
    def test_list_accounts(self):
        data = json.dumps({
            'accounts' : [{'name': 'test'}],
            'services': {'storage': {'local': 'http://127.0.0.1/'}}})
        requests.get = mock.Mock(return_value=DummyResponse(201, content=data))
        account = {'x_account_bytes_used': '3'}
        swiftclient.client.get_account = mock.Mock(return_value=(account, None))
        resp = self.client.post(reverse('accountlist'), {'password': 'testing'})

        self.assertEqual(resp.context['username'], u'tester')
        self.assertEqual(resp.context['disk_usage'],
            {'space_total': 0.3, 'space_used': 3, 'percentage': 1000.0}) 
        self.assertEqual(resp.context['accounts'],
            {u'test': {'x_account_bytes_used': '3'}})
        self.assertEqual(resp.status_code, 200)

    def test_list_users(self):
        data = json.dumps({
            'users': [{'name': 'testuser'}],
            'groups': [],
            'accounts' : [{'name': 'test'}],
            'services': {'storage': {'local': 'http://127.0.0.1/'}}})
        requests.get = mock.Mock(return_value=DummyResponse(200, content=data))
        account = {'x_account_bytes_used': '3'}
        swiftclient.client.get_account = mock.Mock(return_value=(account, None))
        resp = self.client.post(reverse('userlist'), {'password': 'testing'})
        self.assertEqual(resp.context['account'], 'test')
        self.assertEqual(resp.context['access'], True)
        self.assertEqual(resp.context['username'], 'tester')
        self.assertEqual(resp.status_code, 200)

    def test_create_account(self):
        data = json.dumps({
            'accounts' : [{'name': 'test'}],
            'services': {'storage': {'local': 'http://127.0.0.1/'}}})
        requests.get = mock.Mock(return_value=DummyResponse(201, content=data))
        requests.put = mock.Mock(return_value=DummyResponse(201))
        resp = self.client.post(reverse('create_account'),
            {'new_account': 'accountname', 'account_password': 'secret'})
        requests.put.assert_called_with(
            u'http://127.0.0.1:8080/v2//accountname', verify=False,
            headers={'X-Auth-Admin-Key': u'secret',
                     'X-Auth-Admin-User': u'test:tester'})
        self.assertEqual(resp.status_code, 200)

    def test_delete_account(self):
        data = json.dumps({
            'accounts' : [{'name': 'test'}],
            'services': {'storage': {'local': 'http://127.0.0.1/'}}})
        requests.get = mock.Mock(return_value=DummyResponse(201, content=data))
        requests.delete = mock.Mock(return_value=DummyResponse(201))
        resp = self.client.post(reverse('delete_account'),
            {'account': 'accountname', 'password': 'secret'})
        requests.delete.assert_called_with(
            u'http://127.0.0.1:8080/v2//accountname', verify=False,
            headers={'X-Auth-Admin-Key': u'secret',
                     'X-Auth-Admin-User': u'test:tester'})
        self.assertEqual(resp.status_code, 302)
