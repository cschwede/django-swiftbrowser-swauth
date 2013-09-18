""" Forms for swiftbrowser.accounts """
# -*- coding: utf-8 -*-
#pylint:disable=R0924
from django import forms


class CreateUserForm(forms.Form):
    """ Credential Form """
    new_username = forms.CharField(max_length=100)
    new_password = forms.CharField(max_length=100)
    account_password = forms.CharField(widget=forms.PasswordInput)
    admin = forms.BooleanField(required=False)


class DeleteUserForm(forms.Form):
    """ Credential Form """
    username = forms.CharField(max_length=100)
    password = forms.CharField(widget=forms.PasswordInput)


class PasswordForm(forms.Form):
    """ Credential Form """
    password = forms.CharField(widget=forms.PasswordInput)


class ChangePasswordForm(forms.Form):
    """ Credential Form """
    old_password = forms.CharField(widget=forms.PasswordInput)
    new_password = forms.CharField(widget=forms.PasswordInput)
    new_password2 = forms.CharField(widget=forms.PasswordInput)
