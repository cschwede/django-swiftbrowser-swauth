from django.conf.urls import patterns, url
from swiftbrowser_swauth.views import accountlist, create_account, create_user, delete_account, delete_user, change_password, login, set_quota, userlist

urlpatterns = patterns('swiftbrowser_swauth.views',
    url(r'^login/$', login, name="login"),
    url(r'^delete_account/$', delete_account, name="delete_account"),
    url(r'^delete_user/(?P<account>.*)$', delete_user, name="delete_user"),
    url(r'^create_user/(?P<account>.*)$', create_user, name="create_user"),
    url(r'^create_account/$', create_account, name="create_account"),
    url(r'^change_password/$', change_password, name="change_password"),
    url(r'^set_quota/(?P<account>.*)$', set_quota, name="set_quota"),
    url(r'^accountlist/$', accountlist, name="accountlist"),
    url(r'^userlist/$', userlist, name="userlist"),
    url(r'^userlist/(?P<account>.*)$', userlist, name="userlist_with_account"),
    )

