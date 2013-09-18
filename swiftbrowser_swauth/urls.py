from django.conf.urls.defaults import patterns, url
from swiftbrowser_swauth.views import userlist, create_user, delete_user, change_password

urlpatterns = patterns('swiftbrowser_swauth.views',
    url(r'^users/$', userlist, name="userlist"),
    url(r'^delete_user/$', delete_user, name="delete_user"),
    url(r'^create_user/$', create_user, name="create_user"),
    url(r'^change_password/$', change_password, name="change_password"),
    )

