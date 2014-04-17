import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-swiftbrowser-swauth',
    version='0.1',
    packages=['swiftbrowser_swauth'],
    include_package_data=True,
    license='Apache License (2.0)',
    description='Password change/User Admin addon for Django Swiftbrowser using Swauth',
    long_description=README,
    url='http://www.cschwede.com/',
    author='Christian Schwede',
    author_email='info@cschwede.de',
    install_requires=['django>=1.5', 'python-swiftclient', 'requests', 'django-swiftbrowser'],
    dependency_links=[
        "git+ssh://git@github.com/cschwede/django-swiftbrowser.git#egg=swiftbrowser"
    ],
    zip_safe=False,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache License (2.0)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
