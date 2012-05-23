# -*- coding: utf-8 -*-
"""
    config
    ~~~~~~

    Configuration settings.

    :copyright: 2009 by tipfy.org.
    :license: BSD, see LICENSE for more details.
"""
config = {}

# Configurations for the 'tipfy' module.
config['tipfy'] = {
    # Enable debugger. It will be loaded only in development.
    'middleware': [
        'tipfy.ext.debugger.DebuggerMiddleware',
    ],
    'apps_installed': [
    ],
}

config['tipfy.ext.auth'] = {
    'user_model' : 'model.MyUser',
}

config['tipfy.ext.session'] = {
    'secret_key': 'GUID',
    'cookie_name':     'FonN.session',
}

config['facebook'] = {
    'api_key':    'FBAPPAPIKEY',
    'app_secret': 'FBAPPSECRET',
    'app_id': 'FBAPPID'
}

config['tipfy.ext.auth.twitter'] = {
    'consumer_key':    'TWITTERKEY',
    'consumer_secret': 'TWITTERSECRET',
}

config['netflix'] = {
    'consumer_key':    'NETFLIXKEY',
    'consumer_secret': 'NETFLIXSECRET',
}
