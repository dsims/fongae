# -*- coding: utf-8 -*-
"""
    add support for multiple third party logins per user
"""

import urllib
from google.appengine.api import urlfetch
from google.appengine.api import memcache
from django.utils import simplejson as json
from tipfy import (REQUIRED_VALUE, get_config, url_for)
from tipfy.ext.auth import MultiAuthMixin
import logging
from model import Login

class ReallyMultiAuthMixin(MultiAuthMixin):

    def auth_create_login(self, user=None, login_id=None, **kwargs):
        logging.info("Creating login '%s' for user '%s'" % (login_id, user))
        login = Login.create(user, login_id, **kwargs)
        login.put()
        return login

    def auth_login_with_third_party(self, auth_id=None, login_id=None, remember=False, **kwargs):
        """Called to authenticate the user after a third party confirmed
        authentication.

        :param login_id:
            Authentication id, generally a combination of service name and
            user identifier for the service, e.g.: 'twitter:john'.
        :param remember:
            True if authentication should be persisted even if user leaves the
            current session (the "remember me" feature).
        :return:
            ``None``. This always authenticates the user.
        """
        # Load user entity.
        user = self.auth_get_user_entity(auth_id=auth_id, login_id=login_id)
        if user:
            # Set current user from datastore.
            self.auth_set_session(user.auth_id, user.session_id, remember)#, **kwargs)
        else:
            # Simply set a session; user will be created later if required.
			# put args in memcache
            data = memcache.get(login_id)
            if data is None:
                memcache.add(login_id, kwargs, 3600)
            else:
				memcache.set(login_id, kwargs, 3600)
            self.auth_set_session(auth_id, remember=remember, login_id=login_id)#, **kwargs)
        return user

    def auth_get_user_entity(self, username=None, auth_id=None, login_id=None):
        """Loads an user entity from datastore. Override this to implement
        a different loading method. This method will load the user depending
        on the way the user is being authenticated: for form authentication,
        username is used; for third party or App Engine authentication,
        auth_id is used.

        :param username:
            Unique username.
        :param auth_id:
            Unique authentication id.
        :return:
            A ``User`` model instance, or ``None``.
        """
        if login_id:
            return Login.get_user_by_login_id(login_id)
        elif auth_id:
            return self.auth_user_model.get_by_auth_id(auth_id)
        elif username:
            return self.auth_user_model.get_by_username(username)