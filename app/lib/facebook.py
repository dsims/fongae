# -*- coding: utf-8 -*-
"""
Tipfy's implementation of Facebook auth is old and being depricated.
This implements the latest OAuth2.0 scheme
    
"""
from __future__ import absolute_import
import functools
import logging
import urllib
import time
import binascii
import uuid

import cgi
import hashlib
import hmac
import urlparse


from google.appengine.api import urlfetch

from django.utils import simplejson

from tipfy import REQUIRED_VALUE, abort, redirect
from tipfy.ext.auth.oauth import OAuthMixin

#: Default configuration values for this module. Keys are:
#:
#: - ``consumer_key``: Key provided when you register an application with
#: - ``consumer_secret``: Secret provided when you register an application
default_config = {
    'api_key':    REQUIRED_VALUE,
    'app_secret': REQUIRED_VALUE,
}


class FacebookMixin(OAuthMixin):
    _OAUTH_REQUEST_TOKEN_URL = 'https://graph.facebook.com/oauth/request_token'
    _OAUTH_ACCESS_TOKEN_URL = 'https://graph.facebook.com/oauth/access_token'
    _OAUTH_AUTHORIZE_URL = 'https://graph.facebook.com/oauth/authorize'
    _OAUTH_AUTHENTICATE_URL = 'https://graph.facebook.com/oauth/authenticate'
    _OAUTH_NO_CALLBACKS = True
    _FB_AUTH_URL = 'http://www.friendsonnetflix.com/auth/facebook/' #'http://friendsonnetflix.com:8081/auth/facebook/' #http://www.friendsonnetflix.com/auth/facebook/

    def _facebook_consumer_key(self):
        return self.app.get_config(__name__, 'api_key')

    def _facebook_consumer_secret(self):
        return self.app.get_config(__name__, 'app_secret')

    def _oauth_consumer_token(self):
        return dict(
            key=self._facebook_consumer_key(),
            secret=self._facebook_consumer_secret())

    def authenticate_redirect(self):
        consumer_token = self._oauth_consumer_token()
        args = dict(
            redirect_uri=self._FB_AUTH_URL,
            client_id=consumer_token['key'])
			#scope='publish_stream,offline_access')
        return redirect(
            self._OAUTH_AUTHORIZE_URL + '?' +
            urllib.urlencode(args))

    def get_authenticated_user(self, verification_code, callback):
        consumer_token = self._oauth_consumer_token()
        args = dict(
            redirect_uri=self._FB_AUTH_URL,
            client_id=consumer_token['key'],
            client_secret=consumer_token['secret'],
            code=verification_code)
        url = self._OAUTH_ACCESS_TOKEN_URL + '?' + urllib.urlencode(args)
        response = urlfetch.fetch(url, deadline=10)
        access_token = _oauth_parse_responsex(response.content)
        return self._oauth_get_user(access_token['access_token'], callback)

    def facebook_request(self, path, callback, access_token=None,
                           post_args=None, **args):
        """Fetches the given API path

        If the request is a POST, post_args should be provided. Query
        string arguments should be given as keyword arguments.

		Many methods require an OAuth access token which you can obtain
        through authorize_redirect() and get_authenticated_user(). The
        user returned through that process includes an 'access_token'
        attribute that can be used to make authenticated requests via
        this method.
        """
        args['redirect_uri'] = self._FB_AUTH_URL
        args['access_token'] = access_token
        # Add the OAuth resource request signature if we have credentials
        url = 'https://graph.facebook.com' + path
        if access_token:
            all_args = {}
            all_args.update(args)
            all_args.update(post_args or {})
            args.update(all_args)

        if args:
            url += '?' + urllib.urlencode(args)

        try:
            if post_args is not None:
                response = urlfetch.fetch(url, method='POST',
                    payload=urllib.urlencode(post_args), deadline=10)
            else:
                response = urlfetch.fetch(url, deadline=10)
        except urlfetch.DownloadError, e:
            logging.exception(e)
            response = None

        return self._on_facebook_request(callback, response)

    def _on_facebook_request(self, callback, response):
        if not response:
            logging.warning('Could not get Facebook request token.')
            return callback(None)
        elif response.status_code < 200 or response.status_code >= 300:
            logging.warning('Invalid facebook response (%d): %s',
                response.status_code, response.content)
            return callback(None)

        return callback(simplejson.loads(response.content))

    def _oauth_get_user(self, access_token, callback):
        callback = functools.partial(self._parse_user_response, access_token, callback)
        return self.facebook_request(
            '/me',
            access_token=access_token, callback=callback)

    def _parse_user_response(self, access_token, callback, user):
        if user:
            user['access_token'] = access_token

        return callback(user)

    def _on_request_token_more(self, authorize_url, callback_uri, response):
        """
        :param authorize_url:
        :param callback_uri:
        :param response:
        :return:
        """
        if not response:
            logging.warning('Could not get OAuth request token.')
            abort(500)
        elif response.status_code < 200 or response.status_code >= 300:
            logging.warning('Invalid OAuth response (%d): %s',
                response.status_code, response.content)
            abort(500)

        request_token = _oauth_parse_responsex(response.content)
        data = '|'.join([request_token['key'], request_token['secret']])
        self.set_cookie('_oauth_request_token', data)
        args = dict(
            redirect_uri=self.request.url,
            oauth_consumer_key=self._facebook_consumer_key(),
            oauth_token=request_token['key']
            )
        if callback_uri:
            args['oauth_callback'] = urlparse.urljoin(
                self.request.url, callback_uri)

        return redirect(authorize_url + '?' + urllib.urlencode(args))

def _oauth_parse_responsex(body):
    """
    :param body:
    :return:
    """
    p = cgi.parse_qs(body, keep_blank_values=False)
    token = dict(access_token=p['access_token'][-1])

    # Add the extra parameters the Provider included to the token
    special = ('access_token')
    token.update((k, p[k][0]) for k in p if k not in special)
    return token
