# -*- coding: utf-8 -*-
"""
    tipfy.ext.auth.netflix
    ~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Netflix authentication scheme.

    adapted from facebook and twitter auths
    
"""
from __future__ import absolute_import
import functools
import logging
import urllib
import cgi

from google.appengine.api import urlfetch
from google.appengine.api.labs import taskqueue
from google.appengine.runtime import apiproxy_errors
from google.appengine.ext.deferred import defer

from django.utils import simplejson

from tipfy import REQUIRED_VALUE
from tipfy.ext.auth.oauth import OAuthMixin

from tipfy import abort, redirect
from model import NetflixTitle, NetflixRating, MyUser

default_config = {
    'consumer_key':    REQUIRED_VALUE,
    'consumer_secret': REQUIRED_VALUE,
}

class NetflixMixin(OAuthMixin):
    """A :class:`tipfy.RequestHandler` mixin that implements Netflix OAuth
    authentication.
    """
    _OAUTH_REQUEST_TOKEN_URL = 'http://api.netflix.com/oauth/request_token'
    _OAUTH_ACCESS_TOKEN_URL = 'http://api.netflix.com/oauth/access_token'
    _OAUTH_AUTHORIZE_URL = 'https://api-user.netflix.com/oauth/login'
    _OAUTH_AUTHENTICATE_URL = 'https://api-user.netflix.com/oauth/login'
    _OAUTH_APP_NAME = 'FriendsOnNetflix'
    _OAUTH_NO_CALLBACKS = True

    def _netflix_consumer_key(self):
        return self.app.get_config(__name__, 'consumer_key')

    def _netflix_consumer_secret(self):
        return self.app.get_config(__name__, 'consumer_secret')

    def _oauth_consumer_token(self):
        return dict(
            key=self._netflix_consumer_key(),
            secret=self._netflix_consumer_secret())

    def authenticate_redirect(self):
        """Just like authorize_redirect(), but auto-redirects if authorized.

        This is generally the right interface to use if you are using
        Twitter for single-sign on.
        """
        url = self._oauth_request_token_url()
        try:
            response = urlfetch.fetch(url, deadline=10)
        except urlfetch.DownloadError, e:
            logging.exception(e)
            response = None

        return self._on_request_token(self._OAUTH_AUTHENTICATE_URL, None,
            response)

    def netflix_request(self, path, callback, access_token=None,
                           post_args=None, **args):
        args['output'] = 'json'
        overridepost = False
        if(args.get('override') == 'POST'):
            args.pop('override')
            overridepost = True
            post_args = args
            args = {}
        # Add the OAuth resource request signature if we have credentials
        url = 'http://api.netflix.com' + path
        if access_token:
            #args['output'] = 'json'
            all_args = {}
            all_args.update(args)
            all_args.update(post_args or {})
            method = 'POST' if post_args is not None else 'GET'
            oauth = self._oauth_request_parameters(
                url, access_token, all_args, method=method)
            args.update(oauth)

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

        return self._on_netflix_request(callback, response)

    def _on_netflix_request(self, callback, response):
        if not response:
            logging.warning('Could not get Netflix request token.')
            return callback(None)
        elif response.status_code < 200 or response.status_code >= 300:
            logging.warning('Invalid Netflix response (%d): %s',
                response.status_code, response.content)
            return callback(None)
        #logging.warning('Netflix response (%d): %s', response.status_code, response.content)
        return callback(simplejson.loads(response.content))

    def _oauth_get_user(self, access_token, callback):
        callback = functools.partial(self._parse_user_response, callback)

        data = {
            'username': access_token['user_id'],
            'email': '',
            'provider_name': 'netflix',
            'provider_id': access_token['user_id'],
            'oauth_token':access_token['key'],
            'oauth_token_secret':access_token['secret'],
        }

        return callback(data)

        ##return self.netflix_request(
        ##    '/users/' + access_token['user_id'],
        ##    access_token=access_token, callback=callback)

    def _parse_user_response(self, callback, user):
        ##if user:
            #logging.warning('USER item: %s',user['user']['user_id'])
        ##    user['username'] = user['user']['user_id']

        return callback(user)

    def oauth_get_feeds(self, login_data, callback):
        callback = functools.partial(self._parse_feed_response, callback)
        access_token = {'key':login_data['oauth_token'],'secret':login_data['oauth_token_secret']}
        return self.netflix_request('/users/' + login_data['provider_id'] + '/feeds', access_token=access_token, callback=callback)

    def _parse_feed_response(self, callback, data):
        ratingsfeed = None;
        for link in data['resource']['link']:
            if link['rel'] == 'http://schemas.netflix.com/feed.ratings':
                ratingsfeed = link['href']
        return callback(ratingsfeed)

    def get_ratings_from_feed(self, feed, callback):
        callback = functools.partial(self._parse_ratingsfeed_response, callback)
        #change feed to json
        feed = unicode.replace(feed, 'output=atom', 'output=json')
        feed = feed + '&expand=synopsis'
        response = urlfetch.fetch(feed, deadline=10)
        return callback(simplejson.loads(response.content))

    def _parse_ratingsfeed_response(self, callback, data):
        return callback(data)
	
    def oauth_load_ratings(self, user, login, title_ids):
        callback = functools.partial(self._parse_ratings_response, user, False)
        access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
        return self.netflix_request('/users/' + login.provider_id + '/ratings/title', access_token=access_token, callback=callback, override='POST', method='GET', expand='synopsis', title_refs=title_ids )
        #return self.netflix_request('/users/' + login.provider_id + '/ratings/title/actual', access_token=access_token, callback=callback, expand='synopsis' )

    def oauth_load_ratings_recent(self, user, login):
        callback = functools.partial(self._parse_ratings_response, user, True)
        access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
        #return self.netflix_request('/users/' + login.provider_id + '/ratings/title', access_token=access_token, callback=callback, override='POST', method='GET', expand='synopsis', title_refs=title_ids )
        return self.netflix_request('/users/' + login.provider_id + '/ratings/title/actual', access_token=access_token, callback=callback, expand='synopsis' )

    def oauth_load_reviews(self, user, login, title_ids):
        callback = functools.partial(self._parse_reviews_response, user, False)
        access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
        return self.netflix_request('/users/' + login.provider_id + '/reviews', access_token=access_token, callback=callback, override='POST', method='GET', expand='synopsis', title_refs=title_ids )

    def oauth_load_reviews_recent(self, user, login):
        callback = functools.partial(self._parse_reviews_response, user, True)
        access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
        return self.netflix_request('/users/' + login.provider_id + '/reviews', access_token=access_token, callback=callback, expand='synopsis', updated_min=user.last_netflix_review )

    def _parse_ratings_response(self, user, reverse, data):
        if data is None or 'ratings_item' not in data['ratings']:
            if user.rating_count > 0:
                logging.warning('No ratings for user: %s' % user.key().name )
            return 0
        #logging.info('%d Ratings' % len(data['ratings']['ratings_item']) )

        ratingsdata = data['ratings']['ratings_item']
        item = None
        try:
            itr = iter(ratingsdata)
            for item in itr:
				if item:
					testvar = item.get('release_year');
        except:            
            ratingsdata = [ratingsdata] #add single item to a list so for loop is consistent
        
        numdone = 0
        itr = iter(ratingsdata)
        if reverse:
            itr = reversed(ratingsdata)
        for item in itr:
            try:
                if(item == '' or item.get('user_rating') is None or item.get('average_rating','0.0') == '0.0' or (int(item.get('updated', 0)) > 0 and int(item.get('updated', 0)) < user.last_netflix_rating)):
                    continue
            except:
                logging.info('item.get error, was %s' % item)
                continue

            title_id = None
            for link in item['link']:
                if link['rel'] == 'http://schemas.netflix.com/catalog/title':
                    title_id = link['href']
            title = NetflixTitle.get_by_key_name(title_id);
            if not title:
                addTask(url='/workeraddtitle', params={'title_id':title_id, 'item':simplejson.dumps(item)})
            else: #check if we already did this rating (its possible for a new rating to have the same updated date as a rating weve already seen)
                if (int(item.get('updated', 0)) > 0 and int(item.get('updated', 0)) == user.last_netflix_rating):
                    existingrating = NetflixRating(title=title, user=user).all().filter('user =', user).filter('title =', title).get()
                    if existingrating is not None:
                        continue
            numdone = numdone+1
            #task - add rating
            addTask(url='/workeraddrating', params={'user_key':user.key().name(), 'title_key':title_id, 'rating':item.get('user_rating'), 'submitted':item.get('updated')})
        if numdone > 0:
            addTask(url='/workersharerating', params={'user_key':user.key().name(), 'title_key':title_id})
            logging.info('%d Ratings Done' % numdone)
        return numdone

    def _parse_reviews_response(self, user, reverse, data):
        #logging.info('%s Reviews' % data['reviews']['number_of_results'] )

        if data is None or 'reviews' not in data or 'review' not in data['reviews']:
            return 0

        reviewdata = data['reviews']['review']
        if int(data['reviews']['number_of_results']) == 1:
			reviewdata = [reviewdata] #add single item to a list so for loop is consistent
        numdone = 0
        itr = iter(reviewdata)
        if reverse:
            itr = reversed(reviewdata)
        for item in itr:
            if(item == ''  or (int(item.get('updated', 0)) > 0 and int(item.get('updated', 0)) <= user.last_netflix_review)):
                continue
            numdone = numdone+1
            title_id = None
            for link in item['link']:
                if link['rel'] == 'http://schemas.netflix.com/catalog/title':
                    title_id = link['href']
            title = NetflixTitle.get_by_key_name(title_id);
            #logging.info('Movie %s' % item.get('title').get('regular'))
            if not title:
                addTask(url='/workeraddtitle', params={'title_id':title_id, 'item':simplejson.dumps(item)})
				#self._create_title(title_id, item, user)
            addTask(url='/workeraddreview', params={'user_key':user.key().name(), 'title_key':title_id, 'rating':item.get('user_rating','0.0'), 'review':item.get('write-up'), 'submitted':item.get('updated')})
        if numdone > 0:
            addTask(url='/workersharerating', params={'user_key':user.key().name(), 'title_key':title_id})
            logging.info('%d Reviews Done' % numdone)
        return numdone


    def oauth_load_history(self, user, login, page_num, callback, title_ids=[]):
        callback = functools.partial(self._parse_history_response, user, login, page_num, callback, title_ids)
        access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
        return self.netflix_request('/users/' + login.provider_id + '/rental_history', access_token=access_token, callback=callback, max_results=500, start_index=500 * page_num)

    def _parse_history_response(self, user, login, page_num, callback, title_ids, data):
        total = 0
        lastlink = None
        thislink = None
        try:
            for item in data['rental_history']['rental_history_item']:
                if item is None or 'link' not in item:
                    continue
                itemlinks = item['link']
                if 'href' in itemlinks:
			        itemlinks = [itemlinks] #add single item to a list so for loop is consistent
                lastlink = thislink
                thislink = item

                total = total+1
                for link in itemlinks:
                    if link['rel'] == 'http://schemas.netflix.com/catalog/title.season':
                        if link['href'] in title_ids:
                            continue
                        title_ids.append(link['href'])
                    if link['rel'] == 'http://schemas.netflix.com/catalog/title':
                        if link['href'].find('titles/programs') > -1 or link['href'].find('titles/discs') > -1:
                            continue
                        if link['href'] in title_ids:
                            break
                        title_ids.append(link['href'])
        except Exception, e:
            logging.error('lastlink %s' % lastlink)
            logging.error('thislink %s' % thislink)
            logging.error('rental_history %s' % data['rental_history'])
            logging.exception(e)
            return None

        #still have more left
        logging.info('%d Total History Items in this Request' % total)
        if(total == 500):
            return self.oauth_load_history(user, login, page_num+1, callback, title_ids)

        title_ids.reverse()

        #if there were alot, import them in batches
        if(len(title_ids) > 500):
            grouped = list(chunks(title_ids, 100))
            for chunk in grouped:
                addTask(url='/workeraddhistory', params={'user_key':user.key().name(), 'title_ids':",".join(chunk)})
            return callback(len(title_ids), 0)

        fulltotal = self.oauth_load_ratings(user, login, ",".join(title_ids) )
        #numreviews = self.oauth_load_reviews(user, login, ",".join(title_ids) )
        numreviews = 0
        #get recent updated dates
        self.oauth_load_ratings_recent(user, login)

        return callback(fulltotal, numreviews)

    def authorize_redirect_more(self, callback_uri=None, oauth_authorize_url=None, app_name=None):
        """Redirects the user to obtain OAuth authorization for this service.
        passing a callback and app name
        """
        if callback_uri and getattr(self, '_OAUTH_NO_CALLBACKS', False):
            raise Exception('This service does not support oauth_callback')

        oauth_authorize_url = oauth_authorize_url or self._OAUTH_AUTHORIZE_URL

        url = self._oauth_request_token_url()
        try:
            response = urlfetch.fetch(url, deadline=10)
        except urlfetch.DownloadError, e:
            logging.exception(e)
            response = None

        return self._on_request_token_more(oauth_authorize_url, callback_uri,
            response, app_name)


    def _on_request_token_more(self, authorize_url, callback_uri, response, app_name):
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
            application_name=self._OAUTH_APP_NAME,
            oauth_callback=self.request.url,
            oauth_consumer_key=self._netflix_consumer_key(),
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
    token = dict(key=p['oauth_token'][0], secret=p['oauth_token_secret'][0])

    # Add the extra parameters the Provider included to the token
    special = ('oauth_token', 'oauth_token_secret')
    token.update((k, p[k][0]) for k in p if k not in special)
    return token

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def addTask(url, params={}, name=None):
    try:
        task = taskqueue.Task(url=url, params=params)
        if name:
            task = taskqueue.Task(name=name, url=url, params=params)
        task.add()
    except taskqueue.TaskAlreadyExistsError:
        pass
    except taskqueue.TransientError, e:
        logging.exception("adding Task failed with a TransientError")
        addTask(url, params, name)
    except taskqueue.TaskTooLargeError :
		logging.exception('adding Task failed with TaskTooLargeError')
    except apiproxy_errors.OverQuotaError, e:
        #but keep going
        logging.exception("adding Task failed with a OverQuotaError")