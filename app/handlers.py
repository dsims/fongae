from django.utils import simplejson
import logging
import functools
import sys
from datetime import datetime, timedelta
from google.appengine.ext import db
from google.appengine.api import urlfetch
from google.appengine.api.labs import taskqueue
from google.appengine.api import memcache
from google.appengine.runtime import apiproxy_errors

from tipfy import (RequestHandler, RequestRedirect, Response, abort,
    cached_property, redirect, url_for, render_json_response)
from tipfy.ext.auth import MultiAuthMixin, login_required, user_required
from facebook import FacebookMixin
from tipfy.ext.auth.friendfeed import FriendFeedMixin
from tipfy.ext.auth.google import GoogleMixin
from tipfy.ext.auth.twitter import TwitterMixin
from tipfy.ext.jinja2 import Jinja2Mixin
from tipfy.ext.session import AllSessionMixins, SessionMiddleware
from tipfy.ext.wtforms import Form, fields, validators
from tipfy.ext.taskqueue import DeferredHandler

from netflix import NetflixMixin
from reallymultiauth import ReallyMultiAuthMixin
from model import Friend, Login, NetflixTitle, NetflixRating, FollowerIndex, NetflixRatingIndex, MyUser, TwitterFriendsTBD, FacebookFriendsTBD, FriendNetflixTitleRatings, Sitemap
import PyECS
import copy

REQUIRED = validators.required()

class LoginForm(Form):
    username = fields.TextField('Username', validators=[REQUIRED])
    password = fields.PasswordField('Password', validators=[REQUIRED])
    remember = fields.BooleanField('Keep me signed in')


class SignupForm(Form):
    nickname = fields.TextField('Nickname', validators=[REQUIRED, validators.regexp('^[a-zA-Z0-9-]+$'), validators.Length(min=3, max=50)]) #preg_match(, $username);

class RegistrationForm(Form):
    username = fields.TextField('Username', validators=[REQUIRED])
    password = fields.PasswordField('Password', validators=[REQUIRED])
    password_confirm = fields.PasswordField('Confirm the password', validators=[REQUIRED])


class BaseHandler(RequestHandler, ReallyMultiAuthMixin, Jinja2Mixin,
    AllSessionMixins):
    middleware = [SessionMiddleware]

    def render_response(self, filename, **kwargs):
        auth_session = None
        if 'id' in self.auth_session:
            auth_session = self.auth_session

        self.request.context.update({
            'auth_session': auth_session,
            'current_user': self.auth_current_user,
            'login_url':    self.auth_login_url(),
            'logout_url':   self.auth_logout_url(),
            'current_url':  self.request.url,
        })
        if self.messages:
            self.request.context['messages'] = simplejson.dumps(self.messages)
            
        import os
        if 'HTTP_HOST' in os.environ and os.environ['HTTP_HOST'].find('friendsonnetflix.appspot.com') is not -1:
            self.request.context.update({
                'iscanvas':  1
            })

        response = super(BaseHandler, self).render_response(filename, **kwargs)
        response.headers['P3P'] = 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"' # iframe cookies in IE
        return response

    def redirect_path(self, default='/'):
        if '_continue' in self.session:
            url = self.session.pop('_continue')
        else:
            url = self.request.args.get('continue', '/')

        if not url.startswith('/'):
            url = default

        return url

    def _on_auth_redirect(self):
        """Redirects after successful authentication using third party
        services.
        """

        if '_continue' in self.session:
            url = self.session.get('_continue')
        else:
            url = '/'

        if not self.auth_current_user:
            logging.info("No current user, go to signup")
            #appears that the user is always not set after login, so ends up redirecting back through the oauth process if we dont specifiy the url
            url = self.auth_signup_url(url)

        logging.info("redirecting to %s" % url)
        return self._redirect(url)
    
    def _redirect(self, url):
        response = redirect(url)
        response.headers['P3P'] = 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"' # iframe cookies in IE
        return response

class HomeHandler(BaseHandler):
    def get(self, **kwargs):
        if self.auth_current_user:
            return self._redirect('ratings')
        return self.render_response('home.html', section='home')
    
class FaqHandler(BaseHandler):
    def get(self, **kwargs):
        return self.render_response('faq.html', section='faq')
    
class CanvasChannelHandler(BaseHandler):
    def get(self, **kwargs):
        return self.render_response('canvaschannel.html')    

class ProfileHandler(BaseHandler):
    def get(self, user_name, **kwargs):
        import sys
        if (user_name == 'Ann' or user_name == 'MattyGCar' or user_name == 'Rob' or user_name == 'STACY' or user_name == 'TheDixons'):
            user = MyUser.get_by_key_name(user_name)
        else:
            user = MyUser.get_by_username(user_name)
        show = self.request.args.get('show')
        tab = 4 if show == 'reviews' else 1
        tab = 2 if show == 'favorites' else tab
        tab = 3 if show == 'hated' else tab

        if tab == 2:
            ratings = user.ratings.filter('rating =', 5.0).order('-__key__').fetch(20)
        elif tab == 3:
            ratings = user.ratings.filter('rating =', 1.0).order('-__key__').fetch(20)
        elif tab == 4:
            ratings = user.ratings.filter('has_review =', True).order('-__key__').fetch(20)              
        else:
            ratings = user.ratings.order('-__key__').fetch(20)
            ratings2 = user.ratings.order('-submitted').fetch(20)
            for rat2 in ratings2:
                doadd = True
                for rat in ratings:
                    if rat2.key() == rat.key():
                        doadd = False
                if doadd:
                    ratings.append(rat2)
        ratings.sort(key=lambda x: x.get_submitted(), reverse=True)
        ratings = ratings[0:20]
        isfollowing = False
        numfollowers = 0
        for i in range(1,user.follower_indexes+1):
            shard_name = 'index' + str(i)
            followerIdx = FollowerIndex.get_by_key_name(shard_name,parent=user)
            followers = followerIdx.followers
            if not isfollowing and self.auth_current_user:
                isfollowing = self.auth_current_user.key().name() in followers
            numfollowers += len(followers)
        context = {
            'ratings': ratings,
            'user': user,
            'tab':tab,
            'isfollowing':isfollowing,
            'numfollowers':numfollowers
        }
        return self.render_response('profile.html', **context)

class RatingsHandler(BaseHandler):
    def get(self, **kwargs):
        if self.auth_current_user:
            users = memcache.get("fr-"+str(self.auth_current_user.key().name()))
            if users is None:
                users = self.auth_current_user.getFriends()
                if not memcache.add("fr-"+str(self.auth_current_user.key().name()), users, 1800):
                    logging.error("Memcache fr set failed.")       
            context = {
                'friends': users
            }
            #if self.request.is_xhr:
            #    return render_json_response(context)
            return self.render_response('friends.html', **context) #list.html

        ratings = memcache.get("publicratings")
        if ratings is None:
            ratings = NetflixRating.all().order('-submitted').fetch(20)
            if not memcache.add("publicratings", ratings, 1800):
                logging.error("Memcache set failed.")
        context = {
            'ratings': ratings
        }
        #ajaxratings = []
        #for rating in ratings:
        #    image = ''
            #if rating.user.twitter_name:
            #image = 'https://api.twitter.com/1/users/profile_image?screen_name='+str(rating.user.twitter_name)
            #elif rating.user.facebook_id:
            #    image = '<img src="https://graph.facebook.com/'+rating.user.facebook_id+'/picture?type=square">'
            #ajaxratings.append({
            #                    'title':rating.title.title,
            #                    'image':image,
            #                    'name':str(rating.user),
            #                    'rating':rating.rating_format()
            #})
        #return "Ext.util.JSONP.callback("+simplejson.dumps(ajaxratings)+");"
        #if self.request.is_xhr:
        #    return render_json_response(ajaxratings )
        return self.render_response('list.html', **context) #list.html

class TitleHandler(BaseHandler):
    def get(self, title_id, **kwargs):
        import re
        ratings = []
        yourrating = None
        reviewuser = self.request.args.get('review', None)
        title_key_name = 'http://api.netflix.com/catalog/titles/'+title_id
        title = NetflixTitle.get_by_key_name(title_key_name)
        synopsisFormated = re.sub(r'\([^)]*\)', '', title.synopsis)
        synopsisFormatedNoLinks = re.sub('<[^<]+?>', '', synopsisFormated)
        title_type = 'movie'
        if title.rating.startswith('TV'):
            title_type = 'tv_show'
        ratings = []
        if reviewuser:
            ratings = [NetflixRating.all().filter('user =', db.Key.from_path('MyUser', reviewuser)).filter('title =', title).get()]
        if self.auth_current_user and title:
            ratings.extend(NetflixTitle.getRatingFriends(str(self.auth_current_user.key().name()), title_key_name))
            yourrating = NetflixRating.all().filter('user =', self.auth_current_user).filter('title =', title).get()
        else:
            cachedratings = memcache.get("tr-"+title_key_name)
            if cachedratings is None:
                cachedratings = NetflixRating.all().filter('title =', title).order('-__key__').fetch(20)
                if not memcache.add("tr-"+title_key_name, cachedratings, 1800):
                    logging.error("Memcache tr set failed.")
            ratings.extend(cachedratings)
            
        context = {
            'title':title,
            'synopsisFormated':synopsisFormated,
            'synopsisFormatedNoLinks':synopsisFormatedNoLinks,
            'ratings': ratings,
            'yourrating':yourrating,
			'title_type': title_type,
            'reviewuser':reviewuser,
        }
        return self.render_response('title.html', **context) #list.html
    
class TitleLookupHandler(BaseHandler):
    def get(self, **kwargs):
        import string
        q = self.request.args.get("q")
        if not q:
            q = ''
        q = string.capwords(q)
        titles = NetflixTitle.all().filter('title =', q).fetch(20)
        context = {'titles': titles, 'titlename':q}
        return self.render_response('titlelookup.html', **context) #list.html

class LoginHandler(BaseHandler):
    def get(self, **kwargs):
        import urllib
        context = {
            'app_id': self.app.get_config('facebook', 'app_id'),
            'canvas_url': urllib.quote('http://apps.facebook.com/friendsonnetflix/'),
            'section':'home'
        }
        return self.render_response('auth.html', **context)
    def getold(self, **kwargs):
        redirect_url = self.redirect_path()

        ##if self.auth_current_user:
            # User is already registered, so don't display the signup form.
        ##    return redirect(redirect_url)

        opts = {'continue': self.redirect_path()}
        context = {
            'form':                 self.form,
            'facebook_login_url':   url_for('auth/facebook', **opts),
            'friendfeed_login_url': url_for('auth/friendfeed', **opts),
            'google_login_url':     url_for('auth/google', **opts),
            'twitter_login_url':    url_for('auth/twitter', **opts),
            'yahoo_login_url':      url_for('auth/yahoo', **opts),
			'netflix_login_url':      url_for('auth/netflix', **opts),
        }
        return self.render_response('login.html', **context)

    def post(self, **kwargs):
        redirect_url = self.redirect_path()

        if self.auth_current_user:
            # User is already registered, so don't display the signup form.
            return self._redirect(redirect_url)

        if self.form.validate():
            username = self.form.username.data
            password = self.form.password.data
            remember = self.form.remember.data

            res = self.auth_login_with_form(username, password, remember)
            if res:
                return self._redirect(redirect_url)

        self.set_message('error', 'Authentication failed. Please try again.',
            life=None)
        return self.get(**kwargs)

    @cached_property
    def form(self):
        return LoginForm(self.request)


class LogoutHandler(BaseHandler):
    def get(self, **kwargs):
        self.auth_logout()
        return self._redirect('/')


class SignupHandler(BaseHandler):
    @login_required
    def get(self, **kwargs):
        if self.auth_current_user:
            logging.info("user found!  skip signup, go to %s" % self.redirect_path())
            # User is already registered, so don't display the signup form.
            return self._redirect(self.redirect_path())
        login_id = self.auth_session['login_id']
        userdata = memcache.get(login_id)
        return self.render_response('signup.html', form=self.form, service=userdata['provider_name'])

    @login_required
    def post(self, **kwargs):
        redirect_url = self.redirect_path()

        if self.auth_current_user:
            # User is already registered, so don't process the signup form.
            return self._redirect(redirect_url)
        login_id = self.auth_session['login_id']
        userdata = memcache.get(login_id)

        if self.form.validate():
            nicknamelower = self.form.nickname.data.lower()
            if (nicknamelower == 'ann' or nicknamelower == 'mattygcar' or nicknamelower == 'rob' or nicknamelower == 'stacy' or nicknamelower == 'thedixons'):
                self.set_message('error', 'This nickname is already registered.', life=None)
                return self.get(**kwargs)
            auth_id = self.auth_session.get('id')
            if(userdata['provider_name'] == 'twitter'):
                user = self.auth_create_user(username=self.form.nickname.data, auth_id=auth_id, twitter_name=userdata['username'])
            elif(userdata['provider_name'] == 'facebook'):
                user = self.auth_create_user(username=self.form.nickname.data, auth_id=auth_id, facebook_id=userdata['username'])
            elif(userdata['provider_name'] == 'netflix'):
                user = self.auth_create_user(username=self.form.nickname.data, auth_id=auth_id, has_netflix=True)
            if user:
                self.auth_set_session(user.auth_id, user.session_id, '1')
                cpysession = {
                'username' : userdata.get('username'),
                'login_id' : login_id,
                'provider_id' : userdata.get('provider_id'),
                'oauth_token_secret' : userdata.get('oauth_token_secret'),
                'oauth_token' : userdata.get('oauth_token'),
                'provider_name' : userdata.get('provider_name'),
				}
                self.auth_create_login(user=user, **dict(cpysession))
                self.set_message('success', 'You are now registered. '
                    'Welcome!', flash=True, life=5)
                logging.info("redirecting to %s" % redirect_url)
                
                sitemapModel = Sitemap.get_by_key_name('sitemapusers1');
                if sitemapModel == None:
                    sitemapModel = Sitemap(key_name='sitemapusers1')
                    sitemapModel.sitemap = ''
                sitemapModel.sitemap += '<url><loc>http://www.friendsonnetflix.com/profile/%s</loc><changefreq>daily</changefreq><priority>0.8</priority></url>' % (user.key().name())
                sitemapModel.put()
                
                return self._redirect(redirect_url)
            else:
                self.set_message('error', 'This nickname is already '
                    'registered.', life=None)
                return self.get(**kwargs)

        self.set_message('error', 'A problem occurred. Please correct the '
            'errors listed in the form.', life=None)
        return self.get(**kwargs)

    @cached_property
    def form(self):
        import string
        import random
        #nickname = ''.join((random.choice(string.letters+string.digits) for _ in xrange(random.randint(8,10))))
        nickname = ''
        login_id = self.auth_session['login_id']
        userdata = memcache.get(login_id)
        if(userdata['provider_name'] == 'twitter'):
            nickname = userdata['username']
        return SignupForm(self.request, nickname=nickname)

class FacebookAuthHandler(BaseHandler, FacebookMixin):
    def get(self):

        self.session['_continue'] = '/facebook'        
                
        verification_code = self.request.args.get("code")
        if verification_code is None:
            return self.authenticate_redirect()
        else:
            return self.get_authenticated_user(verification_code, self._on_auth)
        
    def post(self):
        import hmac
        import hashlib
        import urllib
        
        if self.request.args.get("error"):
            context = {
                'app_id': self.app.get_config('facebook', 'app_id'),
                'canvas_url': urllib.quote('http://apps.facebook.com/friendsonnetflix/'),
                'iscanvas':1
            }
            logging.error('FB canvas request error %s' % self.request.args.get("error"))
            return self.render_response('canvaslanding.html', **context)
        
        signed_request = self.request.form.get('signed_request')
        if(signed_request):
            l = signed_request.split('.', 2)
            encoded_sig = l[0]
            payload = l[1]
            sig = self._base64_url_decode(encoded_sig)
            data = simplejson.loads(self._base64_url_decode(payload))
            secret = self.app.get_config('facebook', 'app_secret')
    
            if data.get('algorithm').upper() != 'HMAC-SHA256':
                logging.error('Unknown algorithm')
                return None
            else:
                expected_sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).digest()
            if sig != expected_sig:
                logging.error('Unexpected sig ')
                return None
            else:
                logging.debug('valid auth signed request received..')
            user_id = data.get('user_id')
            oauth_token = data.get('oauth_token')

            self.auth_logout()
            
            if oauth_token:
                self.session['_continue'] = '/facebook'
                return self._oauth_get_user(oauth_token, self._on_auth)

            context = {
                'app_id': self.app.get_config('facebook', 'app_id'),
                'canvas_url': urllib.quote('http://apps.facebook.com/friendsonnetflix/'),
                'iscanvas':1
            }
            logging.debug('Got signed_request, but no oauth_token.')
            return self.render_response('canvaslanding.html', **context)
        
        logging.error('no signed request')        
        return None   

    def _base64_url_decode(self, inp):
        import base64
        padding_factor = (4 - len(inp) % 4) % 4
        inp += "="*padding_factor 
        return base64.b64decode(unicode(inp).translate(dict(zip(map(ord, u'-_'), u'+/'))))                

    def _on_auth(self, user):
        if not user:
			logging.error('No user after Facebook auth.')
			context = {
				'results': 'We\'re having trouble communicating with Facebook.  Try again later.'
			}
			return self.render_response('error.html', **context)

        login_id = 'facebook|%s' % user.get('id')
        login_data = {
            'username': user['id'],
            'email': '',
            'provider_name': 'facebook',
            'provider_id': '%s' % user.get('id'),
			'oauth_token':user.get('access_token')
        }

        currentuser = self.auth_current_user

        if currentuser:
            fblogin = currentuser.logins.filter('provider_name =', 'facebook').get()
            if(fblogin):
                fblogin.oauth_token = login_data['oauth_token']
                fblogin.put()
                return self._on_auth_redirect()
            self.auth_create_login(user=currentuser, login_id=login_id,**login_data)
            currentuser.facebook_id = login_data['provider_id']
            currentuser.put()

            existingfriends = Login.get_users_by_friendid('facebook', login_data['provider_id'])
            userkey = currentuser.key()
            fromkeys = []
            for friend in existingfriends:
                followerIdx = None
                for i in range(1,currentuser.follower_indexes+1):
                    followerIdx_key = db.Key.from_path('FollowerIndex', 'index'+str(i), parent=userkey)
                    followerIdx = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key AND followers = :follower", key=followerIdx_key, follower=friend.key().name()).get()
                    if followerIdx is not None:
                        break
                if followerIdx is None:
                    fromkeys.append(friend.key().name())
            if len(existingfriends) > 0:
                addTask(url='/workeraddfriend', params={'from_keys': fromkeys, 'to_user_key': userkey.name()}, name="newfbfollowers-"+str(userkey))
            self.set_message('success', 'Login added.', flash=True, life=5)
            return self._on_auth_redirect()

        logging.info("Third party auth: %s" % login_data)
        user = self.auth_login_with_third_party(auth_id=login_id,login_id=login_id, remember=True, **login_data)

        if(user):
            fblogin = user.logins.filter('provider_name =', 'facebook').get()
            if(fblogin):
                fblogin.oauth_token = login_data['oauth_token']
                fblogin.put()
            logging.info("Logged in with user: %s" % user)
        else:
            self.session['_continue'] = '/facebook/?new=1'

        return self._on_auth_redirect()

class TwitterAuthHandler(BaseHandler, TwitterMixin):
    def get(self):

        self.session['_continue'] = '/twitterdialog'

        if self.request.args.get('oauth_token', None):
            return self.get_authenticated_user(self._on_auth)

        return self.authenticate_redirect()

    def _on_auth(self, user):
        if not user:
            abort(403)

        ##auth_id = 'twitter|%s' % user.pop('username', '')
        login_id = 'twitter|%s' % user.get('id')
        login_data = {
            'username': user['username'],
            'email': '',
            'provider_name': 'twitter',
            'provider_id': '%s' % user.get('id'),
			'oauth_token':user.get('access_token')['key'],
			'oauth_token_secret':user.get('access_token')['secret']
        }

        currentuser = self.auth_current_user
        if currentuser:
            currentuser.twitter_name = user['username']
            currentuser.put()
            twlogin = currentuser.logins.filter('provider_name =', 'twitter').get()
            if(twlogin):
                twlogin.oauth_token = login_data['oauth_token']
                twlogin.oauth_token_secret = login_data['oauth_token_secret']				
                twlogin.put()
                self.set_message('success', 'Twitter already assigned.', flash=True, life=5)
                return self._on_auth_redirect()

            self.auth_create_login(user=currentuser, login_id=login_id,**login_data)

            existingfriends = Login.get_users_by_friendid('twitter', login_data['provider_id'])
            userkey = currentuser.key()
            fromkeys = []
            for friend in existingfriends:
                followerIdx = None
                for i in range(1,currentuser.follower_indexes+1):
                    followerIdx_key = db.Key.from_path('FollowerIndex', 'index'+str(i), parent=userkey)
                    followerIdx = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key AND followers = :follower", key=followerIdx_key, follower=friend.key().name()).get()
                    if followerIdx is not None:
                        break
                if followerIdx is None:
                    fromkeys.append(friend.key().name())
            if len(existingfriends) > 0:
                addTask(url='/workeraddfriend', params={'from_keys': fromkeys, 'to_user_key': userkey.name()}, name="newtwfollowers-"+str(userkey))

            self.set_message('success', 'Login added.', flash=True, life=5)
            return self._on_auth_redirect()

        logging.info("Third party auth: %s" % login_data)
        user = self.auth_login_with_third_party(auth_id=login_id,login_id=login_id, remember=True, **login_data)

        if(user):
            logging.info("Logged in with user: %s" % user)
        else:
            self.session['_continue'] = '/twitterdialog/?new=1'

        return self._on_auth_redirect()

class NetflixAuthHandler(BaseHandler, NetflixMixin):
    def get(self):

        self.session['_continue'] = '/netflixdialog'

        if self.request.args.get('oauth_token', None):
            return self.get_authenticated_user(self._on_auth)

        return self.authorize_redirect_more()

    def _on_auth(self, login_data):
        if not login_data:
            abort(403)

        if 'access_token' in login_data:
            del login_data['access_token']

        login_id = 'netflix|%s' % login_data['provider_id']
        if self.auth_current_user:
            if(self.auth_get_user_entity(login_id=login_id)):
                self.set_message('success', 'Netflix already assigned.', flash=True, life=5)
            else:
                self.auth_create_login(user=self.auth_current_user, login_id=login_id,**login_data)
                self.auth_current_user.has_netflix = True
                self.auth_current_user.put()
            return self._on_auth_redirect()

        logging.info("Third party auth: %s" % login_data)
        user = self.auth_login_with_third_party(auth_id=login_id, login_id=login_id, remember=True, **login_data)
        if(user):
            logging.info("Logged in with user: %s" % user)
        return self._on_auth_redirect()

        #callback = functools.partial(self._on_feed, login_data)
        #return self.oauth_get_feeds(login_data, callback)

    def _on_feed(self, data, feed):
        login_data = {
            'email': data['email'],
            'provider_name': data['provider_name'],
            'provider_id': data['provider_id'],
			'oauth_token':data['oauth_token'],
			'oauth_token_secret':data['oauth_token_secret'],
			'netflix_ratings_feed':feed
        }
        login_id = 'netflix|%s' % login_data['provider_id']
        if self.auth_current_user:
            self.auth_create_login(user=self.auth_current_user, login_id=login_id, **login_data)
            self.set_message('success', 'Login added.', flash=True, life=5)
            #return redirect(self.auth_session.pop('_continue', '/'))
            return self._on_auth_redirect()

        logging.info("Third party auth: %s" % login_data)
        user = self.auth_login_with_third_party(auth_id=login_id, login_id=login_id, remember=True, **login_data)
        logging.info("Logged in with user: %s" % user)
        return self._on_auth_redirect()

class NetflixDialogHandler(BaseHandler, NetflixMixin):
    def get(self):
        return self.render_response('netflixdialog.html')

class NetflixFetchHandler(BaseHandler, NetflixMixin):
    def get(self):
        user = self.auth_current_user

        login = user.logins.filter('provider_name =', 'netflix').get()
        if not login:
            return self._redirect('/')
        if(login.last_import is not None and (login.last_import + timedelta(minutes=5)) > datetime.utcnow()):
            context = {}
            return self.render_response('wait.html', **context)
        login.last_import = datetime.now()
        login.put()

        notnew = db.GqlQuery("SELECT __key__ FROM NetflixRating WHERE user = :usr", usr=user).get()
        if(notnew is None):
            followerIdx_key = db.Key.from_path('FollowerIndex', 'index1', parent=user.key())
            notnew = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key", key=followerIdx_key).get()
            if(notnew is None):
                followerIdx = FollowerIndex(key_name='index1',parent=user)
                followerIdx.followers=[user.key().name()]
                followerIdx.put()
            #return self.get_ratings(login.netflix_ratings_feed, self._on_result)
            return self.oauth_load_history(self.auth_current_user, login, 0, self._on_result, [])

        numrat = self.oauth_load_ratings_recent(self.auth_current_user, login)
        #numrev = self.oauth_load_reviews_recent(self.auth_current_user, login)
        numrev = 0
        return self._on_result(numrat, numrev)

    def _on_result(self, ratings, reviews=0):
        context = {
            'ratings': ratings,
			'reviews': reviews,
			'results': ''
        }
        return self.render_response('netflixupdate.html', **context)

class TwitterDialogHandler(BaseHandler):
    def get(self):
        return self.render_response('twitterdialog.html')

class TwitterFetchHandler(BaseHandler, TwitterMixin):
    def get(self):
        user = self.auth_current_user
        login = user.logins.filter('provider_name =', 'twitter').get()
        if not login:
            return self._redirect('/')
        if(login.last_import is not None and (login.last_import + timedelta(minutes=5)) > datetime.utcnow()):
            return self._redirect('/')
        login.last_import = datetime.now()
        login.put()

        followerIdx_key = db.Key.from_path('FollowerIndex', 'index1', parent=user.key())
        notnew = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key", key=followerIdx_key).get()
        if(notnew is None):
            followerIdx = FollowerIndex(key_name='index1',parent=user)
            followerIdx.followers=[user.key().name()]
            followerIdx.put()
            existingfriends = Login.get_users_by_friendid('twitter', login.provider_id)
            fromkeys = []
            fromkeys.append(user.key().name()) #friend yourself
            for friend in existingfriends:
                fromkeys.append(friend.key().name())
            if len(fromkeys) > 0:
                addTask(url='/workeraddfriend', params={'from_keys': fromkeys, 'to_user_key': user.key().name()})

        return self._import(login, [], [], 0, -1)

    def _import(self, login, friendids, friendnames, alreadyfriends, cursor):
        callback = functools.partial(self._on_result, login, friendids, friendnames, alreadyfriends)
        access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
        return self.twitter_request( '/friends/ids',
            access_token=access_token,
            callback=callback,
            user_id=login.provider_id, cursor=cursor )

    def _on_result(self, login, friendids, friendnames, alreadyfriends, data):
        #if not data:
         #   abort(403)
        user = self.auth_current_user
        for twitterid in data['ids']:
            twitteruser = self.auth_get_user_entity(login_id = 'twitter|'+str(twitterid))
            if twitteruser is None:
                if len(friendids) < 4500:
                    friendids.append(str(twitterid))
                continue
            followerIdx = None
            for i in range(1,user.follower_indexes+1):
                followerIdx_key = db.Key.from_path('FollowerIndex', 'index'+str(i), parent=twitteruser.key())
                followerIdx = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key AND followers = :me", key=followerIdx_key, me=user.key().name()).get()
                if followerIdx is not None:
                    alreadyfriends += 1;
                    break
            if followerIdx is None:
                friendnames.append(twitteruser.username)
                addTask(url='/workeraddfriend', params={'from_keys': [user.key().name()], 'to_user_key': twitteruser.key().name()})

        if(data['next_cursor'] > 0):
            return self._import(login, friendids, friendnames, alreadyfriends, data['next_cursor'])

        twfriends = TwitterFriendsTBD.all().filter('user =', user).get()
        if twfriends is None:
            twfriends = TwitterFriendsTBD(user=user)
        twfriends.friendids = friendids
        twfriends.put()

        if not user.twitterSettings:
            user.twitterSettings = [False,False,False,False,False,False];

        context = {
            'alreadyfriends':                 alreadyfriends,
            'newfriends':                 friendnames,
            'newfriendscount':                 len(friendnames),
            'missingcount': len(friendids),
			'sharereviews':user.twitterSettings[0],
			'share1':user.twitterSettings[1],
			'share2':user.twitterSettings[2],
			'share3':user.twitterSettings[3],
			'share4':user.twitterSettings[4],
			'share5':user.twitterSettings[5]
        }
        return self.render_response('twitterupdate.html', **context)

    def post(self, **kwargs):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')
        sharereviews = True if self.request.form.get('sharereviews') is not None else False
        share1 = True if self.request.form.get('share1') is not None else False
        share2 = True if self.request.form.get('share2') is not None else False
        share3 = True if self.request.form.get('share3') is not None else False
        share4 = True if self.request.form.get('share4') is not None else False
        share5 = True if self.request.form.get('share5') is not None else False
        user.twitterSettings = []
        user.twitterSettings.append(sharereviews)
        user.twitterSettings.append(share1)
        user.twitterSettings.append(share2)
        user.twitterSettings.append(share3)
        user.twitterSettings.append(share4)
        user.twitterSettings.append(share5)
        user.put()
        return self._redirect('/twitter/settings')


class FacebookFetchHandler(BaseHandler, FacebookMixin):
    def get(self):
        user = self.auth_current_user
        login = user.logins.filter('provider_name =', 'facebook').get()
        if not login:
            return self._redirect('/')
        if(login.last_import is not None and (login.last_import + timedelta(minutes=5)) > datetime.utcnow()):
            return self._redirect('/')
        login.last_import = datetime.now()
        login.put()

        followerIdx_key = db.Key.from_path('FollowerIndex', 'index1', parent=user.key())
        notnew = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key", key=followerIdx_key).get()
        if(notnew is None):
            followerIdx = FollowerIndex(key_name='index1',parent=user)
            followerIdx.followers=[user.key().name()]
            followerIdx.put()
            existingfriends = Login.get_users_by_friendid('facebook', login.provider_id)
            fromkeys = []
            fromkeys.append(user.key().name()) #friend yourself
            for friend in existingfriends:
                fromkeys.append(friend.key().name())
            if len(fromkeys) > 0:
                addTask(url='/workeraddfriend', params={'from_keys': fromkeys, 'to_user_key': user.key().name()})

        return self._import(login.oauth_token)

    def _import(self, access_token):
        return self.facebook_request( '/me/friends',
            access_token=access_token,
            callback=self._on_result)

    def _on_result(self, data):
        if not data:
			logging.error('No data after Facebook friends import.')
			context = {
				'results': 'We\'re having trouble communicating with Facebook.  Try again later.'
			}
			return self.render_response('error.html', **context)	
        user = self.auth_current_user
        friendids = []
        alreadyfriends=0
        friendnames=[]
        for fbuserinfo in data['data']:
            fbuser = self.auth_get_user_entity(login_id = 'facebook|'+str(fbuserinfo['id']))
            if fbuser is None:
                friendids.append(fbuserinfo['id'])
                continue
            followerIdx = None
            for i in range(1,user.follower_indexes+1):
                followerIdx_key = db.Key.from_path('FollowerIndex', 'index'+str(i), parent=fbuser.key())
                followerIdx = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE __key__ = :key AND followers = :me", key=followerIdx_key, me=user.key().name()).get()
                if followerIdx is not None:
                    alreadyfriends += 1
                    break
            if followerIdx is None:
                friendnames.append(fbuser.username)
                addTask(url='/workeraddfriend', params={'from_keys': [user.key().name()], 'to_user_key': fbuser.key().name()})

        fbfriends = FacebookFriendsTBD.all().filter('user =', user).get()
        if fbfriends is None:
            fbfriends = FacebookFriendsTBD(user=user)
        fbfriends.friendids = friendids
        fbfriends.put()

        if not user.facebookSettings:
            user.facebookSettings = [False,False,False,False,False,False];

        context = {
            'alreadyfriends':                 alreadyfriends,
            'newfriends':                 friendnames,
            'newfriendscount':                 len(friendnames),
            'missingcount': len(friendids),
			'sharereviews':user.facebookSettings[0],
			'share1':user.facebookSettings[1],
			'share2':user.facebookSettings[2],
			'share3':user.facebookSettings[3],
			'share4':user.facebookSettings[4],
			'share5':user.facebookSettings[5]
        }
        if len(friendnames) == 0:
            return self._redirect('/')
        return self.render_response('facebookupdate.html', **context)

    def post(self, **kwargs):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')
        sharereviews = True if self.request.form.get('sharereviews') is not None else False
        share1 = True if self.request.form.get('share1') is not None else False
        share2 = True if self.request.form.get('share2') is not None else False
        share3 = True if self.request.form.get('share3') is not None else False
        share4 = True if self.request.form.get('share4') is not None else False
        share5 = True if self.request.form.get('share5') is not None else False
        user.facebookSettings = []
        user.facebookSettings.append(sharereviews)
        user.facebookSettings.append(share1)
        user.facebookSettings.append(share2)
        user.facebookSettings.append(share3)
        user.facebookSettings.append(share4)
        user.facebookSettings.append(share5)
        user.put()
        return self._redirect('/facebook/settings')

    def post(self, **kwargs):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')

        sharereviews = True if self.request.form.get('sharereviews') is not None else False
        share1 = True if self.request.form.get('share1') is not None else False
        share2 = True if self.request.form.get('share2') is not None else False
        share3 = True if self.request.form.get('share3') is not None else False
        share4 = True if self.request.form.get('share4') is not None else False
        share5 = True if self.request.form.get('share5') is not None else False
        user.facebookSettings = []
        user.facebookSettings.append(sharereviews)
        user.facebookSettings.append(share1)
        user.facebookSettings.append(share2)
        user.facebookSettings.append(share3)
        user.facebookSettings.append(share4)
        user.facebookSettings.append(share5)
        user.put()
        return self._redirect('/facebook/settings')


class FacebookSettingsHandler(BaseHandler, FacebookMixin):
    def get(self):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')
        
        login = user.logins.filter('provider_name =', 'facebook').get()
        
        return self.facebook_request( '/me/permissions',
            access_token=login.oauth_token,
            callback=self._on_result)

    def _on_result(self, data):
        import urllib
        haspermissions = False
        if data is not None and 'publish_stream' in data['data'][0] and 'offline_access' in data['data'][0]:        
            haspermissions = True
        
        user = self.auth_current_user
        if not user.facebookSettings:
            user.facebookSettings = [False,False,False,False,False,False];

        context = {
			'sharereviews':user.facebookSettings[0],
			'share1':user.facebookSettings[1],
			'share2':user.facebookSettings[2],
			'share3':user.facebookSettings[3],
			'share4':user.facebookSettings[4],
			'share5':user.facebookSettings[5],
            'app_id': self.app.get_config('facebook', 'app_id'),
            'canvas_url': urllib.quote('http://apps.facebook.com/friendsonnetflix/'),
            'haspermissions': haspermissions,
        }
        return self.render_response('facebooksettings.html', **context)

    def post(self, **kwargs):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')
        sharereviews = True if self.request.form.get('sharereviews') is not None else False
        share1 = True if self.request.form.get('share1') is not None else False
        share2 = True if self.request.form.get('share2') is not None else False
        share3 = True if self.request.form.get('share3') is not None else False
        share4 = True if self.request.form.get('share4') is not None else False
        share5 = True if self.request.form.get('share5') is not None else False
        user.facebookSettings = []
        user.facebookSettings.append(sharereviews)
        user.facebookSettings.append(share1)
        user.facebookSettings.append(share2)
        user.facebookSettings.append(share3)
        user.facebookSettings.append(share4)
        user.facebookSettings.append(share5)
        user.put()
        return self._redirect('/facebook/settings')

class TwitterSettingsHandler(BaseHandler):
    def get(self):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')

        if not user.twitterSettings:
            user.twitterSettings = [False,False,False,False,False,False];

        context = {
			'sharereviews':user.twitterSettings[0],
			'share1':user.twitterSettings[1],
			'share2':user.twitterSettings[2],
			'share3':user.twitterSettings[3],
			'share4':user.twitterSettings[4],
			'share5':user.twitterSettings[5]
        }
        return self.render_response('twittersettings.html', **context)

    def post(self, **kwargs):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')
        sharereviews = True if self.request.form.get('sharereviews') is not None else False
        share1 = True if self.request.form.get('share1') is not None else False
        share2 = True if self.request.form.get('share2') is not None else False
        share3 = True if self.request.form.get('share3') is not None else False
        share4 = True if self.request.form.get('share4') is not None else False
        share5 = True if self.request.form.get('share5') is not None else False
        user.twitterSettings = []
        user.twitterSettings.append(sharereviews)
        user.twitterSettings.append(share1)
        user.twitterSettings.append(share2)
        user.twitterSettings.append(share3)
        user.twitterSettings.append(share4)
        user.twitterSettings.append(share5)
        user.put()
        return self._redirect('/twitter/settings')

class TitleEmbedHandler(BaseHandler):
    def get(self):
        id = self.request.args.get("id")
        if id is None:
            return ''
        ratings = []
        title = NetflixTitle.all().filter('title_id_num  =', id).get()
        if title and self.auth_current_user:
            ratings = NetflixTitle.getRatingFriends(str(self.auth_current_user.key().name()), title.key().name())
        context = {
            'ratings': ratings,
            'title':title
        }
        return self.render_response('titleembed.html', **context)


class TestViewHandler(BaseHandler):
    def get2(self):
        for movie in NetflixTitle(title='dummy').all():
            if(movie.metacritic_rating):
                continue
            #slugtitle = str(movie.slugify('-'))
            #url = 'http://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20html%20where%20url%3D%22http%3A%2F%2Fwww.rottentomatoes.com%2Fm%2F'+slugtitle+'%22%20and%20xpath%3D\'%2F%2Fspan%5B%40id%3D%22all-critics-meter%22%5D\'&format=json'
            #response = self._parsemovie(urlfetch.fetch(url, deadline=10))
            #if(response and response['query']['results']):
            #    results = response['query']['results']['span'][0]['content']
            #    movie.rotten_rating = int(results)
            slugtitle = str(movie.slugify('-'))
            url = 'http://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20html%20where%20url%3D%22http%3A%2F%2Fwww.metacritic.com%2Fmovie%2F'+slugtitle+'%22%20and%20xpath%3D\'%2F%2Fspan%5B%40class%3D%22score_value%22%5D\'&format=json'
            response = self._parsemovie(urlfetch.fetch(url, deadline=10))
            if(response and response['query']['results']):
                results = response['query']['results']['span'][0]['content']
                movie.metacritic_rating = int(results)
            movie.put()
        context = {
            'results':                 'done'
        }
        return self.render_response('netflixupdate.html', **context)

    def _parsemovie(self, response):
        if not response:
            logging.warning('Could not get movie request.')
            return None
        elif response.status_code < 200 or response.status_code >= 300:
            logging.warning('Invalid movie response (%d): %s',
                response.status_code, response.content)
            return None
        return simplejson.loads(response.content)

    def get(self):
        PyECS.setLicenseKey('AKIAINRBYW54VUIMAMMA')
        PyECS.setSecretKey('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')
        title_id = 'movies/540533'
        title_key_name = 'http://api.netflix.com/catalog/titles/'+title_id
        title = NetflixTitle.get_by_key_name(title_key_name)
        results = PyECS.ItemSearch(str(title.release_year), SearchIndex="DVD", Availability=None, Title=title.title, Power=None, BrowseNode=None, Artist=None, Author=None, Actor=None, Director=None, AudienceRating=None, Manufacturer=None, MusicLabel=None, Composer=None, Publisher=None, Brand=None, Conductor=None, Orchestra=None, TextStream=None, ItemPage=None, OfferPage=None, ReviewPage=None, Sort=None, City=None, Cuisine=None, Neighborhood=None, MinimumPrice=None, MaximumPrice=None, MerchantId="Amazon", Condition="New", DeliveryMethod=None, ResponseGroup='ItemIds')
        ASIN = results.cache[0].ASIN
        context = {
            'results':                 results.cache[0].ASIN
        }
        return self.render_response('results.html', **context)

class NewFriend(BaseHandler):
    def post(self):
        if self.request.is_xhr:
            user = self.auth_current_user
            if not user:
                return render_json_response([])
            to_user_key = self.request.form.get('to_user')
            addTask(url='/workeraddfriend', params={'from_keys': [user.key().name()], 'to_user_key': to_user_key})
            return render_json_response([])

class DownloadRatingsHandler(BaseHandler):
    def get(self):
        user = self.auth_current_user
        if not user:
            return self._redirect('/')
        logging.info('Downloading ratings for %s' % user)
        import csv
        import StringIO
        output_buffer = StringIO.StringIO()
        csv_output = csv.writer(output_buffer)
        csv_output.writerow( ('num','Title', 'Year', 'Date Rated', 'Rating', 'Review') )

        q = user.ratings.order('__key__')
        ratings = []
        while True:
            fetched = q.fetch(10000)
            ratings.extend(fetched)
            if len(fetched) < 10000:
                break;
            cursor = q.cursor()
            q.with_cursor(cursor)
        i=0
        for rat in ratings:
            i+=1;
            csv_output.writerow( (i, rat.title.title, rat.title.release_year, rat.submitted, rat.rating, rat.review) )
        response = Response()
        response.data = output_buffer.getvalue()
        response.headers['Content-Type'] = "text/csv; charset=utf-8"
        response.headers['Content-Disposition'] = "attachment;filename="+str(user.key().name())+"_ratings.csv"
        return response

class CountRatingsHandler(BaseHandler):
    def get(self):
        q = MyUser.all()
        results = ''
        for usr in q.fetch(1000):
            results += str(usr.rating_count) +' - '+str(usr.ratings.count())+' <br />'
        return results
class DoCountRatingsHandler(BaseHandler):
    def get(self):
        q = MyUser.all()
        for usr in q.fetch(1000):
            if usr.rating_count != usr.ratings.count():
                usr.rating_count = usr.ratings.count()
                usr.put()
        return 'done'

#add list of followers to to_user
class WorkerAddFollower(RequestHandler):
    def post(self): # should run at most 1/s
        from types import ListType
        to_user_key = self.request.form.get('to_user_key')
        data = self.request.form.get('from_keys')
        if to_user_key is None or data is None:
            logging.warning('WorkerAddFollower is missing args')
            return ''
        if not isinstance(data, ListType):
            data = [data]
        shard_name = ''
        to_user = MyUser.get_by_key_name(to_user_key)
        if to_user is None:
            return ''
        startindexes = to_user.follower_indexes
        #for each follower, check if already exists, if not, append to to_user's followers
        def txn():
                idxs = to_user.follower_indexes
                shard_name = 'index' + str(idxs)
                followerIdx = FollowerIndex.get_by_key_name(shard_name,parent=to_user)
                if(followerIdx is None):
                    followerIdx = FollowerIndex(key_name=shard_name,parent=to_user,followers=[])
                    if idxs == 1:
                        followerIdx.followers=[to_user.key().name()]
                for key in data:
                    if(key in followerIdx.followers):
                        continue
                    if(len(followerIdx.followers) < 5000):
                        followerIdx.followers.append(key)
                    else:
                        followerIdx.put()
                        idxs = idxs + 1
                        shard_name = 'index' + str(idxs)
                        followerIdx = FollowerIndex(key_name=shard_name,parent=to_user, followers=[])
                        followerIdx.followers.append(key)
                followerIdx.put()
                if(to_user.follower_indexes < idxs):
                    to_user.follower_indexes = idxs
                    to_user.put()
        db.run_in_transaction(txn)

        #for each of to_users's ratings, update who can see them.  And for each title, add what ratings the follower can see
        endindexes = to_user.follower_indexes
        ratingindexes = []
        for i in range(startindexes, endindexes+1):
            shard_name = 'index' + str(i)
            followerIdx = FollowerIndex.get_by_key_name(shard_name,parent=to_user)
            for rating in to_user.ratings:
                ratingIdx = NetflixRatingIndex(key_name=shard_name,parent=rating)
                ratingIdx.followers = followerIdx.followers
                ratingindexes.append(ratingIdx)
                titleKey = NetflixRating.title.get_value_for_datastore(rating)
                for newfollowerkey in data:
                    stupidhack = newfollowerkey
                    if newfollowerkey == 'mikep.':
                        newfollowerkey = 'mikep-'
                    addTask(url='/workeraddfriendrating', params={'title_key':titleKey.name(), 'rating_key': rating.key().name(), 'user_key': stupidhack}, name='wafr-'+newfollowerkey+'-'+str(rating.key()))
        db.put(ratingindexes)
        return ''

class WorkerAddRating(RequestHandler):
    def post(self): # should run at most 1/s
        from datetime import date
        from time import mktime
        user_key = self.request.form.get('user_key')
        title_key = self.request.form.get('title_key')
        submittedval = self.request.form.get('submitted')
        try:
            ratingval = float(self.request.form.get('rating'))
        except ValueError:
            logging.error('Rating Float error.  The rating value was %s' % self.request.form.get('rating'))
            return ''

        submitted = None
        try:
            submittedval = float(submittedval)
            submitted=datetime.fromtimestamp(submittedval)
        except ValueError:
            #t=datetime.now()
            submitted = None
            submittedval = None#mktime(t.timetuple())+1e-6*t.microsecond

        user = MyUser.get_by_key_name(user_key)
        title = NetflixTitle.get_by_key_name(title_key)
        if not title or not user:
			return ''

        rating = NetflixRating(title=title, user=user).all().filter('user =', user).filter('title =', title).get()
        #if oldrating is not None:
            #delete
        #    def txn():
        #        rkey = oldrating.key()
        #        if(rkey is not None):
        #            for i in range(1,user.follower_indexes+1):
        #                shard_name = 'index' + str(i)
        #                idxkey = db.Key.from_path('NetflixRatingIndex', shard_name, parent=rkey)
        #                db.delete(idxkey)
        #            db.delete(rkey)
        #    db.run_in_transaction(txn)
        #else:
        #    oldrating = NetflixRating(title=title, user=user)

        t=datetime.now()
        unixtimestamp = mktime(t.timetuple())+1e-6*t.microsecond
        isnew = False
        #rating = NetflixRating(key_name='r'+str(unixtimestamp)+'-'+str(user.key()), title=title, user=user, rating=ratingval, review=oldrating.review, created=oldrating.created, submitted=oldrating.submitted, has_review=oldrating.has_review)
        if rating is None:
            isnew = True
            rating = NetflixRating(key_name='r'+str(unixtimestamp)+'-'+str(user.key().name()), title=title, user=user)
        rating.rating = ratingval
        if submitted is not None:
            rating.submitted = submitted
        rating.put()

        if isnew:
            for i in range(1,user.follower_indexes+1):
                shard_name = 'index' + str(i)
                followerIdx = FollowerIndex.get_by_key_name(shard_name,parent=user)
                if followerIdx:
                    rindex = NetflixRatingIndex.get_by_key_name(shard_name,parent=rating)
                    if rindex is None:
                        rindex = NetflixRatingIndex.get_or_insert(key_name=shard_name,parent=rating, followers=followerIdx.followers)
                    else:
                        rindex.followers=followerIdx.followers
                        rindex.put()
                    #adjust the title's recent ratings for each follower
                    for follower in followerIdx.followers:
                        stupidhack = follower
                        if follower == 'mikep.':
                            follower = 'mikep-'                        
                        addTask(url='/workeraddfriendrating', params={'title_key':title.key().name(), 'rating_key': rating.key().name(), 'user_key': stupidhack}, name='wafr-'+follower+'-'+str(rating.key()))

        if isnew or (submitted is not None and user.last_netflix_rating < submittedval):
            if submitted is not None and user.last_netflix_rating < submittedval:
                user.last_netflix_rating = int(submittedval)
            user.rating_count = user.rating_count + 1
            user.put()

        return ''

class WorkerAddReview(RequestHandler):
    def post(self):
        from datetime import date
        from time import mktime
        user_key = self.request.form.get('user_key')
        title_key = self.request.form.get('title_key')
        submittedval = self.request.form.get('submitted')
        ratingval = float(self.request.form.get('rating'))
        review = self.request.form.get('review')
        submitted = None
        try:
            submittedval = float(submittedval)
            submitted=datetime.fromtimestamp(submittedval)
        except ValueError:
            #t=datetime.now()
            submittedval = None
            submitted = None#mktime(t.timetuple())+1e-6*t.microsecond

        user = MyUser.get_by_key_name(user_key)
        title = NetflixTitle.get_by_key_name(title_key)
        if not title or not user:
			return ''

        rating = NetflixRating(title=title, user=user).all().filter('user =', user).filter('title =', title).get()
        #if oldrating is not None:
            #delete
        #    def txn():
        #        rkey = oldrating.key()
        #        if(rkey is not None):
        #            for i in range(1,user.follower_indexes+1):
        #                shard_name = 'index' + str(i)
        #                idxkey = db.Key.from_path('NetflixRatingIndex', shard_name, parent=rkey)
        #                db.delete(idxkey)
        #            db.delete(rkey)
        #    db.run_in_transaction(txn)
        #else:
        #    oldrating = NetflixRating(title=title, user=user)

        t=datetime.now()
        unixtimestamp = mktime(t.timetuple())+1e-6*t.microsecond
        isnew = False
        isnewreview = False
        #rating = NetflixRating(key_name='r'+str(unixtimestamp)+'-'+str(user.key()), title=title, user=user, rating=ratingval, review=oldrating.review, created=oldrating.created, submitted=oldrating.submitted, has_review=oldrating.has_review)
        if rating is None:
            isnew = True
            isnewreview = True
            rating = NetflixRating(key_name='r'+str(unixtimestamp)+'-'+user.key().name(), title=title, user=user, rating=ratingval)
        elif (rating.review is None) or (rating.review == ""):
            isnewreview = True
        if submitted is not None:
            rating.submitted = submitted
        rating.set_review(review)
        rating.put()

        if isnew:
            for i in range(1,user.follower_indexes+1):
                shard_name = 'index' + str(i)
                followerIdx = FollowerIndex.get_by_key_name(shard_name,parent=user)
                if followerIdx:
                    rindex = NetflixRatingIndex.get_by_key_name(shard_name,parent=rating)
                    if rindex is None:
                        rindex = NetflixRatingIndex.get_or_insert(key_name=shard_name,parent=rating, followers=followerIdx.followers)
                    else:
                        rindex.followers=followerIdx.followers
                        rindex.put()
                    #adjust the title's recent ratings for each follower
                    for follower in followerIdx.followers:
                        stupidhack = follower                        
                        if follower == 'mikep.':
                            follower = 'mikep-'
                        addTask(url='/workeraddfriendrating', params={'title_key':title.key().name(), 'rating_key': rating.key().name(), 'user_key': stupidhack}, name='wafr-'+follower+'-'+str(rating.key()))

        if isnewreview or isnew or (submitted is not None and user.last_netflix_review < submittedval):
            if submitted is not None and user.last_netflix_review < submittedval:
                user.last_netflix_review = int(submittedval)
            if isnew:
                user.rating_count = user.rating_count + 1
            if isnewreview:
                user.review_count = user.review_count + 1
            user.put()

        return ''

class TitleHandler2(BaseHandler, TwitterMixin, FacebookMixin):
    def get(self, title_id, **kwargs):
        from datetime import datetime, timedelta
        title_key_name = 'http://api.netflix.com/catalog/titles/'+title_id
        user_key = "dsims"
        title_key = title_key_name
        user = MyUser.get_by_key_name(user_key)
        doshareTW = False
        doshareFB = False
        for twit in user.twitterSettings:
            if twit:
                doshareTW = True
        for fbook in user.facebookSettings:
            if fbook:
                doshareFB = True
        if not doshareTW and not doshareFB:
            return 'no share'

        title = NetflixTitle.get_by_key_name(title_key)
        if not title or not user:
			return 'no title'

        #only share once per 30 minutes, and only a rating done in the last 30 minutes
        rating = NetflixRating(title=title, user=user).all().filter('user =', user).filter('title =', title).get()
        #if rating is None or rating.submitted is None or (datetime.now() - (datetime.min if user.lastshare is None else user.lastshare)) < timedelta (minutes = 30) or (datetime.now() - rating.created) > timedelta (minutes = 60):
            #return  'too soon/late'
        try:
            from re import match
            from urllib2 import urlopen, Request, HTTPError
            from urllib import urlencode
            from django.utils import simplejson
        except ImportError, e:
            logging.error('import error')

        bitlyuser = "friendsonnetflix"
        apikey  = "R_37b0dc1cd9e30167b116f4742df20c37"
        url = 'http://www.friendsonnetflix.com/title/'+rating.title.slugify()+'/'+rating.title.key().name().replace('http://api.netflix.com/catalog/titles/', '')#+'?review='+rating.user.key().name()
        if rating.has_review:
            url = 'http://www.friendsonnetflix.com/title/'+rating.title.slugify()+'/'+rating.title.key().name().replace('http://api.netflix.com/catalog/titles/', '')+'?review='+rating.user.key().name()		
        bitlyurl = ""
        try:
            params = urlencode({'longUrl': url, 'login': bitlyuser, 'apiKey': apikey, 'format': 'json'})
            req = Request("http://api.bit.ly/v3/shorten?%s" % params)
            response = urlopen(req)
            j = simplejson.loads(response.read())
            if j['status_code'] == 200:
                bitlyurl = j['data']['url']
            else:
                logging.error('Bitly status error')
        except HTTPError, e:
            logging.error('Bitly httperror')

        if doshareTW:
            message = ""
            if(rating.rating == 1 and (user.twitterSettings[1] or user.twitterSettings[0])):
                message = "Hated %s." % (title.title)
            elif(rating.rating <= 2.5 and (user.twitterSettings[2] or user.twitterSettings[0])):
                message = "Didn't like %s." % (title.title)
            elif(rating.rating <= 3.5 and (user.twitterSettings[3] or user.twitterSettings[0])):
                message = "thought %s was ok." % (title.title)
            elif(rating.rating <= 4.5 and (user.twitterSettings[4] or user.twitterSettings[0])):
                message = "Liked %s." % (title.title)
            elif(rating.rating <= 5 and (user.twitterSettings[5] or user.twitterSettings[0])):
                message = "Loved %s." % (title.title)
            if(user.twitterSettings[0] and rating.has_review):
                message = message + " Review:"
            if(message != ""):
                message = "%s %s" % (message, bitlyurl)
                login = user.logins.filter('provider_name =', 'twitter').get()
                if login:
                    logging.info('Tweeting %s to %s' % (message, user.twitter_name))
                    callback = functools.partial(self._on_twitter_result)
                    access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
                    self.twitter_request( '/statuses/update',
                        access_token=access_token,
                        callback=callback,
                        post_args={'status': message} )
                    user.lastshare = datetime.now()
                    user.put()

        if doshareFB:
            message = ""
            if(rating.rating == 1 and (user.facebookSettings[1] or user.facebookSettings[0])):
                message = "hated %s." % (title.title)
            elif(rating.rating <= 2 and (user.facebookSettings[2] or user.facebookSettings[0])):
                message = "didn't like %s." % (title.title)
            elif(rating.rating <= 3 and (user.facebookSettings[3] or user.facebookSettings[0])):
                message = "thought %s was ok." % (title.title)
            elif(rating.rating <= 4 and (user.facebookSettings[4] or user.facebookSettings[0])):
                message = "liked %s." % (title.title)
            elif(rating.rating <= 5 and (user.facebookSettings[5] or user.facebookSettings[0])):
                message = "loved %s." % (title.title)
            if(user.facebookSettings[0] and rating.has_review):
                message = message + " Review:"
            if(message != ""):
                message = "%s %s" % (message, bitlyurl)
                login = user.logins.filter('provider_name =', 'facebook').get()
                if login:
                    logging.info('Facebooking %s.  ID: %s' % (message, user.facebook_id))
                    self.facebook_request( '/me/feed',
                        access_token=login.oauth_token,
                        callback=self._on_fb_result,
                        post_args={'message': message})
                    user.lastshare = datetime.now()
                    user.put()

        return 'fin'

    def _on_twitter_result(self, data):
        if not data:
            logging.error('Tweet failed')
        logging.info('Tweet data %s' % data)
        return
    def _on_fb_result(self, data):
        if not data:
            logging.error('FB failed')
        return


class HistoryHandler(BaseHandler, NetflixMixin):
    def get(self, **kwargs):
        profile = self.request.args.get("profile")
        logging.error('Do History attempt.  Name: %s' % profile)
        douser = MyUser.get_by_key_name(profile)
        user = self.auth_current_user
        if not douser or user.key().name() != 'dsims':
            return self._redirect('/')
        login = douser.logins.filter('provider_name =', 'netflix').get()
        if not login:
            return self._redirect('/')
        return self.oauth_load_history(douser, login, 0, self._on_result, [])
	
    def _on_result(self, ratings, reviews=0):
        context = {
            'ratings': ratings,
			'reviews': reviews,
			'results': ''
        }
        return self.render_response('netflixupdate.html', **context)

class WorkerShareRating(RequestHandler, TwitterMixin, FacebookMixin):
    
    def post(self):
        from datetime import datetime, timedelta
        user_key = self.request.form.get('user_key')
        title_key = self.request.form.get('title_key')
        user = MyUser.get_by_key_name(user_key)
        doshareTW = False
        doshareFB = False
        for twit in user.twitterSettings:
            if twit:
                doshareTW = True
        for fbook in user.facebookSettings:
            if fbook:
                doshareFB = True
        if not doshareTW and not doshareFB:
            return ''

        title = NetflixTitle.get_by_key_name(title_key)
        if not title or not user:
			return ''

        #only share once per 30 minutes, and only a rating done in the last 30 minutes
        rating = NetflixRating(title=title, user=user).all().filter('user =', user).filter('title =', title).get()
        if rating is None or rating.submitted is None or (datetime.now() - (datetime.now() if user.lastshare is None else user.lastshare)) < timedelta (minutes = 30) or (datetime.now() - rating.created) > timedelta (minutes = 30):
            return  ''
        try:
            from re import match
            from urllib2 import urlopen, Request, HTTPError
            from urllib import urlencode
            from django.utils import simplejson
        except ImportError, e:
            logging.error('import error')

        bitlyuser = "friendsonnetflix"
        apikey  = "R_37b0dc1cd9e30167b116f4742df20c37"
        url = 'http://www.friendsonnetflix.com/title/'+rating.title.slugify()+'/'+rating.title.key().name().replace('http://api.netflix.com/catalog/titles/', '')#+'?review='+rating.user.key().name()
        if rating.has_review:
            url = 'http://www.friendsonnetflix.com/title/'+rating.title.slugify()+'/'+rating.title.key().name().replace('http://api.netflix.com/catalog/titles/', '')+'?review='+rating.user.key().name()
        bitlyurl = ""
        try:
            params = urlencode({'longUrl': url, 'login': bitlyuser, 'apiKey': apikey, 'format': 'json'})
            req = Request("http://api.bit.ly/v3/shorten?%s" % params)
            response = urlopen(req)
            j = simplejson.loads(response.read())
            if j['status_code'] == 200:
                bitlyurl = j['data']['url']
            else:
                logging.error('Bitly status error')
        except HTTPError, e:
            logging.error('Bitly httperror')

        if doshareTW:
            message = ""
            if(rating.rating == 1 and (user.twitterSettings[1] or (rating.has_review and user.twitterSettings[0]))):
                message = "Hated %s." % (title.title)
            elif((rating.rating > 1 and rating.rating <= 2.5) and (user.twitterSettings[2] or (rating.has_review and user.twitterSettings[0]))):
                message = "Didn't like %s." % (title.title)
            elif((rating.rating > 2.5 and rating.rating <= 3.5) and (user.twitterSettings[3] or (rating.has_review and user.twitterSettings[0]))):
                message = "thought %s was ok." % (title.title)
            elif((rating.rating > 3.5 and rating.rating <= 4.5) and (user.twitterSettings[4] or (rating.has_review and user.twitterSettings[0]))):
                message = "Liked %s." % (title.title)
            elif(rating.rating <= 5 and (user.twitterSettings[5] or (rating.has_review and user.twitterSettings[0]))):
                message = "Loved %s." % (title.title)
            if(user.twitterSettings[0] and rating.has_review):
                message = message + " Review:"
            if(message != ""):
                message = "%s %s" % (message, bitlyurl)
                login = user.logins.filter('provider_name =', 'twitter').get()
                if login:
                    logging.info('Tweeting %s to %s', message, user.twitter_name)
                    callback = functools.partial(self._on_twitter_result)
                    access_token = {'key':login.oauth_token,'secret':login.oauth_token_secret}
                    self.twitter_request( '/statuses/update',
                        access_token=access_token,
                        callback=callback,
                        post_args={'status': message} )
                    user.lastshare = datetime.now()
                    user.put()

        if doshareFB:
            message = ""
            if(rating.rating == 1 and (user.facebookSettings[1] or (rating.has_review and user.facebookSettings[0])) ):
                message = "hated %s." % (title.title)
            elif((rating.rating > 1 and rating.rating <= 2.5) and (user.facebookSettings[2] or (rating.has_review and user.facebookSettings[0]))):
                message = "didn't like %s." % (title.title)
            elif((rating.rating > 2.5 and rating.rating <= 3.5) and (user.facebookSettings[3] or (rating.has_review and user.facebookSettings[0]))):
                message = "thought %s was ok." % (title.title)
            elif((rating.rating > 3.5 and rating.rating <= 4.5) and (user.facebookSettings[4] or (rating.has_review and user.facebookSettings[0]))):
                message = "liked %s." % (title.title)
            elif(rating.rating == 5 and (user.facebookSettings[5] or (rating.has_review and user.facebookSettings[0]))):
                message = "loved %s." % (title.title)
            if(user.facebookSettings[0] and rating.has_review):
                message = message + " Review:"
            if(message != ""):
                message = "%s %s" % (message, bitlyurl)
                login = user.logins.filter('provider_name =', 'facebook').get()
                if login:
                    logging.info('Facebooking %s.  ID: %s' % (message, user.facebook_id))
                    self.facebook_request( '/me/feed',
                        access_token=login.oauth_token,
                        callback=self._on_fb_result,
                        post_args={'message': message})
                    user.lastshare = datetime.now()
                    user.put()

        return ''

    def _on_twitter_result(self, data):
        if not data:
            logging.error('Tweet failed')
        return
    def _on_fb_result(self, data):
        if not data:
            logging.error('FB failed')
        return

class WorkerAddFriendRating(RequestHandler):
    def post(self):
        user_key = self.request.form.get('user_key')
        title_key = self.request.form.get('title_key')
        rating_key = self.request.form.get('rating_key')

        user = MyUser.get_by_key_name(user_key)
        if not user:
			return ''

        for i in range(1,user.follower_indexes+1):
            shard_name = 'index' + str(i)
            followerIdx = FollowerIndex.get_by_key_name(shard_name,parent=user)
            if followerIdx:
                fntrs = []
                for follower in followerIdx.followers:
                    fntr = FriendNetflixTitleRatings.get_by_key_name(follower+'-'+title_key)
                    if fntr is None:
                        fntr = FriendNetflixTitleRatings.get_or_insert(key_name=follower+'-'+title_key)
                    if fntr.ratings is None:
                        fntr.ratings = []
                    if rating_key in fntr.ratings:
                        continue
                    if len(fntr.ratings) >= 20:
                        fntr.ratings.pop()
                    fntr.ratings.insert(0,rating_key)
                    fntrs.append(fntr)

                db.put(fntrs)

        return ''

class WorkerAddAmazon(RequestHandler):
    def post(self):

        title_key = self.request.form.get('title_key')
        title = NetflixTitle.get_by_key_name(title_key);
        if not title:
			return ''
        PyECS.setLicenseKey('AKIAINRBYW54VUIMAMMA')
        PyECS.setSecretKey('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')
        ASIN = None
        soundtrackASIN = None
        if title.ASIN is None:
            try:
                results = PyECS.ItemSearch(str(title.release_year), SearchIndex="DVD", Availability=None, Title=title.title, Power=None, BrowseNode=None, Artist=None, Author=None, Actor=None, Director=None, AudienceRating=None, Manufacturer=None, MusicLabel=None, Composer=None, Publisher=None, Brand=None, Conductor=None, Orchestra=None, TextStream=None, ItemPage=None, OfferPage=None, ReviewPage=None, Sort=None, City=None, Cuisine=None, Neighborhood=None, MinimumPrice=None, MaximumPrice=None, MerchantId="Amazon", Condition="New", DeliveryMethod=None, ResponseGroup='ItemIds')
                if results.cache:
                    ASIN = results.cache[0].ASIN
            except PyECS.ECommerceServiceNoExactMatches, e:
                pass
            except Exception, e:
                logging.exception(e)
                return ''
        if title.soundtrackASIN is None:
            try:
                results = PyECS.ItemSearch(title.title + ' soundtrack', SearchIndex="DigitalMusic", Availability=None, Title=None, Power=None, BrowseNode=None, Artist=None, Author=None, Actor=None, Director=None, AudienceRating=None, Manufacturer=None, MusicLabel=None, Composer=None, Publisher=None, Brand=None, Conductor=None, Orchestra=None, TextStream=None, ItemPage=None, OfferPage=None, ReviewPage=None, Sort=None, City=None, Cuisine=None, Neighborhood=None, MinimumPrice=None, MaximumPrice=None, MerchantId="Amazon", Condition="New", DeliveryMethod=None, ResponseGroup='ItemIds')
                if results.cache:
                    soundtrackASIN = results.cache[0].ASIN
            except PyECS.ECommerceServiceNoExactMatches, e:
                pass
            except Exception, e:
                logging.exception(e)
                return ''

        if ASIN is None and soundtrackASIN is None:
			return ''

        def txn():
            title = NetflixTitle.get_by_key_name(title_key);
            if ASIN is not None:
                title.ASIN = ASIN
            if soundtrackASIN is not None:
                title.soundtrackASIN = soundtrackASIN
            title.put()
        db.run_in_transaction(txn)
        return ''


class WorkerAddMetacritic(RequestHandler):
    def post(self):

        title_key = self.request.form.get('title_key')

        movie = NetflixTitle.get_by_key_name(title_key);
            #slugtitle = str(movie.slugify('-'))
            #url = 'http://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20html%20where%20url%3D%22http%3A%2F%2Fwww.rottentomatoes.com%2Fm%2F'+slugtitle+'%22%20and%20xpath%3D\'%2F%2Fspan%5B%40id%3D%22all-critics-meter%22%5D\'&format=json'
            #response = self._parsemovie(urlfetch.fetch(url, deadline=10))
            #if(response and response['query']['results']):
            #    results = response['query']['results']['span'][0]['content']
            #    movie.rotten_rating = int(results)
        slugtitle = str(movie.slugify('-'))
        url = 'http://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20html%20where%20url%3D%22http%3A%2F%2Fwww.metacritic.com%2Fmovie%2F'+slugtitle+'%22%20and%20xpath%3D\'%2F%2Fspan%5B%40class%3D%22score_value%22%5D\'&format=json'
        response = urlfetch.fetch(url, deadline=10)

        if not response:
            logging.warning('Could not get movie request.')
            return ''
        elif response.status_code < 200 or response.status_code >= 300:
            logging.warning('Invalid movie response (%d): %s', response.status_code, response.content)
            return ''
        response = simplejson.loads(response.content)

        if(response and response['query']['results']):
            try:
                results = response['query']['results']['span'][0]['content']
            except:
                results = response['query']['results']['span']['content']
            def txn():
                movie = NetflixTitle.get_by_key_name(title_key);
                try:
                    movie.metacritic_rating = int(results)
                    movie.put()
                except ValueError:
                    logging.error('Metacritic ValueError: slugtitle: %s, rating: %s', slugtitle, results)
                    return ''
            db.run_in_transaction(txn)
        return ''

class WorkerAddTrailer(RequestHandler):
    def post(self):
        from xml.dom import minidom
        from xml.parsers import expat
        title_key = self.request.form.get('title_key')

        movie = NetflixTitle.get_by_key_name(title_key);
        slugtitle = str(movie.slugify('-'))
        url = 'http://simpleapi.traileraddict.com/trailer/'+slugtitle+'/trailer'
        response = urlfetch.fetch(url, deadline=10)

        if not response:
            logging.warning('Could not get movie request.')
            return ''
        elif response.status_code < 200 or response.status_code >= 300:
            logging.warning('Invalid movie response (%d): %s', response.status_code, response.content)
            return ''
        try:
            response = minidom.parseString(response.content)
        except expat.ExpatError, e:
            return ''

        if(response and response.getElementsByTagName("trailer")):
            trailer_id = response.getElementsByTagName("trailer")[0].getElementsByTagName("trailer_id")[0].firstChild.data
            def txn():
                movie = NetflixTitle.get_by_key_name(title_key);
                movie.traileraddict_id = trailer_id
                movie.put()
            db.run_in_transaction(txn)
        logging.info('Movie trailer added %s.' % movie.title)
        return ''


class WorkerAddTitle(RequestHandler):
    def post(self):
                from django.utils import simplejson
                import urllib
                title_id = self.request.form.get('title_id')
                item = self.request.form.get('item')
                item = simplejson.loads(item)

                title = NetflixTitle(key_name=title_id, title=unicode(item.get('title').get('regular')))
                title.box_art = item.get('box_art').get('large')
                title.title_id = title_id
                title.average_rating = float(item.get('average_rating','0.0'))
                title.title_id_num = title_id[title_id.rfind('/')+1:]
                title.release_year = int(item.get('release_year'))
                try:
                    for category in item['category']:
                        if (category['scheme'] == 'http://api.netflix.com/categories/mpaa_ratings' or  category['scheme'] == 'http://api.netflix.com/categories/tv_ratings'):
                            title.rating = category['term']
                except:
                    category = item.get('category')
                    if category:
                        if 'scheme' not in category:
                            logging.info('No category scheme for %s' % category)
                        elif (category['scheme'] == 'http://api.netflix.com/categories/mpaa_ratings' or  category['scheme'] == 'http://api.netflix.com/categories/tv_ratings'):
                            title.rating = category['term']
                    else:
                        logging.info('No category for %s' % title.title_id)
                for link in item['link']:
                    if link['rel'] == 'http://schemas.netflix.com/catalog/titles/synopsis':
                        title.synopsis = link['synopsis']
                urlquery = urllib.urlencode({'$filter':"NetflixApiId eq '"+title_id+"'"})
                try:
                    response = urlfetch.fetch("http://odata.netflix.com/Catalog/Titles?"+urlquery+"&$format=json", deadline=10)
                    data = simplejson.loads(response.content)
                    title.ODataId = data['d']['results'][0]['Id']
                except:
                    logging.error('Unable to get odata for %s' % title_id)
                logging.info('New Movie put %s' % title.title)
                title.put()
                sitemapModel = Sitemap.get_by_key_name('sitemap5')
                if sitemapModel == None:
                    sitemapModel = Sitemap(key_name='sitemap5')
                    sitemapModel.sitemap = ''
                try:
                    sitemapModel.sitemap += '<url><loc>http://www.friendsonnetflix.com/title/%s/%s</loc><changefreq>daily</changefreq><priority>0.8</priority></url>' % (title.slugify(), title.key().name().replace('http://api.netflix.com/catalog/titles/', ''))
                    sitemapModel.put()
                except:
                    logging.error('sitemap5 Failed, skipping. Length: %s.' % len(sitemapModel.sitemap))
                    
                addTask(url='/workeraddamazon', params={'title_key':title_id})
                addTask(url='/workeraddmetacritic', params={'title_key':title_id})
                addTask(url='/workeraddtrailer', params={'title_key':title_id})
                return ''

class NetflixUpdateHandler(RequestHandler, NetflixMixin):
    def get(self):
        q = Login.all().filter('provider_name =', 'netflix').filter('last_import <',  datetime.utcnow() - timedelta(minutes=30))
        nflxlogins = []
        while True:
            logins = q.fetch(1000)
            nflxlogins.extend(logins)
            if len(nflxlogins) < 1000:
                break;
            cursor = q.cursor()
            q.with_cursor(last_cursor)

        for login in nflxlogins:
            login.last_import = datetime.now()
            login.put()
            numrat = self.oauth_load_ratings_recent(login.user, login)
            #numrev = self.oauth_load_reviews_recent(login.user, login)
        return ""

class AmazonGetHandler(RequestHandler):
    def get(self):
        q = NetflixTitle.all()
        nflxtitles = []
        while True:
            logins = q.fetch(10000)
            nflxtitles.extend(logins)
            if len(logins) < 10000:
                break;
            cursor = q.cursor()
            q.with_cursor(cursor)

        countdown=0
        for title in nflxtitles:
            if title.soundtrackASIN is not None:
                continue
            countdown=countdown+2
            addTask(url='/workeraddamazon', params={'title_key':title.key().name()}, countdown=countdown)

        return str(countdown)
class TrailerGetHandler(RequestHandler):
    def get(self):
        q = NetflixTitle.all()
        nflxtitles = []
        while True:
            logins = q.fetch(10000)
            nflxtitles.extend(logins)
            if len(logins) < 10000:
                break;
            cursor = q.cursor()
            q.with_cursor(cursor)

        countdown=0
        for title in nflxtitles:
            if title.traileraddict_id is not None:
                continue
            countdown=countdown+1
            addTask(url='/workeraddtrailer', params={'title_key':title.key().name()}, countdown=countdown)

        return str(countdown)


class WorkerAddHistory(DeferredHandler, NetflixMixin):
    def post(self):
        from datetime import date
        from time import mktime
        user_key = self.request.form.get('user_key')
        title_ids = self.request.form.get('title_ids')
        logging.info('Deferred Import.  User: %s' % user_key)
        user = MyUser.get_by_key_name(user_key)
        login = user.logins.filter('provider_name =', 'netflix').get()

        self.oauth_load_ratings(user, login, title_ids )
        #self.oauth_load_reviews(user, login, title_ids )

        return ''

class SitemapHandler(RequestHandler):
    def get(self):
        sitemapModel = Sitemap.get_by_key_name('sitemap');
        sitemapModel2 = Sitemap.get_by_key_name('sitemap2');
        sitemapModel3 = Sitemap.get_by_key_name('sitemap3');
        sitemapModel4 = Sitemap.get_by_key_name('sitemap4');
        sitemapModel5 = Sitemap.get_by_key_name('sitemap5');
        sitemapModelUsers1 = Sitemap.get_by_key_name('sitemapusers1');
        return sitemapModel.sitemap + sitemapModel2.sitemap + sitemapModel3.sitemap + sitemapModel4.sitemap + sitemapModel5.sitemap + sitemapModelUsers1.sitemap+'</urlset>'

class SitemapUpdateHandler(RequestHandler):
    def get(self):
        q = NetflixTitle.all()
        nflxtitles = []

        count=0
        sitemap = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://www.friendsonnetflix.com/</loc><changefreq>weekly</changefreq><priority>0.9</priority></url><url><loc>http://www.friendsonnetflix.com/auth</loc><changefreq>weekly</changefreq><priority>0.9</priority></url><url><loc>http://www.friendsonnetflix.com/faq</loc><changefreq>weekly</changefreq><priority>0.9</priority></url>'

        while True:
            nflxtitles = q.fetch(1000)
            for title in nflxtitles:
                count+=1
                sitemap += '<url><loc>http://www.friendsonnetflix.com/title/%s/%s</loc><changefreq>daily</changefreq><priority>0.8</priority></url>' % (title.slugify(), title.key().name().replace('http://api.netflix.com/catalog/titles/', ''))
            if len(nflxtitles) < 1000:
                break;
            cursor = q.cursor()
            q.with_cursor(cursor)

        sitemapModel = Sitemap.get_by_key_name('sitemap');
        if sitemapModel == None:
            sitemapModel = Sitemap(key_name='sitemap')
        sitemapModel.sitemap = sitemap
        sitemapModel.put()
        return str(count)
class SitemapUpdateUsersHandler(RequestHandler):
    def get(self):
        q = MyUser.all()
        users = []

        sitemap=''
        count=0
        while True:
            users = q.fetch(1000)
            for usr in users:
                count+=1
                sitemap += '<url><loc>http://www.friendsonnetflix.com/profile/%s</loc><changefreq>daily</changefreq><priority>0.8</priority></url>' % (usr.key().name())
            if len(users) < 1000:
                break;
            cursor = q.cursor()
            q.with_cursor(cursor)

        sitemapModel = Sitemap.get_by_key_name('sitemapusers1');
        if sitemapModel == None:
            sitemapModel = Sitemap(key_name='sitemapusers1')
        sitemapModel.sitemap = sitemap
        sitemapModel.put()
        return str(count)    

def addTask(url, params={}, name=None, countdown=0):
    try:
        task = taskqueue.Task(url=url, params=params, countdown=countdown)
        if name:
            task = taskqueue.Task(name=name, url=url, params=params, countdown=countdown)
        task.add()
    except taskqueue.TaskAlreadyExistsError:
        pass
    except taskqueue.TombstonedTaskError, e:
        logging.error('TombstonedTaskError error.  Name: %s' % name)
        pass
    except taskqueue.TransientError, e:
        logging.exception("adding Task failed with a TransientError")
        addTask(url, params, name)
    except apiproxy_errors.OverQuotaError, e:
        #but keep going
        logging.exception("adding Task failed with a OverQuotaError")