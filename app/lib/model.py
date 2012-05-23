# -*- coding: utf-8 -*-
"""
    tipfy.ext.auth.rpx
    ~~~~~~~~~~~~~~~~~~

    RPX/JanRain Engage authentication for tipfy.

    :copyright: 2010 Ragan Webber.
    :license: Apache, see LICENSE.txt for more details.
"""

from google.appengine.ext import db
from tipfy.ext.auth.model import User

class MyUser(User):
    twitter_name = db.StringProperty()
    facebook_id = db.StringProperty()
    has_netflix = db.BooleanProperty(default=False)
    last_netflix_rating = db.IntegerProperty(default=0)
    last_netflix_review = db.IntegerProperty(default=0)
    follower_indexes = db.IntegerProperty(default=1)
    rating_count = db.IntegerProperty(default=0)
    review_count = db.IntegerProperty(default=0)
    twitterSettings = db.ListProperty(bool, default=[False, False, False, False, False, False])
    facebookSettings = db.ListProperty(bool, default=[False, False, False, False, False, False])
    lastshare = db.DateTimeProperty()
    #follower_count = db.IntegerProperty(default=0)
    #friend_count = db.IntegerProperty(default=0)
    def getFriends(self):
        users = []
        index_keys = db.GqlQuery("SELECT __key__ FROM FollowerIndex WHERE followers = :subscriber ORDER BY __key__ DESC", subscriber=self.key().name()).fetch(20)
        keys = [k.parent() for k in index_keys]
        usrs = MyUser.get(keys)
        for rt in usrs:
            if rt is not None:
                users.append(rt)
        users.sort(key=lambda x: x.last_netflix_rating, reverse=True)
        return users

class FollowerIndex(db.Model):
    followers = db.StringListProperty()

class Login(db.Expando):
    """A RPX login for a user
    """
    #: Creation date.
    created = db.DateTimeProperty(auto_now_add=True)
    #: Modification date.
    updated = db.DateTimeProperty(auto_now=True)
    #: Provider Name
    provider_name = db.StringProperty(required=True)
    #: Name on provider system
    provider_id = db.StringProperty(default=None)
    username = db.StringProperty(default=None)
    #: User Reference
    user = db.ReferenceProperty(MyUser,required=True,collection_name='logins')
    oauth_token = db.StringProperty(default=None)
    oauth_token_secret = db.StringProperty(default=None)
    friendids = db.StringListProperty()
    last_import = db.DateTimeProperty()

    @classmethod
    def get_by_login_id(cls, login_id):
        return cls.get_by_key_name(login_id)

    @classmethod
    def get_user_by_login_id(cls, login_id):
        login = cls.get_by_login_id(login_id)
        if login:
            return login.user
        else:
            return None

    @classmethod
    def get_users_by_friendid(cls, provider, friendid):
        #return db.GqlQuery("SELECT user FROM Logins WHERE provider_name = :1 AND friendids = :2",provider, friendid)
        """
        Count *all* of the rows (without maxing out at 1000)
        """
        count = 0
        if provider == 'twitter':
            query = db.GqlQuery("SELECT * FROM TwitterFriendsTBD WHERE friendids = :1 ORDER BY __key__", friendid)
        elif provider == 'facebook':
            query = db.GqlQuery("SELECT * FROM FacebookFriendsTBD WHERE friendids = :1 ORDER BY __key__", friendid)
        users = []
        while 1:
                logins = query.fetch(1000)
                current_count = query.count()
                count += current_count
                if current_count == 0:
                        break
                for alogin in logins:
                    users.append(alogin.user)
                query.with_cursor(query.cursor())

        """
        while 1:
                current_count = query.count()
                count += current_count
                if current_count == 0:
                        break
                logins = query.fetch(1000)
                last_key = None
                for alogin in logins:
                    users.append(alogin.user)
                    last_key = alogin.key()
                query = query.filter('__key__ > ', last_key)
        """
        return users

    @classmethod
    def create(cls, user, login_id, **kwargs):
        """Creates a new user and returns it. If the username already exists,
        returns None.

        :param user:
            User entity
        :param login_id:
            RPX login id
        :param kwargs:
            Additional entity attributes.
        :return:
            The newly created login
        """
        kwargs['user'] = user
        kwargs['key_name'] = login_id
        kwargs['login_id'] = login_id

        def txn():
            login = cls(**kwargs)
            login.put()
            return login

        return db.run_in_transaction(txn)

    def __unicode__(self):
        """Returns username.

        :return:
            Username, as unicode.
        """
        return unicode(self.provider_name)

    def __str__(self):
        """Returns username.

        :return:
            Username, as unicode.
        """
        return self.__unicode__()

    def __eq__(self, obj):
        """Compares this user entity with another one.

        :return:
            ``True`` if both entities have same key, ``False`` otherwise.
        """
        if not obj:
            return False

        return str(self.key()) == str(obj.key())

    def __ne__(self, obj):
        """Compares this user entity with another one.

        :return:
            ``True`` if both entities don't have same key, ``False`` otherwise.
        """
        return not self.__eq__(obj)

class NetflixTitle(db.Model):
    #: Creation date.
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    title = db.StringProperty(required=True)
    title_id = db.StringProperty(default=None)
    average_rating = db.FloatProperty()
    box_art = db.StringProperty()
    rating = db.StringProperty()
    title_id_num = db.StringProperty()
    synopsis = db.TextProperty()
    release_year = db.IntegerProperty()
    metacritic_rating = db.IntegerProperty()
    ASIN = db.StringProperty()
    soundtrackASIN = db.StringProperty()
    traileraddict_id = db.StringProperty()
    ODataId = db.StringProperty()
    def big_box_art(self):
        return self.box_art.replace('/large/', '/gsd/')
    def slugify(self, space='-'):
        """
        Adapted from Django's django.template.defaultfilters.slugify.
        """
        #strtitle = unicode(self.title)
        strtitle = self.title
        import unicodedata
        import re
        strtitle = unicodedata.normalize('NFKD', strtitle).encode('ascii', 'ignore')
        strtitle = unicode(re.sub('[^\w\s-]', '', strtitle).strip().lower())
        return re.sub('[-\s]+', space, strtitle)

    @classmethod
    def getRatingFriends(cls, userkey, titlekey):
        ratings = []
        fntr = FriendNetflixTitleRatings.get_by_key_name(userkey+'-'+titlekey)
        if fntr is None:
            return []
        ratingkeys = fntr.ratings
        rts = NetflixRating.get_by_key_name(ratingkeys)
        for rt in rts:
            if rt is not None:
                ratings.append(rt)
        ratings.sort(key=lambda x: x.get_submitted(), reverse=True)
        return ratings


class NetflixRating(db.Model):
    #: Creation date.
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    submitted = db.DateTimeProperty()
    rating = db.FloatProperty()
    review = db.TextProperty()
    title = db.ReferenceProperty(NetflixTitle,required=True,collection_name='ratings')
    user = db.ReferenceProperty(MyUser,required=True,collection_name='ratings')
    has_review = db.BooleanProperty(default=False)

    def set_review(self, data):
        if not data: return
        self.has_review = True
        self.review = data

    def created_format(self):
        import datetime
        return datetime.datetime.strftime(self.updated, '%b %d %Y')
    def rating_format(self):
        return str(self.rating).replace('.0', '')
    def submitted_format(self):
        import datetime
        if self.submitted is None:
            return ""
        return datetime.datetime.strftime(self.submitted, '%b %d %Y')
    def get_submitted(self):
        import datetime
        if self.submitted is not None:
            return self.submitted
        else:
            return datetime.datetime(1900, 1, 1)

    @classmethod
    def getRatingSubs(cls, subscriberkey):
        ratings = []
        index_keys = db.GqlQuery("SELECT __key__ FROM NetflixRatingIndex WHERE followers = :subscriber ORDER BY __key__ DESC", subscriber=subscriberkey).fetch(20)
        keys = [k.parent() for k in index_keys]
        rts = NetflixRating.get(keys)
        for rt in rts:
            if rt is not None:
                ratings.append(rt)
        ratings.sort(key=lambda x: x.get_submitted(), reverse=True)
        return ratings

class FriendNetflixTitleRatings(db.Model): #key = user_key-title_key
    ratings = db.StringListProperty()

class NetflixRatingIndex(db.Model):
    followers = db.StringListProperty()

class Friend(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    from_user = db.ReferenceProperty(MyUser,required=True,collection_name='friends')
    to_user = db.ReferenceProperty(MyUser,required=True,collection_name='followers')

class TwitterFriendsTBD(db.Model):
    user = db.ReferenceProperty(MyUser,required=True,collection_name='twitterfriendstbd')
    friendids = db.StringListProperty()
class FacebookFriendsTBD(db.Model):
    user = db.ReferenceProperty(MyUser,required=True,collection_name='facebookfriendstbd')
    friendids = db.StringListProperty()

class Sitemap(db.Model):
    sitemap = db.TextProperty()