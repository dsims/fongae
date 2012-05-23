# -*- coding: utf-8 -*-
"""
    urls
    ~~~~

    URL definitions.

    :copyright: 2009 by tipfy.org.
    :license: BSD, see LICENSE.txt for more details.
"""
from tipfy import Rule, import_string


def get_rules(app):
    """Returns a list of URL rules for the application. The list can be
    defined entirely here or in separate ``urls.py`` files.

    :param app:
        The WSGI application instance.
    :return:
        A list of class:`tipfy.Rule` instances.
    """
    rules = [
        Rule('/', endpoint='home', handler='handlers.HomeHandler'),
        Rule('/sitemap.xml', handler='handlers.SitemapHandler'),
        Rule('/canvaschannel.html', handler='handlers.CanvasChannelHandler'),
        Rule('/faq', endpoint='faq', handler='handlers.FaqHandler'),
        Rule('/auth', endpoint='auth/login', handler='handlers.LoginHandler'),
        Rule('/auth/logout', endpoint='auth/logout', handler='handlers.LogoutHandler'),
        Rule('/auth/signup', endpoint='auth/signup', handler='handlers.SignupHandler'),
        Rule('/auth/register', endpoint='auth/register', handler='handlers.RegisterHandler'),
        Rule('/cron/netflixupdate', handler='handlers.NetflixUpdateHandler'),
        Rule('/cron/sitemapupdate', handler='handlers.SitemapUpdateHandler'),

        Rule('/auth/facebook/', endpoint='auth/facebook', handler='handlers.FacebookAuthHandler'),
        Rule('/auth/friendfeed/', endpoint='auth/friendfeed', handler='handlers.FriendFeedAuthHandler'),
        Rule('/auth/google/', endpoint='auth/google', handler='handlers.GoogleAuthHandler'),
        Rule('/auth/twitter/', endpoint='auth/twitter', handler='handlers.TwitterAuthHandler'),
        Rule('/auth/yahoo/', endpoint='auth/yahoo', handler='handlers.YahooAuthHandler'),
		Rule('/auth/netflix/', endpoint='auth/netflix', handler='handlers.NetflixAuthHandler'),

        Rule('/content', endpoint='content/index', handler='handlers.RatingsHandler'),
        Rule('/ratings', endpoint='ratings/index', handler='handlers.RatingsHandler'),
        Rule('/ratings/download', endpoint='ratings/download', handler='handlers.DownloadRatingsHandler'),
        Rule('/review/<review_id>/<slug>', endpoint='ratings/view', handler='handlers.RatingViewHandler'),
        Rule('/profile/<user_name>', endpoint='user/profile', handler='handlers.ProfileHandler'),
        Rule('/title/<slug>/<path:title_id>', endpoint='title/index', handler='handlers.TitleHandler'),
        Rule('/lookup', endpoint='title/lookup', handler='handlers.TitleLookupHandler'),
        Rule('/title2/<slug>/<path:title_id>', endpoint='title2/index', handler='handlers.TitleHandler2'),
        Rule('/titleembed/', endpoint='title/embed', handler='handlers.TitleEmbedHandler'),
		Rule('/netflix/', endpoint='update/netflix', handler='handlers.NetflixFetchHandler'),
        Rule('/netflixdialog/', endpoint='dialog/netflix', handler='handlers.NetflixDialogHandler'),
        Rule('/twitterdialog/', endpoint='dialog/twitter', handler='handlers.TwitterDialogHandler'),
        Rule('/dohistory/', endpoint='update/history', handler='handlers.HistoryHandler'),		
		#Rule('/netflix/', endpoint='netflix', handler='handlers.NetflixViewHandler'),
        Rule('/twitter/', endpoint='update/twitter', handler='handlers.TwitterFetchHandler'),
		Rule('/facebook/', endpoint='update/facebook', handler='handlers.FacebookFetchHandler'),
        Rule('/twitter/settings/', endpoint='settings/twitter', handler='handlers.TwitterSettingsHandler'),
		Rule('/facebook/settings/', endpoint='settings/facebook', handler='handlers.FacebookSettingsHandler'),
		Rule('/workeraddfriend', endpoint='worker/addfriend', handler='handlers.WorkerAddFollower'),
        Rule('/workeraddrating', endpoint='worker/addrating', handler='handlers.WorkerAddRating'),
        Rule('/workeraddreview', endpoint='worker/addreview', handler='handlers.WorkerAddReview'),
        Rule('/workersharerating', endpoint='worker/sharerating', handler='handlers.WorkerShareRating'),
        Rule('/workersharereview', endpoint='worker/sharereview', handler='handlers.WorkerShareReview'),
        Rule('/workeraddhistory', endpoint='worker/addhistory', handler='handlers.WorkerAddHistory'),
        Rule('/newfriend', endpoint='user/newfriend', handler='handlers.NewFriend'),		

        Rule('/workeraddamazon', endpoint='worker/addamazon', handler='handlers.WorkerAddAmazon'),
        Rule('/workeraddmetacritic', endpoint='worker/addmetacritic', handler='handlers.WorkerAddMetacritic'),
        Rule('/workeraddfriendrating', endpoint='worker/addfriendrating', handler='handlers.WorkerAddFriendRating'),
        Rule('/workeraddtitle', endpoint='worker/addtitle', handler='handlers.WorkerAddTitle'),
        Rule('/workeraddtrailer', endpoint='worker/addtrailer', handler='handlers.WorkerAddTrailer'),

        Rule('/refreshamazon/', endpoint='load/getamazon', handler='handlers.AmazonGetHandler'),
        Rule('/refreshtrailer/', endpoint='load/gettrailer', handler='handlers.TrailerGetHandler'),
        Rule('/refreshsitemap/', endpoint='load/sitemap', handler='handlers.RefreshSitemapHandler'),
        Rule('/updatesitemapusers', endpoint='update/sitemapusers', handler='handlers.SitemapUpdateUsersHandler'),

        Rule('/docountratings/', endpoint='ratings/docount', handler='handlers.DoCountRatingsHandler'),
        Rule('/countratings/', endpoint='ratings/count', handler='handlers.CountRatingsHandler'),
        Rule('/testview/', endpoint='test/view', handler='handlers.TestViewHandler'),
        Rule('/_ah/queue/deferred', endpoint='tasks/deferred', handler='tipfy.ext.taskqueue:DeferredHandler')
    ]

    return rules
