# Copyright 2009 John Wiseman <jjwiseman@gmail.com>

from __future__ import with_statement

import os
import logging
import pprint
import time
import sys
import datetime

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from django.utils import simplejson
from google.appengine.ext import db


import oauth
import gmemsess
import foursquare


class FourMapperException(Exception):
  pass


class History(db.Model):
  uid = db.IntegerProperty(required=True)
  history = db.TextProperty()
  history_date = db.DateTimeProperty()
  public = db.BooleanProperty()
  name = db.StringProperty()
  picture = db.StringProperty()

def get_user_record(uid):
  user_q = History.all().filter('uid =', uid)
  logging.info('user_q: %s' % (user_q,))
  users = user_q.fetch(2)
  logging.info('users: %s', users)
  if len(users) > 1:
    logging.error('Multiple records for uid %s' % (uid,))

  if len(users) > 0:
    return users[0]
  else:
    return None

def make_user_record(uid, name, picture):
  return History(uid=uid, public=False, name=name, picture=picture)



TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

def render_template(name, values):
  return template.render(os.path.join(TEMPLATE_PATH, name), values)


def safer_eval(s):
  return eval(s, {'__builtins__': None}, {})


key_cache = {}

def get_key(name, secret=False):
  if name in key_cache:
    return key_cache[name]

  if secret:
    extension = 'secret'
  else:
    extension = 'key'
    
  path = os.path.join('keys', '%s.%s' % (name, extension))
  with open(path, 'r') as f:
    value = safer_eval(f.read())
  key_cache[name] = value
  return value


class MainPage(webapp.RequestHandler):
  "This is the main app page."
  def get(self):
    session = gmemsess.Session(self)

    do_map = False
    map_uid = 0
    map_user_photo = ""
    map_user_name = ""
    uid = 0
    user_photo = ""
    user_name = ""
    authorized = False
    history_is_public = False
    
    # Have we authorized this user?
    if 'user_token' in session:
      authorized = True
      do_map = True
      map_uid = session['uid']
      user = get_user_record(map_uid)
      if user:
        history_is_public = user.public
        uid = map_uid
        user_photo = user.picture
        user_name = user.name
        map_user_photo = user_photo
        map_user_name = user_name
    

    # Get the appropriate google maps API key; there's one for
    # 4mapper.appspot.com and one for localhost (for testing).
    host = self.request.headers['Host'].split(':')[0]
    gmaps_api_key = get_key('gmaps-api-key-%s' % (host,))

    if 'uid' in self.request.arguments():
      map_uid = int(self.request.get('uid'))
      map_user = get_user_record(map_uid)
      map_user_photo = map_user.picture
      map_user_name = map_user.name
      do_map = True

      
    template_values = {'gmaps_api_key': gmaps_api_key,
                       'authorized': authorized,
                       'history_is_public': history_is_public,
                       'uid': uid,
                       'map_uid': map_uid,
                       'map_user_photo': '%s' % (map_user_photo,),
                       'map_user_name': '%s' % (map_user_name,),
                       'user_photo': '%s' % (user_photo,),
                       'user_name': '%s' % (user_name,),
                       'do_map': do_map,
                       'do_map_js': ('%s' % (do_map,)).lower()}
    logging.info(template_values)
    self.response.out.write(render_template('index.html', template_values))


def get_foursquare(session):
  """Returns an instance of the foursquare API initialized with our
  oauth info.
  """
  oauth_consumer_key = get_key('foursquare-oauth-consumer-key', secret=True)
  oauth_consumer_secret = get_key('foursquare-oauth-consumer-secret', secret=True)
  fs = foursquare.Foursquare(foursquare.OAuthCredentials(oauth_consumer_key, oauth_consumer_secret))
  if 'user_token' in session:
    user_token = oauth.OAuthToken.from_string(session['user_token'])
    fs.credentials.set_access_token(user_token)
  return fs

class Authorize(webapp.RequestHandler):
  """This page is used to do the oauth dance.  It gets an app token
  from foursquare, saves it in the session, then redirects to the
  foursquare authorization page.  That authorization page then
  redirects to /oauth_callback.
  """
  def get(self):
    return self.run()

  def post(self):
    return self.run()
  
  def run(self):
    session = gmemsess.Session(self)
    fs = get_foursquare(session)
    app_token = fs.request_token()
    auth_url = fs.authorize(app_token)
    session['app_token'] = app_token.to_string()
    session.save()
    self.redirect(auth_url)


class OAuthCallback(webapp.RequestHandler):
  """This is our oauth callback, which the foursquare authorization
  page will redirect to.  It gets the user token from foursquare,
  saves it in the session, and redirects to the main page.
  """
  def get(self):
    session = gmemsess.Session(self)
    fs = get_foursquare(session)
    app_token = oauth.OAuthToken.from_string(session['app_token'])
    user_token = fs.access_token(app_token)
    session['user_token'] = user_token.to_string()

    fs.credentials.set_access_token(user_token)
    uid = fs.user()['user']['id']
    session['uid'] = uid
    session.save()
    self.redirect('/')

class FourHistory(webapp.RequestHandler):
  """This is an Ajax endpoint that returns a user's checkin history.
  Requires foursquare authorization.
  """
  def get(self):
    session = gmemsess.Session(self)
    fs = get_foursquare(session)
    start_time = time.time()

    # Are we getting the current user's history, in which case we'll
    # ask foursquare so as to get the latest info, or are we
    # retrieving someone else's history?
    if 'uid' in self.request.arguments() and \
       (not 'uid' in session or int(self.request.get('uid')) != session['uid']):
      uid = int(self.request.get('uid'))
      user_record = get_user_record(uid)
      logging.info('got user record %s' % (user_record,))
      if not user_record:
        raise FourMapperException('No history for user %s' % (uid,))

      if not user_record.public:
        current_user = session['uid']
        logging.info('current: %s, uid: %s' % (`current_user`, `uid`))
        if current_user != uid:
          raise FourMapperException('No history for user %s.' % (uid,))
      history = simplejson.loads(user_record.history)
      
    else:
      # Get latest history for current user.
      history = fs.history(l=250)

      # Store the history.
      user = fs.user()['user']
      uid = user['id']
      history_s = simplejson.dumps(history)
      logging.info('Storing history for user %s (%s bytes)' % (uid, len(history_s)))
      user_record = get_user_record(uid)
      if not user_record:
        logging.debug('(This is a new record.)')
        user_record = make_user_record(uid, user['firstname'], user['photo'])
      user_record.history = history_s
      user_record.history_date = datetime.datetime.now()
      logging.info('creating record %s, %s, %s' % \
                   (user_record.uid, user_record.name, user_record.picture))
                    
      user_record.put()

    logging.info('history took %.3f s' % (time.time() - start_time,))
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write(simplejson.dumps(history))

class FourUser(webapp.RequestHandler):
  def get(self):
    session = gmemsess.Session(self)
    fs = get_foursquare(session)
    start_time = time.time()
    user = fs.user()
    logging.info('user took %.3f s' % (time.time() - start_time,))
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write(simplejson.dumps(user))


class ToggleHistoryAccess(webapp.RequestHandler):
  def get(self):
    session = gmemsess.Session(self)
    user_record = get_user_record(session['uid'])
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write(simplejson.dumps(user_record.public))

  def post(self):
    session = gmemsess.Session(self)
    fs = get_foursquare(session)
    user = fs.user()['user']
    uid = user['id']
    user_record = get_user_record(uid)
    if not user_record:
      user_record = make_user_record(uid, user['firstname'], user['photo'])
    logging.info('Changing public for uid %s from %s to %s' %
                 (uid, user_record.public, not user_record.public))
    user_record.public = not user_record.public
    user_record.put()
    if 'r' in self.request.arguments():
      self.redirect(self.request.get('r'))
    
  
class Logout(webapp.RequestHandler):
  def get(self):
    session = gmemsess.Session(self)
    session.invalidate()
    self.redirect('/')


class GetPublicIds(webapp.RequestHandler):
  def get(self):
    user_q = History.gql('WHERE public = :1 ORDER BY history_date DESC', True)
    users = user_q.fetch(7)
    logging.info(users)
    def user_dict(user):
      return {'name': user.name, 'uid': user.uid, 'picture': user.picture}
    results = [user_dict(u) for u in users]
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write(simplejson.dumps(results))
    

application = webapp.WSGIApplication([('/authorize', Authorize),
                                      ('/oauth_callback', OAuthCallback),
                                      ('/logout', Logout),
                                      ('/toggle_public', ToggleHistoryAccess),
                                      ('/s/public', GetPublicIds),
                                      ('/4/history', FourHistory),
                                      ('/4/user', FourUser),
                                      ('/', MainPage)],
                                     #debug=True
                                     )

def main():
  run_wsgi_app(application)
    
if __name__ == "__main__":
  main()
