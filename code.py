# Copyright 2009 John Wiseman <jjwiseman@gmail.com>

from __future__ import with_statement

import os
import logging
import pprint
import time
import sys

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from django.utils import simplejson

import oauth
import gmemsess
import foursquare


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

    # Have we authorized this user?
    if 'user_token' in session:
      authorized = True
    else:
      authorized = False
      
    # Get the appropriate google maps API key; there's one for
    # 4mapper.appspot.com and one for localhost (for testing).
    host = self.request.headers['Host'].split(':')[0]
    gmaps_api_key = get_key('gmaps-api-key-%s' % (host,))

    template_values = {'gmaps_api_key': gmaps_api_key,
                       'authorized': authorized}
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
    app_token = fsrequest_token()
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
    session.save()
    self.redirect('/')

class FourHistory(webapp.RequestHandler):
  """This is an Ajax endpoint that returns a user's checkin history.
  Requires foursquare authorization.
  """
  def get(self):
    session = gmemsess.Session(self)
    fs = get_foursquare(session)
    user_token = oauth.OAuthToken.from_string(session['user_token'])
    start_time = time.time()
    history = fs.history(l=250)
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

    sys.stderr.write(simplejson.dumps(user) + '\n')
    self.response.out.write(simplejson.dumps(user))
    

application = webapp.WSGIApplication([('/authorize', Authorize),
                                      ('/oauth_callback', OAuthCallback),
                                      ('/4/history', FourHistory),
                                      ('/4/user', FourUser),
                                      ('/', MainPage)],
                                     #debug=True
                                     )

def main():
  run_wsgi_app(application)
    
if __name__ == "__main__":
  main()
