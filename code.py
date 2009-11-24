from __future__ import with_statement

import os
import logging
import pprint

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template

import oauth
import gmemsess
import foursquare


TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

def render_template(name, values):
  return template.render(os.path.join(TEMPLATE, name), values)


key_cache = {}

def get_key(name, secret=False):
  if name in key_cache:
    return key_cache[name]

  if secret:
    extension = '.secret'
  else:
    extension = '.key'
    
  path = os.path.join('keys', '%s.%s' % (name, extension))
  with open(path, 'r') as f:
    value = f.read()
  key_cache[name] = value
  return value


class MainPage(webapp.RequestHandler):
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


class Authorize(webapp.RequestHandler):
  def get(self):
    return self.run()

  def post(self):
    return self.run()
  
  def run(self):
    session = gmemsess.Session(self)
    fs = foursquare.Foursquare('BR2AXY1DFCQQD3R2ZKAWJOVUAQ4DLPH3MH1SMUQJWTKOVCNI', 'XEZHMQMDIFVTDAHVPDAAJIIRNZF0RXORSY5F31PBBQPQGJ5T')
    app_token = fs.call_method('request_token')
    auth_url = fs.authorize(app_token)
    session['app_token'] = app_token.to_string()
    session.save()
    self.redirect(auth_url)

class OAuthCallback(webapp.RequestHandler):
  def get(self):
    logging.warn('got oauth callback')
    session = gmemsess.Session(self)
    logging.warn('session: %s' % (session,))
    fs = foursquare.Foursquare('BR2AXY1DFCQQD3R2ZKAWJOVUAQ4DLPH3MH1SMUQJWTKOVCNI', 'XEZHMQMDIFVTDAHVPDAAJIIRNZF0RXORSY5F31PBBQPQGJ5T')
    app_token = oauth.OAuthToken.from_string(session['app_token'])
    logging.warn('app token: %s' % (app_token,))

    user_token = fs.call_method('access_token', app_token)
    logging.warn('user token1: %s' % (user_token,))
    session['user_token'] = user_token.to_string()
    session.save()
    logging.warn('user token2: %s' % (session['user_token'],))
    self.redirect('/')

class FourHistory(webapp.RequestHandler):
  def get(self):
    logging.info('FourHistory')
    session = gmemsess.Session(self)
    user_token = oauth.OAuthToken.from_string(session['user_token'])
    fs = foursquare.Foursquare('BR2AXY1DFCQQD3R2ZKAWJOVUAQ4DLPH3MH1SMUQJWTKOVCNI', 'XEZHMQMDIFVTDAHVPDAAJIIRNZF0RXORSY5F31PBBQPQGJ5T')
    history = fs.call_method('history', l=250, token=user_token)
    self.response.headers['Content-Type'] = 'text/plain'
    pprint.pprint(history, stream=self.response.out)
    

application = webapp.WSGIApplication([('/authorize', Authorize),
                                      ('/oauth_callback', OAuthCallback),
                                      ('/4/history', FourHistory),
                                      ('/', MainPage)],
                                     debug=True)

def main():
  run_wsgi_app(application)
    
if __name__ == "__main__":
  main()
                                
