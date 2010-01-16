# 4mapper
#
# Copyright 2009 John Wiseman <jjwiseman@gmail.com>

from __future__ import with_statement

import os
import logging
import pprint
import time
import sys
import datetime
import itertools
import math
import collections
import random

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from django.utils import simplejson
from google.appengine.ext import db
from google.appengine.api import users as gaeusers

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
  uid = int(uid)
  user_q = History.gql('WHERE uid = :1', uid)
  logging.info('user_q: %s' % (user_q,))
  users = user_q.fetch(2)
  logging.info('users: %s', users)
  if len(users) > 1:
    logging.error('Multiple records for uid %s' % (uid,))

  logging.info('queried for user %s, got %s records' % (`uid`, len(users)))
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

class AdminPage(webapp.RequestHandler):
  def get(self):
    # Make sure only I can access this.
    user = gaeusers.get_current_user()
    if user:
      self.response.out.write('Hi, %s\n\n' % (user.nickname(),))
      if not gaeusers.is_current_user_admin():
        self.response.out.write('Sorry, you need to be an administrator to view this page.\n')
      else:
        self.response.out.write('Cool, you are an adminnnistrator.\n')

        earliest_date = None
        earliest_user = None
        logging.info('About to get some users.')
        users = db.GqlQuery('SELECT * FROM History')
        logging.info('Got some users: %s' % (users,))
        for user in users:
          logging.info('user: %s %s' % (user.name, user.uid))
          history = simplejson.loads(user.history)
          history_ts = [(c, seconds_since_epoch_of_checkin(c)) for c in history['checkins']]
          history_ts = sorted(history_ts, key=lambda c: c[1])
          if len(history_ts) > 0:
            logging.info('hist: %s' % (history_ts[0],))
            if not earliest_date or history_ts[0][1] < earliest_date:
              earliest_date = history_ts[0][1]
              earliest_user = user.uid
              logging.info('Got new earliest date %s, user %s' % (earliest_date, user.name))
        self.response.out.write('%s %s' % (time.localtime(earliest_date),
                                           earliest_user))
    else:
      self.redirect(gaeusers.create_login_url(self.request.uri))


def seconds_since_epoch_of_checkin(c):
  import rfc822
  try:
    checkin_ts = time.mktime(rfc822.parsedate(c['created']))
  except:
    logging.error("unable to parse date of %s" % (`c`,))
    raise
  return checkin_ts


class MainPage(webapp.RequestHandler):
  "This is the main app page."
  def get(self):
    session = gmemsess.Session(self)

    # These are the template variables we'll be filling.
    session_user = None
    gmap_api_key = ""
    public_users = []
    map_user = None
    
    # Have we authorized this user?
    if 'user_token' in session:
      session_user = get_user_record(session['uid'])    

    # Get the appropriate google maps API key; there's one for
    # 4mapper.appspot.com and one for localhost (for testing).
    host = self.request.headers['Host'].split(':')[0]
    gmaps_api_key = get_key('gmaps-api-key-%s' % (host,))

    # Which user are we mapping (if any)?
    if 'uid' in self.request.arguments():
      map_user = get_user_record(self.request.get('uid'))
    else:
      map_user = session_user

    template_values = {'gmaps_api_key': gmaps_api_key,
                       'session_user': session_user,
                       'map_user': map_user}
    logging.info(template_values)
    self.response.out.write(render_template('index.html', template_values))


class PublicUsersPage(webapp.RequestHandler):
  "This page displays all users with public histories."
  def get(self):
    # Figure out which users have made their histories public.
    public_user_q = History.gql('WHERE public = :1', True)
    public_users = list(public_user_q)
    logging.info('Have %s users with public histories.' % (len(public_users,)))
    # Randomize the order
    random.shuffle(public_users)
    template_values = {'public_users': public_users}
    self.response.out.write(render_template('users.html', template_values))


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
    user = fs.user()['user']
    uid = user['id']
    session['uid'] = uid

    # Make sure this user is in our DB and we save his most up-to-date
    # name and photo.
    user_record = get_user_record(uid)
    if not user_record:
      user_record = make_user_record(uid, user['firstname'], user['photo'])
      user_record.put()
    else:
      user_record.name = user['firstname']
      user_record.picture = user['photo']
      user_record.put()
    
    session.save()
    self.redirect('/')


class FourHistory(webapp.RequestHandler):
  """This is an Ajax endpoint that returns a user's checkin history.
  Requires Foursquare authorization.
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
      if 'checkins' in history:
        history = history['checkins']
      # Now add a seconds-since-epoch version of each checkin
      # timestamp.
      history = add_created_epoch(history)
    else:
      # Get latest history for current user.
      history = get_entire_history(fs)

      # Massage it a little.
      if 'checkins' in history:
        history = history['checkins']
      if history == None:
        history = []

      # Now add a seconds-since-epoch version of each checkin
      # timestamp.
      history = add_created_epoch(history)
      
      # Store the history.
      store_user_history(session['uid'], history)

    logging.info('history took %.3f s' % (time.time() - start_time,))
    self.response.headers['Content-Type'] = 'text/plain'

    result = {'checkins': history,
              'statistics': generate_history_stats(history)}
    
    self.response.out.write(simplejson.dumps(result))

def add_created_epoch(history):
  # Now add a seconds-since-epoch version of each checkin
  # timestamp.
  h = []
  for c in history:
    c['created_epoch'] = checkin_ts = seconds_since_epoch_of_checkin(c)
    h.append(c)
  return h
  

def generate_history_stats(history):
  fn_start_time = time.time()
  day_groups = []
  history = sorted(history, key=lambda c: c['created_epoch'])
  for k, g in itertools.groupby(history,
                                lambda c: datetime.datetime.fromtimestamp(c['created_epoch']).day):
    day_group = list(g)
    day_groups.append((datetime.datetime.fromtimestamp(day_group[0]['created_epoch']),
                       day_group))

  # We'll return checkin counts and distances for the last 365 days.
  checkin_counts = [0] * 365
  distance_traveled = [0.0] * 365

  # Limit checkins to the last 365 days.
  now = datetime.datetime.now()
  cutoff_date = now - datetime.timedelta(days=365)
  day_groups = [(s, g) for (s, g) in day_groups if s >= cutoff_date]

  # Compute checkin counts and distances for each day, and total
  # number of checkins along with number of days with a checkin.
  total_checkin_count = 0
  day_count = len(day_groups)
  for start_time, group in day_groups:
    total_checkin_count += len(group)
    assert start_time >= cutoff_date
    for checkin in group:
      time_delta = now - datetime.datetime.fromtimestamp(checkin['created_epoch'])
      assert time_delta.days < 365
      days_delta = time_delta.days
      index = 364 - time_delta.days
      checkin_counts[index] += 1
    distance_traveled[index] = distance_between_checkins(group)

  # Compute favorites.
  all_favorites, venue_names = favorites_from_last_n_days(day_groups, now, 10000)  # heh, i rebel.
  # Recent favorites are the top venues from the last 30 days.
  recent_favorites, venue_names_2 = favorites_from_last_n_days(day_groups, now, 30)
  venue_names = merge_dicts(venue_names, venue_names_2)

  # New Favorites are anything in the top 5 recent favorites that
  # aren't in the top 20 all-time favorites.
  new_favorites = set_difference(recent_favorites[-5:], all_favorites[-20:], key=FavoriteVenue.vid)
  new_favorites = set_difference(recent_favorites[-5:], all_favorites[-20:], key=FavoriteVenue.vid)
  new_favorites = sorted(new_favorites, key=FavoriteVenue.count)
  # Forgotten favorites are all-time favorites that aren't recent or new favorites.
  forgotten_favorites = set_difference(all_favorites,
                                       set_union(recent_favorites[-10:], new_favorites[-10:], key=FavoriteVenue.vid),
                                       key=FavoriteVenue.vid)
  forgotten_favorites = sorted(forgotten_favorites, key=FavoriteVenue.count)
  

  recent_favorites = [venue_names[fave.vid()] for fave in recent_favorites[-3:]]
  new_favorites = [venue_names[fave.vid()] for fave in new_favorites][-3:]
  forgotten_favorites = [venue_names[fave.vid()] for fave in forgotten_favorites[-3:]]

  logging.info('statistics took %.3f s' % (time.time() - fn_start_time,))
  return {'total_checkins': total_checkin_count,
          'checkin_days': day_count,
          'checkin_counts': checkin_counts,
          'distances': distance_traveled,
          'recent_favorites': recent_favorites,
          'new_favorites': new_favorites,
          'forgotten_favorites': forgotten_favorites,
          'blurb': ''}

def set_difference(a, b, key=lambda x: x):
  a_map = {}
  for e in a:
    a_map[key(e)] = e
  for e in b:
    if key(e) in a_map:
      del a_map[key(e)]
  return a_map.values()

def set_union(a, b, key=lambda x: x):
  result = {}
  for e in a:
    result[key(e)] = e
  for e in b:
    result[key(e)] = e
  return result.values()


class FavoriteVenue:
  def __init__(self, vid, count):
    self.venue_id = vid
    self.checkin_count = count
  def count(self):
    return self.checkin_count
  def vid(self):
    return self.venue_id
    
def favorites_from_last_n_days(day_groups, now, n):
  recent_day_groups = last_n_days(day_groups, now, n)
  recent_venue_counts = collections.defaultdict(int)
  venue_names =  {}
  for s, g in recent_day_groups:
    for checkin in g:
      if 'venue' in checkin and 'id' in checkin['venue']:
        venue = checkin['venue']
        vid = venue['id']
        venue_names[vid] = venue['name']
        recent_venue_counts[vid] += 1
  recent_favorites = [FavoriteVenue(vid, count) for vid, count in recent_venue_counts.items()]
  recent_favorites = sorted(recent_favorites, key=FavoriteVenue.count)
  return recent_favorites, venue_names



def last_n_days(day_groups, now, n):
  cutoff_date = now - datetime.timedelta(days=n)
  day_groups = [(s, g) for (s, g) in day_groups if s > cutoff_date]
  return day_groups

def all_but_last_n_days(day_groups, now, n):
  cutoff_date = now - datetime.timedelta(days=n)
  day_groups = [(s, g) for (s, g) in day_groups if s <= cutoff_date]
  return day_groups

  
def distance_between_checkins(checkins):
  # Filter out checkins that don't have venues or that don't have geo
  # coordinates.
  checkins = [c for c in checkins if 'venue' in c and 'geolat' in c['venue']]
  distance = 0.0
  for a, b in window(checkins, 2):
    d = distance_between(a, b)
#    logging.info('pair: %s %s' % (d, (a, b),))
    distance += d
    assert distance >= 0.0 and distance < 999999999.0, 'Bad distance %s for these checkins: %s' % (d, (a, b))
  return distance

def distance_between(c1, c2):
  def to_rad(d):
    return d * math.pi / 180.0

  v1 = c1['venue']
  v2 = c2['venue']

  lat1 = to_rad(v1['geolat'])
  lon1 = to_rad(v1['geolong'])
  lat2 = to_rad(v2['geolat'])
  lon2 = to_rad(v2['geolong'])
  r = 6371
  p = math.sin(lat1) * math.sin(lat2) + \
      math.cos(lat1) * math.cos(lat2) * \
      math.cos(lon2 - lon1)
  if p >= 1.0:
    d = 0.0
  else:
    d = math.acos(math.sin(lat1) * math.sin(lat2) + \
                  math.cos(lat1) * math.cos(lat2) * \
                  math.cos(lon2 - lon1)) * r
  return d
  


      
      
        
      
def window(seq, n=2):
  "Returns a sliding window (of width n) over data from the iterable"
  "   s -> (s0,s1,...s[n-1]), (s1,s2,...,sn), ...                   "
  it = iter(seq)
  result = tuple(itertools.islice(it, n))
  if len(result) == n:
    yield result    
  for elem in it:
    result = result[1:] + (elem,)
    yield result
  

  
def store_user_history(uid, history):
  history_s = simplejson.dumps(history)
  logging.info('Storing history for user %s (%s bytes)' % (uid, len(history_s)))
  user_record = get_user_record(uid)
  user_record.history = history_s
  user_record.history_date = datetime.datetime.now()
  user_record.put()
  
  
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


HTML_404 = '404 Error'

class PageNotFound(webapp.RequestHandler):
  def get(self):
    self.error(404)
    self.response.out.write(HTML_404)

    


application = webapp.WSGIApplication([('/authorize', Authorize),
                                      ('/oauth_callback', OAuthCallback),
                                      ('/logout', Logout),
                                      ('/toggle_public', ToggleHistoryAccess),
                                      ('/4/history', FourHistory),
                                      ('/4/user', FourUser),
                                      ('/', MainPage),
                                      ('/users', PublicUsersPage),
                                      ('/admin', AdminPage),
                                      ('/.*', PageNotFound)],
                                     #debug=True
                                     )


def get_entire_history(fs):
  history = []
  logging.info('Getting checkins')
  for h in foursquare.history_generator(fs):
    # Annoying that Foursquare uses null/None to indicate zero
    # checkins.
    logging.info('Getting more checkins')
    if h['checkins']:
      history += h['checkins']
  return history

def merge_dicts(a, b):
    if a == None:
        return b
    if b == None:
        return a

    r = {}
    for key, value in a.items():
        r[key] = value
    for key, value in b.items():
        r[key] = value
    return r



def main():
  run_wsgi_app(application)
    
if __name__ == "__main__":
  main()
