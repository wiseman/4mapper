"""
Foursquare API Python module
by John Wiseman <jjwiseman@gmail.com>

Based on a Fire Eagle module by Steve Marshall <steve@nascentguruism.com>.

Example usage:

>>> from foursquare import Foursquare
>>> fs = Foursquare(YOUR_CONSUMER_KEY, YOUR_CONSUMER_SECRET)
>>> application_token = fs.request_token()
>>> auth_url          = fs.authorize( application_token )
>>> print auth_url
>>> pause( 'Please authorize the app at that URL!' )
>>> user_token        = fs.access_token( application_token )
>>> pprint fs.history()
"""

import datetime, httplib, re, string
from xml.dom import minidom
import time

import oauth
import logging


# General API setup
API_PROTOCOL = 'http'
API_SERVER   = 'api.foursquare.com'
API_VERSION  = 'v1'

OAUTH_SERVER = 'foursquare.com'

# Calling templates
API_URL_TEMPLATE   = string.Template(
    API_PROTOCOL + '://' + API_SERVER + '/' + API_VERSION + '/${method}'
)
OAUTH_URL_TEMPLATE = string.Template(
    API_PROTOCOL + '://' + OAUTH_SERVER + '/oauth/${method}'
)
POST_HEADERS = {
    'Content-type': 'application/x-www-form-urlencoded',
    'Accept'      : 'text/plain'
}

# Error templates
NULL_ARGUMENT_EXCEPTION    = string.Template(
    'Too few arguments were supplied for the method ${method}; required arguments are: ${args}'
)
# TODO: Allow specification of method name and call-stack?
SPECIFIED_ERROR_EXCEPTION   = string.Template(
    '${message} (Code ${code})'
)
UNSPECIFIED_ERROR_EXCEPTION = string.Template(
    'An error occurred whilst trying to execute the requested method, and the server responded with status ${status}.'
)

# Attribute conversion functions
string  = lambda s: s.encode('utf8')
boolean = lambda s: 'true' == s.lower()


def geo_int(s):
    if s == '':
        return None
    else:
        return int(s)
    
def geo_float(s):
    if s == '':
        return None
    else:
        return float(s)
    
def geo_str(s):
    if 0 == len(s):
        return None
    # TODO: Would this be better served returning an array of floats?
    return [float(bit) for bit in s.split(' ')]

def date(s):
    return time.strptime(s[:-6], '%a, %d %b %y %H:%M:%S')

    # 2008-02-08T10:49:03-08:00
    bits = re.match(r"""
        ^(\d{4}) # Year          ($1)
        -(\d{2}) # Month         ($2)
        -(\d{2}) # Day           ($3)
        T(\d{2}) # Hour          ($4)
        :(\d{2}) # Minute        ($5)
        :(\d{2}) # Second        ($6)
        [+-]   # TODO: TZ offset dir ($7)
        \d{2}  # TODO: Offset hour   ($8)
        :\d{2} # TODO: Offset min    ($9)
    """, s, re.VERBOSE
    ).groups()
    bits = [bit for bit in bits if bit is not None]
    
    # TODO: Generate fixed-offset tzinfo
    return datetime.datetime(*map(int, bits))

def boolean(s):
    s = s.lower()
    return s == 'true'
    
# Return types
CITY_T = 'city', {
    'id': string,
    'name': string,
    'geolat': geo_float,
    'geolong': geo_float
    }

BADGE_T = 'badge', {
    'name': string,
    'icon': string,
    'description': string
    }

BADGES_T = 'badges', {
    'badge': BADGE_T
    }

VENUE_T = 'venue', {
    'id': geo_int,
    'name': string,
    'address': string,
    'crossstreet': string,
    'city': string,
    'state': string,
    'zip': string,
    'geolat': geo_float,
    'geolong': geo_float,
    'phone': string
    }

CHECKIN_T = 'checkin', {
    'id': string,
    'venue': VENUE_T,
    'shout': string,
    'created': date
    }

SETTINGS_T = 'settings', {
    'feeds_key': string,
    'sendtotwitter': boolean
    }

USER_T = 'user', {
    'id': string,
    'firstname': string,
    'lastname': string,
    'city': CITY_T,
    'photo': string,
    'gender': string,
    'phone': string,
    'email': string,
    'twitter': string,
    'facebook': string,
    'friendstatus': string,
    'checkin': CHECKIN_T,
    'badges': BADGES_T,
    'settings': SETTINGS_T
    }

CHECKINS_T = 'checkins', {
    'checkin': CHECKIN_T,
    }
    

LIMIT_PARAMETERS = ['l']


FOURSQUARE_METHODS = {
    # OAuth methods
    'access_token': {
        'server'      : OAUTH_SERVER,
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : [],
        'required'    : ['token'],
        'returns'     : 'oauth_token',
        'url_template': OAUTH_URL_TEMPLATE,
    },
    'authorize': {
        'server'      : OAUTH_SERVER,
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : [],
        'required'    : ['token'],
        'returns'     : 'request_url',
        'url_template': OAUTH_URL_TEMPLATE,
    },
    'request_token': {
        'server'      : OAUTH_SERVER,
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : [],
        'required'    : [],
        'returns'     : 'oauth_token',
        'url_template': OAUTH_URL_TEMPLATE,
    },
    # Foursquare methods
    'user':  {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : ['uid', 'badges', 'mayor'],
        'required'    : [],
        'returns'     : USER_T,
        'url_template': API_URL_TEMPLATE,
    },
    'history': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : LIMIT_PARAMETERS,
        'required'    : [],
        'returns'     : CHECKINS_T,
        'url_template': API_URL_TEMPLATE,
    },
    'checkins': {
        'http_headers': None,
        'http_method' : 'GET',
        'optional'    : ['cityid'],
        'required'    : [],
        'returns'     : CHECKINS_T,
        'url_template': API_URL_TEMPLATE,
    },
}


class FoursquareException(Exception):
    pass

# Used as a proxy for methods of the Foursquare class; when methods
# are called, __call__ in FoursquareAccumulator is called, ultimately
# calling the foursquare_obj's callMethod()
class FoursquareAccumulator:
    def __init__(self, foursquare_obj, name):
        self.foursquare_obj = foursquare_obj
        self.name = name
    
    def __repr__(self):
        return self.name
    
    def __call__(self, *args, **kw):
        return self.foursquare_obj.call_method(self.name, *args, **kw)
    

class Foursquare:
    def __init__(self, consumer_key, consumer_secret):
        # Prepare object lifetime variables
        self.consumer_key = consumer_key
        self.consumer_secret  = consumer_secret
        self.oauth_consumer   = oauth.OAuthConsumer(
            self.consumer_key, 
            self.consumer_secret
        )
        self.signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()

        # Prepare the accumulators for each method
        for method, _ in FOURSQUARE_METHODS.items():
            if not hasattr( self, method ):
                setattr( self, method, FoursquareAccumulator( self, method ))

    def get_http_connection(self, server):
        return httplib.HTTPConnection(server)
        
    
    def fetch_response( self, server, http_method, url, \
            body = None, headers = None ):
        """Pass a request to the server and return the response as a string"""
        
        http_connection = self.get_http_connection(server)

        # Prepare the request
        if ( body is not None ) or ( headers is not None ):
            http_connection.request( http_method, url, body, headers )
        else:
            http_connection.request( http_method, url )
        
        # Get the response
        response      = http_connection.getresponse()
        response_body = response.read()

        # If we've been informed of an error, raise it
        if ( 200 != response.status ):
            # Try to get the error message
            try:
                error_dom       = minidom.parseString( response_body )
                response_errors = error_dom.getElementsByTagName( 'err' )
            except: # TODO: Naked except: make this explicit!
                response_errors = None
            
            # If we can't get the error message, just raise a generic one
            if response_errors:
                msg = SPECIFIED_ERROR_EXCEPTION.substitute( \
                    message = response_errors[0].getAttribute( 'msg' ),
                    code    = response_errors[0].getAttribute( 'code' )
                )
            else:
                msg = UNSPECIFIED_ERROR_EXCEPTION.substitute( \
                    status = response.status )
            
            raise FoursquareException, msg
        
        # Return the body of the response
        return response_body
    
    def build_return( self, dom_element, target_element_name, conversions):
        results = []
        for node in dom_element.getElementsByTagName( target_element_name ):
            data = {}
            
            for key, conversion in conversions.items():
                node_key      = key.replace( '_', '-' )
                key           = key.replace( ':', '_' )
                data_elements = node.getElementsByTagName( node_key )
                
                # If conversion is a tuple, call build_return again
                if isinstance( conversion, tuple ):
                    child_element, child_conversions = conversion
                    data[key] = self.build_return( \
                        node, child_element, child_conversions \
                    )
                else:
                    # If we've got multiple elements, build a 
                    # list of conversions
                    if data_elements and ( len( data_elements ) > 1 ):
                        data_item = []
                        for data_element in data_elements:
                            data_item.append( conversion(
                                data_element.firstChild.data
                            ) )
                    # If we only have one element, assume text node
                    elif data_elements:
                        data_item = conversion( \
                            data_elements[0].firstChild.data
                        )
                    # If no elements are matched, convert the attribute
                    else:
                        data_item = conversion( \
                            node.getAttribute( node_key ) \
                        )
                    if data_item is not None:
                        data[key] = data_item
                    
            results.append( data )
        return results
    
    def call_method( self, method, *args, **kw ):
        logging.info('Calling %s' % (method,))
        
        # Theoretically, we might want to do 'does this method exits?' checks
        # here, but as all the aggregators are being built in __init__(),
        # we actually don't need to: Python handles it for us.
        meta = FOURSQUARE_METHODS[method]
        
        if args:
            # Positional arguments are mapped to meta['required'] 
            # and meta['optional'] in order of specification of those
            # (with required first, obviously)
            names = meta['required'] + meta['optional']
            for i in range( len( args ) ):
                kw[names[i]] = args[i]
        
        # Check we have all required arguments
        if len( set( meta['required'] ) - set( kw.keys() ) ) > 0:
            raise FireEagleException, \
                NULL_ARGUMENT_EXCEPTION.substitute( \
                    method = method, \
                    args   = ', '.join( meta['required'] )
                )
        
        # Token shouldn't be handled as a normal arg, so strip it out
        # (but make sure we have it, even if it's None)
        if 'token' in kw:
            token = kw['token']
            del kw['token']
        else:
            token = None
        
        # Build and sign the oauth_request
        # NOTE: If ( token == None ), it's handled it silently
        #       when building/signing
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(
            self.oauth_consumer,
            token       = token,
            http_method = meta['http_method'],
            http_url    = meta['url_template'].substitute( method=method ),
            parameters  = kw
        )
        oauth_request.sign_request(
            self.signature_method,
            self.oauth_consumer,
            token
        )
        
        # If the return type is the request_url, simply build the URL and 
        # return it witout executing anything    
        if 'request_url' == meta['returns']:
            # HACK: Don't actually want to point users to yahooapis.com, so 
            #       point them to fireeagle.com
            return oauth_request.to_url()
        #.replace( \
        #        API_PROTOCOL + '://' + API_SERVER, \
        #        FE_PROTOCOL  + '://' + FE_SERVER )
        
        print oauth_request.to_url()
        
        server = API_SERVER
        if 'server' in meta:
            server = meta['server']
            
        if 'POST' == meta['http_method']:
            response = self.fetch_response(server, oauth_request.http_method, \
                oauth_request.to_url(), oauth_request.to_postdata(), \
                meta['http_headers'] )
        else:
            response = self.fetch_response(server, oauth_request.http_method, \
                oauth_request.to_url() )
        
        # Method returns nothing, but finished fine
        if not meta['returns']:
            return True
        # Return the oauth token
        elif 'oauth_token' == meta['returns']:
            return oauth.OAuthToken.from_string( response )
        
        element, conversions = meta['returns']
        response_dom         = minidom.parseString( response )
        
        results              = self.build_return( \
            response_dom, element, conversions )
        
        return results
    

# TODO: Cached version
