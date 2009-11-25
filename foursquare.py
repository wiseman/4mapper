"""
Foursquare API Python module
by John Wiseman <jjwiseman@gmail.com>

Based on a Fire Eagle module by Steve Marshall <steve@nascentguruism.com>.

Example usage:

>>> from foursquare import Foursquare
>>> fs = Foursquare(YOUR_CONSUMER_KEY, YOUR_CONSUMER_SECRET)
>>> application_token = fs.request_token()
>>> auth_url = fs.authorize(application_token)
>>> print auth_url
>>> pause('Authorize the app at that URL.')
>>> user_token = fs.access_token(application_token)
>>> pprint fs.history()
"""

import datetime
import httplib
import re
import string
import time
import sys
import logging

import oauth

from django.utils import simplejson


# General API setup
API_PROTOCOL = 'http'
API_SERVER   = 'api.foursquare.com'
API_VERSION  = 'v1'

OAUTH_SERVER = 'foursquare.com'

# Calling templates
API_URL_TEMPLATE   = string.Template(
    API_PROTOCOL + '://' + API_SERVER + '/' + API_VERSION + '/${method}.json'
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


FOURSQUARE_METHODS = {}

def def_method(name, server=API_SERVER, http_headers=None,
               http_method="GET", optional=[], required=[],
               returns=None, url_template=API_URL_TEMPLATE):
    FOURSQUARE_METHODS[name] = {
        'server': server,
        'http_headers': http_headers,
        'http_method': http_method,
        'optional': optional,
        'required': required,
        'returns': returns,
        'url_template': url_template,
        }


def_method('access_token',
           server=OAUTH_SERVER,
           required=['token'],
           returns='oauth_token',
           url_template=OAUTH_URL_TEMPLATE)

def_method('authorize',
           server=OAUTH_SERVER,
           required=['token'],
           returns='request_url',
           url_template=OAUTH_URL_TEMPLATE)

def_method('request_token',
           server=OAUTH_SERVER,
           returns='oauth_token',
           url_template=OAUTH_URL_TEMPLATE)

def_method('user',
           required=['token'],
           optional=['uid', 'badges', 'mayor'])

def_method('history',
           required=['token'],
           optional=['l'])

def_method('checkins',
           optional=['cityid'])

def_method('cities')

def_method('checkcity',
           required=['geolat', 'geolong'])







class FoursquareException(Exception):
    pass

class FoursquareRemoteException(FoursquareException):
    def __init__(self, method, code, msg):
        self.code = code
        self.msg = msg

    def __str__(self):
        return 'Error signaled by remote method %s: %s (%s)' % (method, msg, code)


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
        if (response.status != 200):
            raise FoursquareRemoteException(response.status, response_body)
        
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
            raise FoursquareException, \
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
        if 'returns' in meta and meta['returns'] == 'request_url':
            return oauth_request.to_url()
        
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
        # Return the oauth token
        if 'returns' in meta and meta['returns'] == 'oauth_token':
            return oauth.OAuthToken.from_string( response )
        
        results = simplejson.loads(response)
        return results
    

# TODO: Cached version
