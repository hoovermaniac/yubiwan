# -*- coding: utf-8 -*-
# YUBIWAN
# Yubikey OTP Validation Module for Google App Engine
# Version 1.0
# Copyright (c) 2013 David Hall

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.



# IMPORTANT NOTE:
# This module uses PyCrypto, so need to specify PyCrypto library in app.yaml


# Imports ----------------------------------------------------------------

import urllib2
import hmac
import hashlib
import base64
from Crypto.Random import random
from google.appengine.api import urlfetch


# Module Variables -------------------------------------------------------

# Set client_id and client_key to values provided by Yubico. If you do not
# wish to sign requests, leave client_key equal to None. In this case the
# validation request will default to HTTPS. If you want to use both signiture
# checking and HTTPS, change the base_url value to the same as base_url_secure.

client_id = '00000'
client_key = None


base_url_secure = 'https://api.yubico.com/wsapi/2.0/verify'
base_url = 'http://api.yubico.com/wsapi/2.0/verify'


# Module functions -------------------------------------------------------

def extract_keyID(otp):
    """Extracts and returns the Yubikey ID string from the key's otp"""
    if type(otp) is unicode:
        return unicode.lower(otp[:-32])
    else:
        return str.lower(otp[:-32])

def nonce():
    """Returns a random nonce (40 character string)"""
    return hashlib.sha1(random.Random.new().read(32)).hexdigest()

def sign(message):
    """Takes a message string and returns its hmac-sha1 signiture"""
    if client_key:
    	decoded_key = base64.b64decode(client_key)
    	return base64.b64encode(hmac.new(decoded_key, message, hashlib.sha1).digest())
    else:
    	return None

def get_url(otp):
    """Returns the full validation url for a given OTP"""
    s = 'id=%s&nonce=%s&otp=%s' %(client_id, nonce(), otp)
    h = sign(s)
    if h:
    	return '%s?%s&h=%s' %(base_url, s, urllib2.quote(h))
    else:
    	return '%s?%s' %(base_url_secure, s)

def get_content_items(content):
    """Takes the content string from the validation server's response and outputs
    a dictionary of the response items"""
    content_dict = dict()
    content_list = content.split()
    for item in content_list:
    	kv_pair = item.split('=',1)
        content_dict[kv_pair[0]] = kv_pair[1]
    return content_dict

def check_signiture(content_dict):
    """Takes a content dictionary and checks the response signiture. Returns True
    if signiture ok (or no client key specified), otherwise returns False"""
    if not client_key:
    	return True
    else:
    	message = ''
    	key_list = sorted(content_dict.keys())
        key_list.remove('h')
    	for key in key_list:
    		message = message + key + '=' + content_dict[key] + '&'
    	message = message[:-1] #remove the terminal ampersand
    	if content_dict['h'] == sign(message):
    		return True
    	else:
    		return False


# The main OTP validation function ------------------------------------------------------


def validate_otp(otp, yubikey = None):
    """Validates an OTP with the Yubico server and returns a dictionary of values 
    including the server response items (if any) and a boolean under the key 'valid' 
    which indicates if the otp is valid (i.e. has passed all tests in this function
    and has been validated by the Yubico server). If the value of 'valid' is False,
    there will also be a concise error message under the key 'error' which indicates
    the primary reason why validation failed.
    The dictionary will contain at minimum the keys 'error' and 'valid'. 
    Other keys, which may not be present, should be queried using the .get(key) method
    to avoid raising a KeyError"""

    reply = dict(valid=False, error=None)

    # check for correct key length
    if len(otp) < 32 or len(otp) > 48:
        reply['error'] = 'OTP length is invalid'
        return reply
    # check if OTP is from specified Yubikey
    elif yubikey and yubikey != extract_keyID(otp):
        reply['error'] = "That's not the Yubikey you're looking for"
        return reply
    # try to validate the OTP with Yubico validation server
    else:
        url = get_url(otp)
        try:
            response = urlfetch.fetch(url, deadline=10, validate_certificate=True)
            if response.status_code == 200:
                content_dict = get_content_items(response.content)
                # add the server responses dictionary to the reply dictionary
                reply.update(content_dict)
                reply_otp = reply.get('otp')
                if reply.get('status') != 'OK':
                    reply['error'] = 'OTP is not valid'
                    return reply
                elif reply_otp and otp != reply_otp:
                    reply['error'] = 'Request OTP does not match returned OTP'
                    return reply
                elif not check_signiture(content_dict):
                    reply['error'] = 'Bad response signiture'
                    return reply
                else:
                    reply['valid'] = True
                    return reply
            # there was an HTTP error
            else:
                reply['error'] = 'HTTP request not successful'
                reply['HTTP_Code'] = response.status_code
                return reply
        # an exception was raised by the urlfetch service
        except urlfetch.DownloadError:
            reply['error'] = 'Server did not respond'
            return reply
        except urlfetch.SSLCertificateError:
            reply['error'] = 'SSL certificate validation failed'
            return reply
        except urlfetch.InvalidURLError:
            reply['error'] = 'URL not valid'
            return reply




   

