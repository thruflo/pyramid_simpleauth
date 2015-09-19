# -*- coding: utf-8 -*-

"""Provide authentication and authorization policy."""

__all__ = [
    'VALID_API_KEY',
    'VALID_PASS_KEY',
    'VALID_TOKEN',
    'APIKeyAuthenticationPolicy',
    'BearerAuthenticationPolicy',
    'GlobalKeyAuthorizationPolicy',
    'HybridAuthenticationPolicy',
    'PassKeyAuthenticationPolicy',
    'get_bearer_token',
]

import logging
logger = logging.getLogger(__name__)

import urlparse
import re

import zope.interface as zi

from paste import httpheaders

from pyramid import authentication
from pyramid import interfaces
from pyramid import security

from . import bearer
from . import model

TOKEN_PREFIX = u'simpleauth.policy.token:'
VALID_TOKEN = re.compile(r'^[a-z0-9]{' + str(model.ACCESS_TOKEN_LENGTH) + '}$')

VALID_API_KEY = re.compile(r'^\w{40}$')
VALID_PASS_KEY = re.compile(r'^\w{40}$')

def get_bearer_token(request):
    """Return a bearer token provided as an authentication header."""

    # Compose.
    http_auth = httpheaders.AUTHORIZATION
    prefix = TOKEN_PREFIX

    # Try and get the bearer token data from the auth header.
    token = None
    try:
        auth_method, data = http_auth(request.environ).split(' ', 1)
    except ValueError: # not enough values to unpack
        pass
    else:
        if auth_method.lower() == 'bearer':
            token = data.strip()
    return token

@zi.implementer(interfaces.IAuthenticationPolicy)
class BearerAuthenticationPolicy(authentication.CallbackAuthenticationPolicy):
    """Authenticate using a `bearer token`_.

      _`bearer token`: https://tools.ietf.org/html/rfc6750#section-2.1
    """

    def __init__(self, prefix='auth.', callback=None, debug=False, **kwargs):
        self.callback = callback
        self.prefix = prefix or ''
        self.userid_key = prefix + 'userid'
        self.debug = debug
        self.get_token = kwargs.get('get_token', get_bearer_token)
        self.get_canonical_id_cls = kwargs.get('get_canonical_id_cls',
                bearer.GetCanonicalIDFromBearerToken)

    def forget(self, request):
        """Noop."""

        return []

    def remember(self, request, principal, **kw):
        """Noop."""

        return []

    def unauthenticated_userid(self, request):
        """Try and get a canonical id by bearer token."""

        # Prepare the return value.
        canonical_id = None

        # If there's a bearer token in the request, use it to lookup the
        # corresponding canonical id.
        access_token = self.get_token(request)
        if access_token:
            lookup_utility = self.get_canonical_id_cls(request)
            canonical_id = lookup_utility(access_token)

        return canonical_id

@zi.implementer(interfaces.IAuthenticationPolicy)
class HybridAuthenticationPolicy(authentication.SessionAuthenticationPolicy):
    """First try `bearer token`_, then try `session`_.

      _`bearer token`: https://tools.ietf.org/html/rfc6750#section-2.1
      _`session`: http://pyramid.readthedocs.org/en/latest/narr/sessions.html
    """

    def __init__(self, prefix='auth.', callback=None, debug=False, **kwargs):
        self.callback = callback
        self.prefix = prefix or ''
        self.userid_key = prefix + 'userid'
        self.debug = debug
        self.get_token = kwargs.get('get_token', get_bearer_token)
        self.get_canonical_id_cls = kwargs.get('get_canonical_id_cls',
                bearer.GetCanonicalIDFromBearerToken)

    def unauthenticated_userid(self, request):
        """Try and get a bearer token, fallback on a canonical id in the session."""

        # Prepare the return value.
        canonical_id = None

        # If there's a bearer token in the request, use it to lookup the
        # corresponding canonical id.
        access_token = self.get_token(request)
        if access_token:
            lookup_utility = self.get_canonical_id_cls(request)
            canonical_id = lookup_utility(access_token)

        # Fallback on the session.
        if not canonical_id:
            canonical_id = request.session.get(self.userid_key)

        return canonical_id

@zi.implementer(interfaces.IAuthenticationPolicy)
class APIKeyAuthenticationPolicy(authentication.CallbackAuthenticationPolicy):
    """A Pyramid authentication policy which obtains credential data from the
      ``request.headers['api_key']``.
    """

    def __init__(self, header_key, **kwargs):
        self.header_key = header_key
        self.valid_key = kwargs.get('valid_key', VALID_API_KEY)

    def unauthenticated_userid(self, request):
        """The ``api_key`` value found within the ``request.headers``."""

        api_key = request.headers.get(self.header_key, None)
        if api_key and self.valid_key.match(api_key):
            return api_key.decode('utf8')

    def remember(self, request, principal, **kw):
        """A no-op. There's no way to remember the user.

              >>> policy = APIKeyAuthenticationPolicy(None)
              >>> policy.remember('req', 'ppl')
              []

        """

        return []

    def forget(self, request):
        """A no-op. There's no user to forget.

              >>> policy = APIKeyAuthenticationPolicy(None)
              >>> policy.forget('req')
              []

        """

        return []

@zi.implementer(interfaces.IAuthenticationPolicy)
class PassKeyAuthenticationPolicy(authentication.BasicAuthAuthenticationPolicy):
    """A Pyramid authentication policy which validates that the basic auth
      password is a valid pass key and then uses that pass key as user id.
    """

    def __init__(self, **kwargs):
        self.check = kwargs.get('check', lambda u, p, r: [p])
        self.realm = kwargs.get('realm', 'Realm')
        self.debug = kwargs.get('debug', False)

    def unauthenticated_userid(self, request):
        """Return the basic auth password if present and valid."""

        credentials = self._get_credentials(request)
        if credentials:
            pass_key = credentials[1]
            if pass_key and VALID_PASS_KEY.match(pass_key):
                return pass_key

@zi.implementer(interfaces.IAuthorizationPolicy)
class GlobalKeyAuthorizationPolicy(object):
    """Global authorization policy that ignores the context and just checks
      whether the target key is in the principals list.
    """

    def __init__(self, key):
        self.key = key

    def permits(self, context, principals, permission):
        return self.key in principals

    def principals_allowed_by_permission(self, context, permission):
        raise NotImplementedError
