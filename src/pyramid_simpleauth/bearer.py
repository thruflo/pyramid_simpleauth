# -*- coding: utf-8 -*-

"""Business logic utilities to work with bearer tokens."""

__all__ = [
    'CreateBearerToken',
    'GetBearerToken',
    'GetCanonicalIDFromBearerToken',
    'GetOrCreateBearerToken',
    'LookupUserByBearerToken',
]

import logging
logger = logging.getLogger(__name__)

import pyramid_basemodel as bm

from datetime import datetime

try:
    from redis import exceptions as redis_exc
except ImportError:
    pass

from . import model

TOKEN_NAMESPACE = u'simpleauth.bearer:canonical_id_4_token'

class LookupUserByBearerToken(object):
    """Lookup a user by bearer token."""

    def __init__(self, **kwargs):
        self.token_cls = kwargs.get('token_cls', model.BearerToken)
        self.user_cls = kwargs.get('user_cls', model.User)
        self.utcnow = kwargs.get('utcnow', datetime.utcnow)

    def __call__(self, access_token_value, query=None):
        """Build a query to lookup a user via ``bearer_tokens.user_id``."""

        # Unpack.
        token_cls = self.token_cls
        user_cls = self.user_cls
        utcnow = self.utcnow

        # Lookup the user who owns this bearer token.
        if query is None:
            query = user_cls.query
        query = query.join(token_cls, token_cls.user_id==user_cls.id)
        query = query.filter(token_cls.access_token==access_token_value)

        # Making sure that the token hasn't expired or been revoked.
        query = query.filter(token_cls.expires_at_dt>utcnow())
        query = query.filter(token_cls.has_been_revoked==False)

        # Sorting to return the most recently created.
        query = query.order_by(token_cls.created.desc())
        return query.first()

class GetCanonicalIDFromBearerToken(object):
    """As per LookupUserByBearerToken but just lookup the canonical id
      -- this minimises the impact of a potentially common query (every
      bearer token authenticated request).

      The request is passed to the class so that we can cache in
      redis for 5 minutes iff redis is available.
    """

    def __init__(self, request, should_cache=True, **kwargs):
        self.request = request
        self.should_cache = False
        if should_cache:
            redis_client = getattr(request, 'redis', None)
            can_cache = redis_client and hasattr(redis_client, 'setex')
            if can_cache:
                self.should_cache = True
        self.expires = kwargs.get('expires', 300) # 60 * 5
        self.lookup = kwargs.get('lookup', LookupUserByBearerToken())
        self.namespace = kwargs.get('namespace', TOKEN_NAMESPACE)
        self.session = kwargs.get('session', bm.Session)
        self.user_cls = kwargs.get('user_cls', model.User)

    def __call__(self, access_token_value):
        """Try the redis cache, fallback on db query."""

        # Unpack.
        request = self.request
        expires = self.expires
        lookup = self.lookup
        namespace = self.namespace
        session = self.session
        should_cache = self.should_cache
        user_cls = self.user_cls

        # Prepare.
        canonical_id = None

        # First try redis.
        if should_cache:
            key = u'{0}:{1}'.format(namespace, access_token_value)
            try:
                canonical_id = request.redis.get(key)
            except redis_exc.RedisError:
                pass

        # If we got a value, great, otherwise hit the db.
        if not canonical_id:
            query = session.query(user_cls.canonical_id)
            result = lookup(access_token_value, query=query)
            if result:
                canonical_id = result[0]
                if should_cache:
                    request.redis.setex(key, expires, canonical_id)

        return canonical_id

class GetBearerToken(object):
    """Get a user's bearer token."""

    def __init__(self, **kwargs):
        self.token_cls = kwargs.get('token_cls', model.BearerToken)
        self.utcnow = kwargs.get('utcnow', datetime.utcnow)

    def __call__(self, user, scopes_list=None):
        """Lookup a user's bearer token."""

        # Unpack.
        token_cls = self.token_cls
        utcnow = self.utcnow

        # Lookup a token, owned by this user.
        query = token_cls.query.filter_by(user_id=user.id)

        # Making sure that the token hasn't expired or been revoked.
        query = query.filter(token_cls.expires_at_dt>utcnow())
        query = query.filter(token_cls.has_been_revoked==False)

        # Sorting to return the most recently created.
        query = query.order_by(token_cls.created.desc())

        # That matches the scope.
        if not scopes_list:
            return query.first()
        for candidate in query:
            if candidate.validate_scopes(scopes_list):
                return candidate
        return None

class CreateBearerToken(object):
    """Create a user's bearer token."""

    def __init__(self, should_flush=True, **kwargs):
        self.should_flush = should_flush
        self.session = kwargs.get('session', bm.Session)
        self.token_cls = kwargs.get('token_cls', model.BearerToken)

    def __call__(self, user, scopes_list=None):
        """Create, save, flush and return a bearer token."""

        # Unpack.
        session = self.session
        should_flush = self.should_flush
        token_cls = self.token_cls

        # Prepare scope.
        kwargs = {}
        if scopes_list:
            kwargs['scope'] = u' '.join(scopes_list)

        # Create.
        token = token_cls(user=user, **kwargs)

        # Save, flush and return the token instance.
        session.add(token)
        if should_flush:
            session.flush()
        return token

class GetOrCreateBearerToken(object):
    """Get or create a user's bearer token."""

    def __init__(self, **kwargs):
        self.get_token = kwargs.get('get_token', GetBearerToken())
        self.create_token = kwargs.get('create_token', CreateBearerToken())

    def __call__(self, user, scopes_list=None):
        """Use the underlying utilities to get or create and return."""

        # Unpack.
        get_token = self.get_token
        create_token = self.create_token

        # If we already have a matching token, great.
        token = get_token(user, scopes_list=scopes_list)

        # Otherwise, create one.
        if not token:
            token = create_token(user, scopes_list=scopes_list)

        return token
