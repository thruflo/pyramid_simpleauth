# -*- coding: utf-8 -*-

"""Provides functions that get the authenticated user from the ``request``."""

import logging
logger = logging.getLogger(__name__)

import json

from pyramid.security import unauthenticated_userid
from .model import get_existing_user

# Reified request properties.
def get_is_authenticated(request):
    """Has this ``request`` been made by an authenticated user?
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import hooks
          >>> _unauthenticated_userid = hooks.unauthenticated_userid
          >>> hooks.unauthenticated_userid = Mock()
          >>> mock_request = Mock()
      
      When the request is not authenticated, returns ``False``::
      
          >>> hooks.unauthenticated_userid.return_value = None
          >>> get_is_authenticated(mock_request)
          False
      
      When the request is authenticated, returns ``True``::
      
          >>> hooks.unauthenticated_userid.return_value = 1234
          >>> get_is_authenticated(mock_request)
          True
      
      Teardown::
      
          >>> hooks.unauthenticated_userid = _unauthenticated_userid
      
    """
    
    return bool(unauthenticated_userid(request))

def get_authenticated_user(request):
    """Get the authenticated user for this ``request``, if it has one.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import hooks
          >>> _unauthenticated_userid = hooks.unauthenticated_userid
          >>> _get_existing_user = hooks.get_existing_user
          >>> hooks.unauthenticated_userid = Mock()
          >>> hooks.get_existing_user = Mock()
          >>> mock_request = Mock()
      
      When the request is authenticated and the user exists, returns the user::
      
          >>> hooks.unauthenticated_userid.return_value = 1234
          >>> hooks.get_existing_user.return_value = 'user'
          >>> get_authenticated_user(mock_request)
          'user'
      
      When the request is authenticated but the user doesn't exists, returns 
      ``None``::
      
          >>> hooks.get_existing_user.return_value = None
          >>> get_authenticated_user(mock_request)
      
      When the request is not authenticated, doesn't try to find the user::
      
          >>> hooks.get_existing_user = Mock()
          >>> hooks.unauthenticated_userid.return_value = None
          >>> get_authenticated_user(mock_request)
          >>> hooks.get_existing_user.called
          False
      
      Teardown::
      
          >>> hooks.unauthenticated_userid = _unauthenticated_userid
          >>> hooks.get_existing_user = _get_existing_user
      
    """
    
    canonical_id = unauthenticated_userid(request)
    if canonical_id:
        return get_existing_user(canonical_id=canonical_id)

def get_user_json(request):
    """Return a JSON string representation of ``request.user``.
      
          >>> from mock import MagicMock as Mock
          >>> mock_request = Mock()
      
      If there's no authenticated user, returns ``json.dumps({})``::
      
          >>> mock_request.user = None
          >>> get_user_json(mock_request)
          '{}'
      
      Otherwise ``json.dumps(user.__json__())``:
      
          >>> mock_request.user = Mock()
          >>> mock_request.user.__json__ = Mock()
          >>> mock_request.user.__json__.return_value = {'username': 'thruflo'}
          >>> get_user_json(mock_request)
          '{"username": "thruflo"}'
      
    """
    
    user = request.user
    data = user.__json__() if user else {}
    return json.dumps(data)


# Authorization group finder.
def get_roles(canonical_id, request):
    """Get the roles the authenticated user has.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_user = Mock()
          >>> mock_role = Mock()
          >>> mock_role.name = u'editor'
          >>> mock_user.roles = [mock_role]
          >>> mock_request.user = mock_user
      
      Test::
      
          >>> get_roles(None, mock_request)
          [u'r:editor']
       
    """
    
    user = request.user
    if user:
        return [u'r:{0}'.format(role.name) for role in user.roles]


# Session process flags.
def get_is_post_login(request):
    """If the session contains a true value for ``is_post_login``, then wipe
      it and return ``True``.  Otherwise, return ``False``.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
      
      If the session contains a true value for ``is_post_login``, then wipe
      it and return ``True``::
      
          >>> mock_request.session = {'is_post_login': True}
          >>> get_is_post_login(mock_request)
          True
          >>> mock_request.session
          {}
      
      Otherwise, return ``False``::
      
          >>> get_is_post_login(mock_request)
          False
      
    """
    
    is_post_login = request.session.get('is_post_login', False)
    if is_post_login:
        del request.session['is_post_login']
        return True
    return False

def get_is_post_signup(request):
    """If the session contains a true value for ``is_post_signup``, then wipe
      it and return ``True``.  Otherwise, return ``False``.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
      
      If the session contains a true value for ``is_post_signup``, then wipe
      it and return ``True``::
      
          >>> mock_request.session = {'is_post_signup': True}
          >>> get_is_post_signup(mock_request)
          True
          >>> mock_request.session
          {}
      
      Otherwise, return ``False``::
      
          >>> get_is_post_signup(mock_request)
          False
      
    """
    
    is_post_signup = request.session.get('is_post_signup', False)
    if is_post_signup:
        del request.session['is_post_signup']
        return True
    return False
