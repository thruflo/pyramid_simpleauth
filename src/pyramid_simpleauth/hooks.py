# -*- coding: utf-8 -*-

"""Provides functions that get the authenticated user from the ``request``."""

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


# Authorization group finder.
def get_roles(canonical_id, request):
    """Get the roles the authenticated user has.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_user = Mock()
          >>> mock_role = Mock()
          >>> mock_role.name = 'editor'
          >>> mock_user.roles = [mock_role]
          >>> mock_request.user = mock_user
      
      Test::
      
          >>> get_roles(None, mock_request)
          ['editor']
       
    """
    
    user = request.user
    if user:
        return [role.name for role in user.roles]

