# -*- coding: utf-8 -*-

"""Provides ``Root`` traversal root factory."""

from pyramid.security import ALL_PERMISSIONS
from pyramid.security import Allow, Deny
from pyramid.security import Authenticated, Everyone

from .model import get_existing_user
from .schema import Username, Invalid

class AuthRoot(object):
    """Root object of the simpleauth route.
      
      Always raises a ``KeyError``:
      
          >>> root = AuthRoot(None)
          >>> root['foo']
          Traceback (most recent call last):
          ...
          KeyError
      
    """
    
    __name__ = None
    
    __acl__ = [
        (Allow, Everyone, 'logout')
    ]
    
    def __init__(self, request):
        self.request = request
    
    def __getitem__(self, key):
        raise KeyError
    

class UserRoot(object):
    """Root object that gets user's by username.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import tree
          >>> _get_existing_user = tree.get_existing_user
          >>> tree.get_existing_user = Mock()
          >>> mock_request = Mock()
      
      Tries to get username by key::
      
          >>> tree.get_existing_user.return_value = '<user>'
          >>> root = UserRoot(mock_request)
          >>> root['username']
          '<user>'
          >>> tree.get_existing_user.assert_called_with(username='username')
      
      Raises a KeyError if the username is invalid::
      
          >>> root['%$£']
          Traceback (most recent call last):
          ...
          KeyError
      
      Or if the user does't exist::
      
          >>> tree.get_existing_user.return_value = None
          >>> root['username']
          Traceback (most recent call last):
          ...
          KeyError
      
      n.b.: Optimises by not hitting the db if the username matches the current
      authenticated user::
      
          >>> tree.get_existing_user = Mock()
          >>> mock_request.user = Mock()
          >>> mock_request.user.username = 'username'
          >>> root = UserRoot(mock_request)
          >>> root['username'] == mock_request.user
          True
          >>> tree.get_existing_user.called
          False
      
      Teardown::
      
          >>> tree.get_existing_user = _get_existing_user
      
    """
    
    __name__ = None
    
    __acl__ = [
        (Deny, Everyone, ALL_PERMISSIONS)
    ]
    
    def __init__(self, request):
        self.request = request
    
    def __getitem__(self, key):
        try:
            username = Username.to_python(key)
        except Invalid:
            pass
        else:
            existing = None
            # Optimise for a common case: if the username matches the current
            # user, don't make an additional db query here.
            if self.request.user and username == self.request.user.username:
                existing = self.request.user
            else:
                existing = get_existing_user(username=key)
            if existing:
                return existing
        raise KeyError
    

