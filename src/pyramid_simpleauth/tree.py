# -*- coding: utf-8 -*-

"""Provides ``Root`` traversal root factory."""

from pyramid.security import Allow, Authenticated, Everyone

from .model import get_existing_user
from .schema import Username, Invalid

class Root(object):
    """Root object of the simpleauth resource tree.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import tree
          >>> _get_existing_user = tree.get_existing_user
          >>> tree.get_existing_user = Mock()
      
      Tries to get username by key::
      
          >>> tree.get_existing_user.return_value = '<user>'
          >>> root = Root(None)
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
      
      Teardown::
      
          >>> tree.get_existing_user = _get_existing_user
      
    """
    
    __name__ = None
    
    __acl__ = [
        (Allow, Everyone, 'logout')
    ]
    
    def __init__(self, request):
        self.request = request
    
    def __getitem__(self, key):
        try:
            username = Username.to_python(key)
        except Invalid:
            pass
        else:
            existing = get_existing_user(username=key)
            if existing:
                return existing
        raise KeyError
    

