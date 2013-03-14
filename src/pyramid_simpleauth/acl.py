# -*- coding: utf-8 -*-

"""Provides a set of simple convenience mixin classes, designed primarily
  for use with SQLAlchemy model classes, that provide an ``__acl__``
  property (used by the Pyramid security machinery to grant permissions).
"""

__all__ = [
    'PublicMixin',
    'PrivateMixin',
    'PersonalMixin',
    'PublicOwnedMixin',
    'PrivateOwnedMixin'
]

import logging
logger = logging.getLogger(__name__)

from pyramid.security import ALL_PERMISSIONS
from pyramid.security import Allow, Deny
from pyramid.security import Authenticated, Everyone

class PublicMixin(object):
    """Anyone can view."""
    
    __acl__ = [
        (Allow, 'r:admin', ALL_PERMISSIONS),
        (Allow, Everyone, 'view'),
        (Deny, Everyone, ALL_PERMISSIONS)
    ]

class PrivateMixin(object):
    """Authenticated users can view."""
    
    __acl__ = [
        (Allow, 'r:admin', ALL_PERMISSIONS),
        (Allow, Authenticated, 'view'),
        (Deny, Everyone, ALL_PERMISSIONS),
    ]

class PersonalMixin(object):
    """Only ``self.user`` and admins can access."""
    
    @property
    def __acl__(self):
        """Grants ``view``, ``edit`` and ``delete`` to ``self.user``."""
        
        return [
            (Allow, 'r:admin', ALL_PERMISSIONS),
            (Allow, self.user.canonical_id, 'view'),
            (Allow, self.user.canonical_id, 'edit'),
            (Allow, self.user.canonical_id, 'delete'),
            (Deny, Everyone, ALL_PERMISSIONS)
        ]
    

class PublicOwnedMixin(object):
    """Anyone can view. ``self.user`` can edit, etc."""
    
    @property
    def __acl__(self):
        """Grants ``view``, ``edit`` and ``delete`` to admins and ``self.user``
          and ``view`` to ``Everybody``.
        """
        
        return [
            (Allow, 'r:admin', ALL_PERMISSIONS),
            (Allow, self.user.canonical_id, 'view'),
            (Allow, self.user.canonical_id, 'edit'),
            (Allow, self.user.canonical_id, 'delete'),
            (Allow, Everyone, 'view'),
            (Deny, Everyone, ALL_PERMISSIONS)
        ]
    

class PrivateOwnedMixin(object):
    """Authenticated users can view. ``self.user`` can edit, etc."""
    
    @property
    def __acl__(self):
        """Grants ``view``, ``edit`` and ``delete`` to admins and ``self.user``
          and ``view`` to ``Authenticated``.
        """
        
        return [
            (Allow, 'r:admin', ALL_PERMISSIONS),
            (Allow, self.user.canonical_id, 'view'),
            (Allow, self.user.canonical_id, 'edit'),
            (Allow, self.user.canonical_id, 'delete'),
            (Allow, Authenticated, 'view'),
            (Deny, Everyone, ALL_PERMISSIONS)
        ]
    

