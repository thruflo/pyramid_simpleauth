# -*- coding: utf-8 -*-

"""Provides SQLAlchemy based model classes."""

__all__ = [
    'Role',
    'User',
    'Email'
]

import os
from binascii import hexlify
from datetime import datetime

from passlib.apps import custom_app_context as pwd_context

from sqlalchemy import desc, event
from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy import Boolean, DateTime, Integer, Unicode, UnicodeText
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship

from pyramid.security import ALL_PERMISSIONS
from pyramid.security import Allow, Deny
from pyramid.security import Authenticated, Everyone
from pyramid_basemodel import Base, BaseMixin, Session, save

def encrypt(raw_password):
    """Encrypt a raw password into a secure hash using passlib.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import model
          >>> _pwd_context = model.pwd_context
          >>> model.pwd_context = Mock()
          >>> model.pwd_context.encrypt.return_value = 'digest'
      
      Returns a unicode version of the encrypted password::
      
          >>> encrypt('Foo ')
          u'digest'
      
      Using a lower case, stripped version of the raw password::
      
          >>> model.pwd_context.encrypt.call_args[0][0]
          'foo'
      
      Teardown::
      
          >>> model.pwd_context = _pwd_context
      
    """
    
    v = raw_password.strip().lower()
    s = pwd_context.encrypt(v, scheme="sha512_crypt", rounds=90000)
    return unicode(s)

def generate_random_digest(num_bytes=28):
    """Generates a random hash and returns the hex digest as a unicode string.
      
      Defaults to sha224::
      
          >>> import hashlib
          >>> h = hashlib.sha224()
          >>> digest = generate_random_digest()
          >>> len(h.hexdigest()) == len(digest)
          True
      
      Pass in ``num_bytes`` to specify a different length hash::
      
          >>> h = hashlib.sha512()
          >>> digest = generate_random_digest(num_bytes=64)
          >>> len(h.hexdigest()) == len(digest)
          True
      
      Returns unicode::
      
          >>> type(digest) == type(u'')
          True
      
    """
    
    r = os.urandom(num_bytes)
    return unicode(hexlify(r))


generate_canonical_id = lambda: generate_random_digest(num_bytes=64)
generate_confirmation_hash = lambda: generate_random_digest(num_bytes=14)

class Role(Base, BaseMixin):
    """Role a user may have (like admin or editor)."""
    
    __tablename__ = 'auth_roles'
    
    name = Column(Unicode(33), unique=True)
    description = Column(Unicode(256))

class User(Base, BaseMixin):
    """Model class encapsulating a user."""
    
    __tablename__ = 'auth_users'
    
    @property
    def __acl__(self):
        """Grants all permissions to ``self.username``::
          
              >>> user = User()
              >>> user.username = 'foo'
              >>> user.__acl__[1] == (Allow, 'foo', ALL_PERMISSIONS)
              True
        """
        
        return [
            (Allow, 'r:admin', ALL_PERMISSIONS),
            (Allow, self.username, ALL_PERMISSIONS),
            (Allow, Authenticated, 'view'),
            (Deny, Everyone, ALL_PERMISSIONS)
        ]
    
    canonical_id = Column(Unicode(128), default=generate_canonical_id, unique=True)
    username = Column(Unicode(32), unique=True)
    password = Column(Unicode(120))
    
    roles = relationship("Role", secondary="auth_users_to_roles", lazy="joined")
    emails = relationship("Email", lazy="joined")
    
    def __json__(self):
        """Return a dictionary representation of the ``User`` instance.
          
              >>> user = User(username='thruflo')
              >>> user.__json__()
              {'username': 'thruflo'}
          
        """
        
        return {'username': self.username}
    

class Email(Base, BaseMixin):
    """A user's email address with optional confirmation data."""
    
    __tablename__ = 'auth_emails'
    
    address = Column(Unicode(255), unique=True)
    
    confirmation_hash = Column(Unicode(28), default=generate_confirmation_hash)
    is_confirmed = Column(Boolean, default=False)
    
    user_id = Column(Integer, ForeignKey('auth_users.id'))

def get_existing_user(cls=User, **kwargs):
    """Get an existing user from the filter ``kwargs`` provided.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_cls = Mock()
          >>> mock_filtered_query = Mock()
          >>> mock_filtered_query.first.return_value = 'user1'
          >>> mock_cls.query.filter_by.return_value = mock_filtered_query
      
      Queries using the ``kwargs`` and returns the first result::
      
          >>> get_existing_user(cls=mock_cls, foo='bar')
          'user1'
          >>> mock_cls.query.filter_by.assert_called_with(foo='bar')
      
    """
    
    query = cls.query.filter_by(**kwargs)
    return query.first()

def get_existing_email(address, cls=Email):
    """Get an existing email from the ``address`` provided.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_cls = Mock()
          >>> mock_filtered_query = Mock()
          >>> mock_filtered_query.first.return_value = 'email1'
          >>> mock_cls.query.filter_by.return_value = mock_filtered_query
      
      Queries using the ``address`` and returns the first result::
      
          >>> get_existing_email('foo@bar.com', cls=mock_cls)
          'email1'
          >>> mock_cls.query.filter_by.assert_called_with(address='foo@bar.com')
      
    """
    
    query = cls.query.filter_by(address=address)
    return query.first()

def authenticate(username, raw_password):
    """Get an authenticated user corresponding to the credentials provided.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import model
          >>> _get_existing_user = model.get_existing_user
          >>> _pwd_context = model.pwd_context
          >>> model.pwd_context = Mock()
          >>> model.get_existing_user = Mock()
          >>> mock_user = Mock()
      
      If the username doesn't match, returns ``None``::
      
          >>> model.get_existing_user.return_value = None
          >>> authenticate('username', 'password')
      
      If the username does match but the passwords don't, returns ``None``::
          
          >>> model.get_existing_user.return_value = mock_user
          >>> model.pwd_context.verify.return_value = False
          >>> authenticate('username', 'password')
      
      If the username and the password matches, returns the user::
      
          >>> model.pwd_context.verify.return_value = True
          >>> authenticate('username', 'password') == mock_user
          True
      
      Teardown::
      
          >>> model.pwd_context = _pwd_context
          >>> model.get_existing_user = _get_existing_user
      
    """
    
    candidate = get_existing_user(username=username)
    if candidate and pwd_context.verify(raw_password, candidate.password):
        return candidate
    return None


# Many to many relation between users and roles.
users_to_roles = Table(
    'auth_users_to_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('auth_users.id')),
    Column('role_id', Integer, ForeignKey('auth_roles.id'))
)

# Set canonical_id on a new user instance when created (not when loaded from
# the db).
def set_canonical_id(user, *args, **kwargs):
    """Set ``user.canonical_id`` if not provided in the ``kwargs``.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_user = Mock()
          >>> mock_user.canonical_id = None
      
      Test::
      
          >>> set_canonical_id(mock_user, canonical_id='a')
          >>> mock_user.canonical_id
          >>> set_canonical_id(mock_user)
          >>> len(mock_user.canonical_id)
          128
      
    """
    
    if not kwargs.has_key('canonical_id'):
        user.canonical_id = generate_canonical_id()

event.listen(User, 'init', set_canonical_id)
