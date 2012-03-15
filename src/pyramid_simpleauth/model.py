# -*- coding: utf-8 -*-

"""Provides SQLAlchemy based model classes."""

__all__ = [
    'Role',
    'User',
    'Email',
    'TwitterAccount'
]

import logging
logger = logging.getLogger(__name__)

import os
from binascii import hexlify
from datetime import datetime

from passlib.apps import custom_app_context as pwd_context

from sqlalchemy import desc
from sqlalchemy import Column, ForeignKey, Table, MetaData
from sqlalchemy import Boolean, DateTime, Integer, Unicode, UnicodeText
from sqlalchemy.ext.declarative import declared_attr, declarative_base
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
from zope.sqlalchemy import ZopeTransactionExtension

Session = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()

def save(instance_or_instances, session=Session):
    """Save model instance(s) to the db.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_session = Mock()
      
      A single instance is added to the session::
      
          >>> save('a', session=mock_session)
          >>> mock_session.add.assert_called_with('a')
      
      Multiple instances are all added at the same time::
      
          >>> save(['a', 'b'], session=mock_session)
          >>> mock_session.add_all.assert_called_with(['a', 'b'])
      
    """
    
    v = instance_or_instances
    if isinstance(v, list) or isinstance(v, tuple):
        session.add_all(v)
    else:
        session.add(v)

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

class BaseMixin(object):
    """Provides an int ``id`` as primary key, ``version``, ``created`` and
      ``modified`` columns and a scoped ``self.query`` property.
    """
    
    id =  Column(Integer, primary_key=True)
    
    version = Column('v', Integer, default=1)
    created = Column('c', DateTime, default=datetime.utcnow)
    modified = Column('m', DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    query = Session.query_property()

class Role(Base, BaseMixin):
    """Role a user may have (like admin or editor)."""
    
    __tablename__ = 'auth_roles'
    
    name = Column(Unicode(33), unique=True)
    description = Column(Unicode(256))

class User(Base, BaseMixin):
    """Model class encapsulating a user."""
    
    __tablename__ = 'auth_users'
    
    canonical_id = Column(Unicode(128), default=generate_canonical_id, unique=True)
    username = Column(Unicode(32), unique=True)
    password = Column(Unicode(120))
    
    roles = relationship("Role", secondary="auth_users_to_roles", lazy="joined")
    emails = relationship("Email", lazy="joined")
    twitter_accounts = relationship("TwitterAccount", lazy="joined")

class Email(Base, BaseMixin):
    """A user's email address with optional confirmation data."""
    
    __tablename__ = 'auth_emails'
    
    address = Column(Unicode(255), unique=True)
    
    confirmation_hash = Column(Unicode(28), default=generate_confirmation_hash)
    is_confirmed = Column(Boolean, default=False)
    
    user_id = Column(Integer, ForeignKey('auth_users.id'))

class TwitterAccount(Base, BaseMixin):
    """A user's twitter account with oauth token data."""
    
    __tablename__ = 'auth_twitter_accounts'
    
    twitter_id = Column(Integer, unique=True)
    screen_name = Column(Unicode(20))
    
    oauth_token = Column(Unicode(200))
    oauth_token_secret = Column(Unicode(200))
    
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
