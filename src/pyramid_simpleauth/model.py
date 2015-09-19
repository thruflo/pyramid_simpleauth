# -*- coding: utf-8 -*-

"""Provides SQLAlchemy based model classes and utility functions."""

__all__ = [
    'ACCESS_TOKEN_LENGTH',
    'REFRESH_TOKEN_LENGTH',
    'EXPIRES_IN_SECS',
    'BearerToken',
    'Email',
    'Role',
    'User',
    'authenticate',
    'encrypt',
    'generate_random_digest',
    'generate_unique_digest',
    'get_confirmation_link',
    'get_existing_email',
]

import os
from binascii import hexlify
from base64 import urlsafe_b64encode

from datetime import datetime
from datetime import timedelta

from passlib.apps import custom_app_context as pwd_context

from sqlalchemy import event
from sqlalchemy import exc
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Table
from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import Unicode
from sqlalchemy.orm import backref
from sqlalchemy.orm import mapper
from sqlalchemy.orm import relationship
from sqlalchemy.schema import UniqueConstraint

from zope.interface import implements

from pyramid.security import ALL_PERMISSIONS
from pyramid.security import Allow, Deny
from pyramid.security import Authenticated, Everyone
from pyramid_basemodel import Base, BaseMixin, Session, save
from pyramid_basemodel import util

from .interfaces import IEmail, IRole, IUser

ACCESS_TOKEN_LENGTH = 60 # chars
REFRESH_TOKEN_LENGTH = 80 # chars
EXPIRES_IN_SECS = 31449600 # 60*60*24*7*52, i.e.: one year

# Many to many relation between users and roles.
users_to_roles = Table(
    'auth_users_to_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('auth_users.id')),
    Column('role_id', Integer, ForeignKey('auth_roles.id'))
)

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

      Using a stripped version of the raw password::

          >>> model.pwd_context.encrypt.call_args[0][0]
          'Foo'

      Teardown::

          >>> model.pwd_context = _pwd_context

    """

    v = raw_password.strip()
    s = pwd_context.encrypt(v, scheme="sha512_crypt", rounds=90000)
    return unicode(s)

def generate_canonical_id():
    return util.generate_random_digest(num_bytes=64)

def generate_confirmation_hash():
    return util.generate_random_digest(num_bytes=14)

def generate_random_digest(num_bytes=28):
    """Generates a random hash and returns the hex digest as a unicode string."""

    return util.generate_random_digest(num_bytes=num_bytes)

def generate_unique_digest(query, property, **kwargs):
    """Loop until unique, then return digest.

      Setup::

          >>> from mock import Mock
          >>> mock_query = Mock()
          >>> mock_gen_digest = Mock()
          >>> mock_gen_digest.return_value = 'd1gest'

      Generates a digest and then, if it's unique, returns it::

          >>> mock_query.filter.return_value.count.return_value = 0
          >>> generate_unique_digest(mock_query, 'p', gen_digest=mock_gen_digest)
          'd1gest'

      Otherwise, iterates until it throws an error::

          >>> mock_query.filter.return_value.count.return_value = 1
          >>> generate_unique_digest(mock_query, 'p', gen_digest=mock_gen_digest)
          Traceback (most recent call last):
          ...
          Exception: Can't generate a unique digest for p
    """

    # Compose.
    max_attempts = 10
    num_bytes = kwargs.get('num_bytes', ACCESS_TOKEN_LENGTH / 2)
    gen_digest = kwargs.get('gen_digest', util.generate_random_digest)

    # Generate.
    i = 0
    while True:
        candidate = gen_digest(num_bytes=num_bytes)
        try:
            num_existing = query.filter(property==candidate).count()
        except exc.UnboundExecutionError:
            num_existing = 0
        if not num_existing:
            break
        i += 1
        if i > max_attempts:
            msg = u'Can\'t generate a unique digest for {0}'.format(property)
            raise Exception(msg)
    return candidate

def get_confirmation_link(request, email):
    """Return a confirmation link for `email`."""
    base_url = request.route_url('simpleauth', traverse=('confirm',))
    return '/'.join([base_url, email.confirmation_token])

def get_existing_email(address, user_id=None, cls=None):
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
          >>> mock_cls.query.filter_by.assert_called_with(
          ...         address='foo@bar.com')

      Optionally filtering also by the user_id::

          >>> get_existing_email('foo@bar.com', user_id=1234, cls=mock_cls)
          'email1'
          >>> mock_cls.query.filter_by.assert_called_with(
          ...         address='foo@bar.com', user_id=1234)

    """

    if cls is None:
        cls = Email

    filter_kwargs = {'address': address}
    if user_id is not None:
        filter_kwargs['user_id'] = user_id
    query = cls.query.filter_by(**filter_kwargs)
    return query.first()

def get_existing_user(cls=None, **kwargs):
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

    if cls is None:
        cls = User

    query = cls.query.filter_by(**kwargs)
    return query.first()

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

    if 'canonical_id' not in kwargs:
        user.canonical_id = generate_canonical_id()

class Role(Base, BaseMixin):
    """Role a user may have (like admin or editor)."""

    implements(IRole)

    __tablename__ = 'auth_roles'

    name = Column(Unicode(33), unique=True)
    description = Column(Unicode(256))

class User(Base, BaseMixin):
    """Model class encapsulating a user."""

    implements(IUser)

    __tablename__ = 'auth_users'

    @property
    def __name__(self):
        return self.username


    @property
    def __acl__(self):
        """Grants all permissions to ``self.username``::

              >>> user = User()
              >>> user.canonical_id = 'user_id'
              >>> user.__acl__[1] == (Allow, 'user_id', ALL_PERMISSIONS)
              True
        """

        return [
            (Allow, 'r:admin', ALL_PERMISSIONS),
            (Allow, self.canonical_id, ALL_PERMISSIONS),
            (Allow, Authenticated, 'view'),
            (Deny, Everyone, ALL_PERMISSIONS)
        ]

    canonical_id = Column(Unicode(128), default=generate_canonical_id,
                          unique=True)
    username = Column(Unicode(32), unique=True)
    password = Column(Unicode(120))

    roles = relationship("Role", secondary="auth_users_to_roles",
                         lazy="joined")
    emails = relationship("Email", lazy="joined", backref="user",
            cascade="all, delete-orphan", single_parent=True)

    @property
    def is_admin(self):
        """Does the user have a role called 'admin'?

          If the user doesn't have any roles, it's ``False``::

              >>> u = User()
              >>> u.is_admin
              False

          If they have roles but none named ``admin`` then returns ``False``::

              >>> r = Role(name='foo')
              >>> u.roles.append(r)
              >>> u.is_admin
              False

          If they do have a role named ``admin``, then returns ``True``::

              >>> r = Role(name='admin')
              >>> u.roles.append(r)
              >>> u.is_admin
              True

        """

        for item in self.roles:
            if item.name == 'admin':
                return True
        return False

    def __json__(self):
        """Return a dictionary representation of the ``User`` instance.

              >>> user = User(username='thruflo')
              >>> user.__json__()
              {'username': 'thruflo'}

        """

        return {'username': self.username}

    @property
    def confirmed_emails(self, email_cls=None):
        """Return a list of confirmed emails."""

        # Test jig.
        if email_cls is None:
            email_cls = Email

        query = email_cls.query.filter_by(user=self, is_confirmed=True)
        return query.all()

    @property
    def has_confirmed_email(self):
        """Has the user got any confirmed emails?"""

        return bool(self.confirmed_emails)

    def get_preferred_email(self):
        return (Email.query.filter_by(user=self, is_preferred=True).first()
                or Email.query.filter_by(user=self).first())

    def set_preferred_email(self, email):
        for e in self.emails:
            if e is not email:
                e.is_preferred = False
        email.is_preferred = True
        if not email in self.emails:
            self.emails.append(email)

    preferred_email = property(get_preferred_email, set_preferred_email)

class Email(Base, BaseMixin):
    """A user's email address with optional confirmation data."""

    implements(IEmail)

    __tablename__ = 'auth_emails'
    __table_args__ = (
        UniqueConstraint('address', 'user_id', name='auth_user_email_address_uc'),
    )

    address = Column(Unicode(255))

    confirmation_hash = Column(Unicode(28), default=generate_confirmation_hash)
    is_confirmed = Column(Boolean, default=False)
    is_preferred = Column(Boolean, default=False)

    user_id = Column(Integer, ForeignKey('auth_users.id'))

    @property
    def confirmation_token(self):
        encoded_id = urlsafe_b64encode(str(self.id))
        return '%s/%s' % (encoded_id, self.confirmation_hash)

class BearerToken(Base, BaseMixin):
    """Model class encapsulating a bearer access token."""

    __tablename__ = 'bearer_tokens'

    # Can belong to a user.
    user_id = Column(Integer, ForeignKey('auth_users.id'))
    user = relationship(User, backref=backref('bearer_tokens',
            cascade='all, delete-orphan', single_parent=True))

    # The ``access_token`` and ``refresh_token`` values.
    access_token = Column(Unicode(ACCESS_TOKEN_LENGTH), unique=True, nullable=False)
    refresh_token = Column(Unicode(REFRESH_TOKEN_LENGTH), nullable=False)

    # How long does the token last for and when does it expire?
    expires_at_dt = Column(DateTime, nullable=False)
    expires_in_secs = Column(Integer, nullable=False)

    token_type = u'Bearer'

    @classmethod
    def update_expires_at(cls, inst, value, old_value, initiator):
        """Base ``self.expires_at_dt`` on ``self.created`` + ``expires_in_secs``."""

        # First make sure we have a created value.
        if inst.created is None:
            inst.created = datetime.utcnow()

        # Set when the token expires.
        inst.expires_at_dt = inst.created + timedelta(seconds=value)

    # Has the token expired?
    @property
    def has_expired(self):
        """Has this token expired?"""

        return self.expires_at_dt < datetime.utcnow()

    # Has the token been revoked?
    has_been_revoked = Column(Boolean, default=False, nullable=False)

    # Optional: space seperated list of acceptable scopes.
    scope = Column(Unicode(256))

    # List of scopes.
    @property
    def scopes_list(self):
        """Return ``self.scope`` as a list."""

        return [] if self.scope is None else self.scope.split()

    def validate_scopes(self, scopes):
        """Validates if the requested scopes are allowed by the access token."""

        scopes_list = self.scopes_list
        for item in scopes:
            if item not in scopes_list:
                return False
        return True

    def revoke(self, should_save=True, save=None):
        """Revoke this access token."""

        # Compose.
        if save is None:
            save = Session.add

        # Flag as revoked.
        self.has_been_revoked = True

        # Save to db.
        if should_save:
            save(self)

    def generate(self, **kwargs):
        """Generate digests and set as ``access_token`` and ``refresh_token``
          and set the expiry values.
        """

        # Compose.
        access_bytes = kwargs.get('access_bytes', ACCESS_TOKEN_LENGTH / 2)
        expires_in = kwargs.get('expires_in', EXPIRES_IN_SECS)
        gen_digest = kwargs.get('gen_digest', util.generate_random_digest)
        gen_unique = kwargs.get('gen_unique', generate_unique_digest)
        refresh_bytes = kwargs.get('refresh_bytes', REFRESH_TOKEN_LENGTH / 2)

        # Unpack.
        query = self.query
        property_ = self.__class__.access_token

        # Set values.
        self.access_token = gen_unique(query, property_, num_bytes=access_bytes)
        self.expires_in_secs = expires_in
        self.refresh_token = gen_digest(num_bytes=refresh_bytes)

    def __json__(self, request=None):
        """Return a JSON representation."""

        data = {
            'access_token': self.access_token,
            'expires_in': self.expires_in_secs,
            'refresh_token': self.refresh_token,
            'token_type': self.token_type,
        }
        if self.scope is not None:
            data['scope'] = self.scope
        return data

@event.listens_for(mapper, 'after_configured', once=True)
def bind_to_orm_events(*args, **kwargs):
    """Setup ORM events once the mapper is configured."""

    event.listen(User, 'init', set_canonical_id)
