# -*- coding: utf-8 -*-

"""Provides FormEncode based validators and schemas."""

import re
from urlparse import urlparse

from formencode import validators, Invalid, Schema

valid_username = re.compile(r'^[.\w-]{1,32}$', re.U)
valid_password = re.compile(r'^(.){7,200}$', re.U)
valid_digest = re.compile(r'^[a-f0-9]{28,56}$')

class Username(validators.UnicodeString):
    """Validates that the user input matches ``valid_username``, strips and
      coerces to lowercase.
      
      If it isn't valid, raises an exception::
      
          >>> Username.to_python('%^Inv@l|d')
          Traceback (most recent call last):
          ...
          Invalid: No spaces or funny characters.
      
      Otherwise strips, coerces to lowercase and returns as unicode::
      
          >>> Username.to_python('Foo ')
          u'foo'
      
    """
    
    messages = {'invalid': 'No spaces or funny characters.'}
    
    def _to_python(self, value, state):
        value = super(Username, self)._to_python(value, state)
        return value.strip().lower() if value else value
    
    def validate_python(self, value, state):
        super(Username, self).validate_python(value, state)
        if not valid_username.match(value):
            msg = self.message("invalid", state)
            raise validators.Invalid(msg, value, state)
    

class Password(validators.UnicodeString):
    """Strips and validates that the user input is a ``valid_password``.
      
      If it isn't valid, raises an exception::
      
          >>> Password.to_python('short')
          Traceback (most recent call last):
          ...
          Invalid: Must be at least 7 characters.
      
      Otherwise strips and returns as unicode::
      
          >>> Password.to_python(' Password ')
          u'Password'
      
    """
    
    messages = {'invalid': 'Must be at least 7 characters.'}
    
    def _to_python(self, value, state):
        value = super(Password, self)._to_python(value, state)
        return value.strip() if value else value
    
    def validate_python(self, value, state):
        super(Password, self).validate_python(value, state)
        if not valid_password.match(value):
            msg = self.message("invalid", state)
            raise validators.Invalid(msg, value, state)
    

class Email(validators.Email):
    """Patch ``validators.Email`` with ``validators.UnicodeString``s 
      ``_to_python`` method.
      
      If it isn't valid, raises an exception::
      
          >>> Email.to_python('foo')
          Traceback (most recent call last):
          ...
          Invalid: An email address must contain a single @
          >>> Email.to_python('foo@baz')
          Traceback (most recent call last):
          ...
          Invalid: The domain portion of the email address is invalid (the portion after the @: baz)
      
      Note that when used with ``resolve_domain=True`` it must be a real domain::
      
          >>> Email(resolve_domain=True).to_python('a@b.com')
          Traceback (most recent call last):
          ...
          Invalid: The domain of the email address does not exist (the portion after the @: b.com)
      
      Otherwise strips and returns as unicode::
      
          >>> Email.to_python(' a@b.com ')
          u'a@b.com'
      
    """
    
    def _to_python(self, value, state):
        value = validators.UnicodeString.to_python(value, state)
        return value.strip().lower() if value else value
    


class RequestPath(validators.UnicodeString):
    """Valid `/request/path`.
      
      If it isn't valid, raises an exception::
      
          >>> RequestPath.to_python('://blah')
          Traceback (most recent call last):
          ...
          Invalid: Invalid request path.
      
      Otherwise strips and returns as unicode::
      
          >>> RequestPath.to_python(None)
          u''
          >>> RequestPath.to_python('/Foo ')
          u'/Foo'
      
    """
    
    messages = {'invalid': 'Invalid request path.'}
    
    def _to_python(self, value, state):
        value = super(RequestPath, self)._to_python(value, state)
        return value.strip()
    
    def validate_python(self, value, state):
        super(RequestPath, self).validate_python(value, state)
        path = urlparse(value).path
        if path != value or not path.startswith('/'):
            msg = self.message("invalid", state)
            raise validators.Invalid(msg, value, state)
    

class Digest(validators.UnicodeString):
    """Must be a valid hex digest.
      
      If it isn't valid, raises an exception::
      
          >>> Digest.to_python('ab$$')
          Traceback (most recent call last):
          ...
          Invalid: Invalid token. Did your email mangle the link?
      
      Otherwise strips, lowercases and returns as unicode::
      
          >>> Digest.to_python(' Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3 ')
          u'ab3ab3ab3ab3ab3ab3ab3ab3ab3ab3ab3ab3ab3'
      
    """
    
    messages = {'invalid': 'Invalid token. Did your email mangle the link?'}
    
    def _to_python(self, value, state):
        value = super(Digest, self)._to_python(value, state)
        return value.strip().lower()
    
    def validate_python(self, value, state):
        super(Digest, self).validate_python(value, state)
        if not valid_digest.match(value):
            msg = self.message("invalid", state)
            raise validators.Invalid(msg, value, state)
    


class UniqueUsername(Username):
    """A ``Username`` that hasn't already been taken.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import model
          >>> _get_existing_user = model.get_existing_user
          >>> model.get_existing_user = Mock()
      
      If the username exists, raises an exception::
      
          >>> model.get_existing_user.return_value = None
          >>> UniqueUsername.to_python('username')
          u'username'
          >>> model.get_existing_user.return_value = '<user>'
          >>> UniqueUsername.to_python('username')
          Traceback (most recent call last):
          ...
          Invalid: That username has already been taken.
      
      Teardown::
      
          >>> model.get_existing_user = _get_existing_user
      
    """
    
    messages = {'taken': 'That username has already been taken.'}
    
    def validate_python(self, value, state):
        super(UniqueUsername, self).validate_python(value, state)
        from .model import get_existing_user
        if get_existing_user(username=value):
            msg = self.message("taken", state)
            raise validators.Invalid(msg, value, state)
    

class UniqueEmail(Email):
    """An ``Email`` that hasn't already been taken.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import model
          >>> _get_existing_email = model.get_existing_email
          >>> model.get_existing_email = Mock()
      
      If the email exists, raises an exception::
      
          >>> model.get_existing_email.return_value = None
          >>> UniqueEmail.to_python('thruflo@gmail.com')
          u'thruflo@gmail.com'
          >>> model.get_existing_email.return_value = '<email>'
          >>> UniqueEmail.to_python('thruflo@gmail.com')
          Traceback (most recent call last):
          ...
          Invalid: That email address has already been taken.
      
      Teardown::
      
          >>> model.get_existing_email = _get_existing_email
      
    """
    
    messages = {'taken': 'That email address has already been taken.'}
    
    def validate_python(self, value, state):
        super(UniqueEmail, self).validate_python(value, state)
        from .model import get_existing_email
        if get_existing_email(value):
            msg = self.message("taken", state)
            raise validators.Invalid(msg, value, state)
    


class FlexibleSchema(Schema):
    """``formencode.Schema`` that defaults to allow and filter extra fields."""
    
    filter_extra_fields = True
    allow_extra_fields = True

class Signup(FlexibleSchema):
    """Form fields to render and validate for signup."""
    
    username = UniqueUsername(not_empty=True)
    email = UniqueEmail(resolve_domain=True, not_empty=True)
    password = Password(not_empty=True)
    confirm = Password(not_empty=True)
    chained_validators = [
        validators.FieldsMatch(
            'password', 
            'confirm'
        )
    ]

class Authenticate(FlexibleSchema):
    """Form fields to validate when authenticating over XHR."""
    
    username = Username(not_empty=True)
    password = Password(not_empty=True)

class Login(FlexibleSchema):
    """Form fields to render and validate for login."""
    
    username = Username(not_empty=True)
    password = Password(not_empty=True)

