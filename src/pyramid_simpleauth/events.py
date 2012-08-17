# -*- coding: utf-8 -*-

"""Provides events triggered when users signup, login and logout."""

from zope.interface import implementer, Attribute, Interface

class IUserSignedUp(Interface):
    """An event type that is emitted after a new user signs up."""

    request = Attribute('The request object.')
    user = Attribute('The user who signed up.')

class IUserLoggedIn(Interface):
    """An event type that is emitted after a user logs in."""

    request = Attribute('The request object.')
    user = Attribute('The user who logged in.')

class IUserLoggedOut(Interface):
    """An event type that is emitted after a user logs out."""

    request = Attribute('The request object')
    user = Attribute('The user who logged out.')

class IUserChangedPassword(Interface):
    """An event type that is emitted after a user changes its password."""

    request = Attribute('The request object')
    user = Attribute('The user who changes its password.')

class IUserChangedUsername(Interface):
    """An event type that is emitted after a user changes its username."""

    request = Attribute('The request object')
    user = Attribute('The user who changes its username.')

class IEmailAddressConfirmed(Interface):
    """An event type that is emitted whenever a user confirms an email
    address, typically by clicking on a link received by email."""

    request = Attribute('The request object')
    user = Attribute('The user who owns the email address.')


@implementer(IUserSignedUp)
class UserSignedUp(object):
    """An instance of this class is emitted whenever a new user signs up."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data


@implementer(IUserLoggedIn)
class UserLoggedIn(object):
    """An instance of this class is emitted whenever a user logs in."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data


@implementer(IUserLoggedOut)
class UserLoggedOut(object):
    """An instance of this class is emitted whenever a user logs out."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data


@implementer(IUserChangedPassword)
class UserChangedPassword(object):

    """An instance of this class is emitted whenever a user changes its password."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data


@implementer(IUserChangedUsername)
class UserChangedUsername(object):
    """An instance of this class is emitted whenever a user change its username."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data


@implementer(IEmailAddressConfirmed)
class EmailAddressConfirmed(object):
    """An instance of this class is emitted whenever a user confirms an email
    address, typically by clicking on a link received by email."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data


@implementer(IEmailAddressConfirmed)
class EmailPreferred(object):
    """An instance of this class is emitted whenever a user prefers an email
    address, typically by clicking on a button in an account management page."""

    def __init__(self, request, user, data=None):
        self.request = request
        self.user = user
        self.data = data

