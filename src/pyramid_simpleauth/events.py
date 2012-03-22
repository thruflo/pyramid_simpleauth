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


@implementer(IUserSignedUp)
class UserSignedUp(object):
    """An instance of this class is emitted whenever a new user signs up."""
    
    def __init__(self, request, user):
        self.request = request
        self.user = user
    

@implementer(IUserLoggedIn)
class UserLoggedIn(object):
    """An instance of this class is emitted whenever a user logs in."""
    
    def __init__(self, request, user):
        self.request = request
        self.user = user

@implementer(IUserLoggedOut)
class UserLoggedOut(object):
    """An instance of this class is emitted whenever a user logs out."""
    
    def __init__(self, request, user):
        self.request = request
        self.user = user

