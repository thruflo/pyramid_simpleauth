# -*- coding: utf-8 -*-

from .hooks import get_authenticated_user, get_is_authenticated, get_roles
from .tree import AuthRoot

def includeme(config):
    """Allow developers to use ``config.include('pyramid_simpleauth')``."""
    
    # Add ``is_authenticated`` and ``user`` properties to the request.
    settings = config.registry.settings
    config.set_request_property(get_is_authenticated, 'is_authenticated', reify=True)
    config.set_request_property(get_authenticated_user, 'user', reify=True)
    
    # Expose the authentication views.
    prefix = settings.get('simpleauth.url_prefix', '/auth')
    path = '{}/*traverse'.format(prefix)
    config.add_route('simpleauth', path, factory=AuthRoot)
    
    # Lock down everything by default.
    if not settings.get('simpleauth.set_default_permission') is False:
        permission = settings.get('simpleauth.default_permission', 'view')
        config.set_default_permission(permission)
    
    # Setup authentication and authorisation policies.
    if not settings.get('simpleauth.set_auth_policies') is False:
        authn_policy = SessionAuthenticationPolicy(callback=get_roles)
        authz_policy = ACLAuthorizationPolicy()
        config.set_authentication_policy(authn_policy)
        config.set_authorization_policy(authz_policy)

