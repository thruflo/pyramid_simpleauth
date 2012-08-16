# -*- coding: utf-8 -*-

from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy

from .hooks import get_authenticated_user, get_is_authenticated
from .hooks import get_roles, get_user_json
from .hooks import get_is_post_login, get_is_post_signup
from .tree import AuthRoot

def includeme(config):
    """Allow developers to use ``config.include('pyramid_simpleauth')``.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_config = Mock()
          >>> mock_config.registry.settings = {}
      
      Adds properties to the request::
      
          >>> includeme(mock_config)
          >>> args = (get_is_authenticated, 'is_authenticated')
          >>> mock_config.set_request_property.assert_any_call(*args, reify=True)
          >>> args = (get_authenticated_user, 'user')
          >>> mock_config.set_request_property.assert_any_call(*args, reify=True)
          >>> args = (get_user_json, 'user_json')
          >>> mock_config.set_request_property.assert_any_call(*args, reify=True)
          >>> args = (get_is_post_login, 'is_post_login')
          >>> mock_config.set_request_property.assert_any_call(*args, reify=True)
          >>> args = (get_is_post_signup, 'is_post_signup')
          >>> mock_config.set_request_property.assert_any_call(*args, reify=True)
      
      Exposes the authentication views::
      
          >>> args = ('simpleauth', 'auth/*traverse')
          >>> kwargs = {
          ...     'factory': AuthRoot,
          ...     'use_global_views': True
          ... }
          >>> mock_config.add_route.assert_called_with(*args, **kwargs)
      
      Locks down everything by default::
      
          >>> mock_config.set_default_permission.assert_called_with('view')
          >>> mock_config = Mock()
          >>> mock_config.registry.settings = {
          ...     'simpleauth.set_default_permission': False
          ... }
          >>> includeme(mock_config)
          >>> mock_config.set_default_permission.called
          False
      
      Sets up authentication and authorisation policies by default::
      
          >>> mock_config.set_authentication_policy.called
          True
          >>> mock_config.set_authorization_policy.called
          True
          >>> mock_config = Mock()
          >>> mock_config.registry.settings = {'simpleauth.set_auth_policies': False}
          >>> includeme(mock_config)
          >>> mock_config.set_authentication_policy.called
          False
          >>> mock_config.set_authorization_policy.called
          False
      
    """
    
    # Add ``is_authenticated`` and ``user`` properties to the request.
    settings = config.registry.settings
    config.set_request_property(get_is_authenticated, 'is_authenticated', reify=True)
    config.set_request_property(get_authenticated_user, 'user', reify=True)
    config.set_request_property(get_user_json, 'user_json', reify=True)
    
    # Add ``is_post_login`` and ``is_post_signup`` request properties.
    config.set_request_property(get_is_post_login, 'is_post_login', reify=True)
    config.set_request_property(get_is_post_signup, 'is_post_signup', reify=True)

    # Expose the authentication views.
    prefix = settings.get('simpleauth.url_prefix', 'auth')
    path = '{0}/*traverse'.format(prefix)
    config.add_route('simpleauth', path, factory=AuthRoot, use_global_views=True)
    
    # Lock down everything by default.
    if not settings.get('simpleauth.set_default_permission') is False:
        permission = settings.get('simpleauth.default_permission', 'view')
        config.set_default_permission(permission)
    
    # Setup authentication and authorisation policies.
    if not settings.get('simpleauth.set_auth_policies') is False:
        authn_policy = SessionAuthenticationPolicy(callback=get_roles)
        authz_policy = ACLAuthorizationPolicy()
        config.set_authorization_policy(authz_policy)
        config.set_authentication_policy(authn_policy)
    
    # Run a venusian scan to pick up the declarative configuration.
    config.scan('pyramid_simpleauth')

