# -*- coding: utf-8 -*-

"""Provides authentication and authorisation views."""

import logging
logger = logging.getLogger(__name__)

from pyramid.httpexceptions import HTTPForbidden, HTTPFound, HTTPUnauthorized
from pyramid.security import unauthenticated_userid
from pyramid.security import forget, remember
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC
from pyramid.view import view_config

from pyramid_simpleform import Form
from pyramid_simpleform.renderers import FormRenderer

from pyramid_simpleauth import model, schema, tree

@view_config(context=HTTPForbidden, permission=PUBLIC)
def forbidden_view(request):
    """Called when a user has been denied access to a resource or view.  
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_simpleauth import view
          >>> _unauthenticated_userid = view.unauthenticated_userid
          >>> view.unauthenticated_userid = Mock()
          >>> mock_request = Mock()
          >>> mock_request.path = '/forbidden/page'
          >>> mock_request.route_url.return_value = 'http://foo.com/login'
      
      If the user is already logged in, it means they don't have the requisit
      permission, so we raise a 403 Forbidden error::
      
          >>> view.unauthenticated_userid.return_value = 1234
          >>> response = forbidden_view(mock_request)
          >>> response.status
          '403 Forbidden'
      
      Otherwise we redirect to the login page::
      
          >>> view.unauthenticated_userid.return_value = None
          >>> response = forbidden_view(mock_request)
          >>> kwargs = {'_query': (('next', '/forbidden/page'),)}
          >>> mock_request.route_url.assert_called_with('login', **kwargs)
          >>> response.location
          'http://foo.com/login'
          >>> response.status
          '302 Found'
      
      Teardown::
      
          >>> view.unauthenticated_userid = _unauthenticated_userid
      
    """
    
    if unauthenticated_userid(request):
        return HTTPForbidden()
    url = request.route_url('login', _query=(('next', request.path),))
    return HTTPFound(location=url)


@view_config(context=HTTPUnauthorized, permission=PUBLIC)
def unauthorised_view(request):
    """Called when the request included authorization credentials but the user
      has been refused access.
      
          >>> response = unauthorised_view(None)
          >>> response.status
          '403 Forbidden'
      
    """
    
    return HTTPForbidden()


@view_config(context=tree.AuthRoot, name='signup', renderer='signup.mako',
        permission=PUBLIC)
def signup_view(request):
    """Render and handle signup form."""
    
    raise NotImplementedError('Rejig to use distinct user and email classes.')
    
    form = Form(request, schema=schema.Signup, defaults={'failed': False})
    if request.method == 'POST':
        if form.validate():
            # Get the form data
            d = form.data
            args = (d['username'], d['email'], d['password'])
            # Determine whether to skip confirmation.
            s = request.config.settings
            skip_confirmation = s.get('auth.skip_confirmation', False)
            # Create the user and save to the db.
            user = model.create_user(*args, is_confirmed=skip_confirmation)
            model.save(user)
            # Redirect to the index or the confirm page.
            route_name = 'index' if skip_confirmation else 'confirm'
            return HTTPFound(location=request.route_url(route_name))
        form.data['failed'] = True
    return {'renderer': FormRenderer(form)}


@view_config(context=tree.AuthRoot, name='login', request_method='POST',
        xhr=True, renderer='json', permission=PUBLIC)
def authenticate_view(request):
    """If posted a ``username`` and ``password``, attempt to authenticate the
      user using the credentials provided.  If authentication if successful, 
      return the JSON representation of the authenticated user.
    """
    
    form = Form(request, schema=schema.Authenticate)
    if form.validate():
        d = form.data
        user = model.authenticate(d['username'], d['password'])
        if user:
            remember(request, user.canonical_id)
            return user.__json__()
    return {}


@view_config(context=tree.AuthRoot, name='login', xhr=False, 
        renderer='login.mako', permission=PUBLIC)
def login_view(request):
    """Render login form.  If posted a ``username`` and ``password``, attempt to
      authenticate the user using the credentials provided.  If authentication
      if successful, redirect the user whence they came.
    """
    
    raise NotImplementedError(
        """XXX Need to use the settings to potentially provide Twitter auth
          option.  Presumably either both, one or neither.  If both, then
          do we render a link to Twitter on the form and reconcile users?
          Also what about providing easy Twitter connect account?
        """
    )
    
    next = request.params.get('next') or request.route_path('index')
    defaults = {
        'failed': False, 
        'next': next
    }
    form = Form(request, schema=schema.Login, defaults=defaults)
    if request.method == 'POST':
        if form.validate():
            d = form.data
            user = model.authenticate(d['username'], d['password'])
            if user:
                headers = remember(request, user.canonical_id)
                return HTTPFound(location=next, headers=headers)
        logger.debug(form.data)
        logger.debug(form.errors)
        form.data['failed'] = True
    return {'renderer': FormRenderer(form)}


@view_config(context=tree.AuthRoot, name='logout', permission='logout')
def logout_view(request):
    headers = forget(request)
    url = request.route_url('index')
    return HTTPFound(location=url, headers=headers)

