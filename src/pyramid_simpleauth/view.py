# -*- coding: utf-8 -*-

"""Provides authentication and authorisation views."""

from zope.interface.registry import ComponentLookupError

from pyramid.httpexceptions import HTTPForbidden, HTTPFound, HTTPUnauthorized
from pyramid.security import unauthenticated_userid
from pyramid.security import forget, remember
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC
from pyramid.view import view_config

from pyramid_simpleform import Form
from pyramid_simpleform.renderers import FormRenderer

from pyramid_simpleauth import events, model, schema, tree

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
          >>> kwargs = {
          ...     '_query': (('next', '/forbidden/page'),),
          ...     'traverse': ('login',)
          ... }
          >>> mock_request.route_url.assert_called_with('simpleauth', **kwargs)
          >>> response.location
          'http://foo.com/login'
          >>> response.status
          '302 Found'
      
      Teardown::
      
          >>> view.unauthenticated_userid = _unauthenticated_userid
      
    """
    
    if unauthenticated_userid(request):
        return HTTPForbidden()
    query = (('next', request.path),)
    url = request.route_url('simpleauth', traverse=('login',), _query=query)
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


@view_config(context=tree.AuthRoot, name='signup', permission=PUBLIC,
        renderer='pyramid_simpleauth:templates/signup.mako')
def signup_view(request):
    """Render and handle signup form.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid.testing import DummyRequest
          >>> from pyramid_simpleauth import model, view
          >>> _get_existing_email = model.get_existing_email
          >>> _get_existing_user = model.get_existing_user
          >>> _save = model.save
          >>> _remember = view.remember
          >>> view.remember = Mock()
          >>> model.save = Mock()
          >>> model.get_existing_user = Mock()
          >>> model.get_existing_user.return_value = None
          >>> model.get_existing_email = Mock()
          >>> model.get_existing_email.return_value = None
      
      If it's not a POST, renders the form::
      
          >>> dummy_request = DummyRequest()
          >>> return_value = signup_view(dummy_request)
          >>> return_value['renderer'].data
          {'failed': False}
      
      Otherwise it validates the request data against ``schema.Signup``::
      
          >>> dummy_request = DummyRequest(post={'foo': 'bar'})
          >>> return_value = signup_view(dummy_request)
          >>> return_value['renderer'].data
          {'failed': True, 'foo': 'bar'}
      
      If provided with valid data, it saves a ``User`` with related ``Email``,
      logs them in by calling ``remember`` and redirects to the user's profile::
      
          >>> valid_post = {
          ...     'username': 'thruflo',
          ...     'email': 'thruflo@gmail.com',
          ...     'password': 'password',
          ...     'confirm': 'password'
          ... }
          >>> dummy_request = DummyRequest(post=valid_post)
          >>> dummy_request.registry.settings = {}
          >>> dummy_request.route_url = Mock()
          >>> return_value = signup_view(dummy_request)
          >>> model.save.called
          True
          >>> view.remember.called
          True
          >>> isinstance(return_value, HTTPFound)
          True
      
      Teardown::
      
          >>> view.remember = _remember
          >>> model.save = _save
          >>> model.get_existing_user = _get_existing_user
          >>> model.get_existing_email = _get_existing_email
      
    """
    
    form = Form(request, schema=schema.Signup, defaults={'failed': False})
    if request.method == 'POST':
        if form.validate():
            d = form.data
            # Determine whether to skip confirmation.
            s = request.registry.settings
            should_skip_confirmation = s.get('auth.skip_confirmation', False)
            # Instantiate the email instance.
            email = model.Email()
            email.address = d['email']
            email.is_confirmed = should_skip_confirmation
            # Instantiate the user instance.
            user = model.User()
            user.username = d['username']
            user.password = model.encrypt(d['password'])
            user.emails = [email]
            # Save the user and email to the db.
            model.save(user)
            # Log the user in.
            remember(request, user.canonical_id)
            # Fire a ``UserSignedUp`` event.
            request.registry.notify(events.UserSignedUp(request, user))
            # Redirect to the user's profile url.
            settings = request.registry.settings
            route_name = settings.get('simpleauth.after_signup_route', 'users')
            try:
                location = request.route_url(route_name, traverse=(user.username,))
            except (KeyError, ComponentLookupError):
                location = '/'
            return HTTPFound(location=location)
        form.data['failed'] = True
    return {'renderer': FormRenderer(form)}


@view_config(context=tree.AuthRoot, name='authenticate', permission=PUBLIC,
        renderer='json', request_method='POST', xhr=True)
def authenticate_view(request):
    """If posted a ``username`` and ``password``, attempt to authenticate the
      user using the credentials provided.  If authentication if successful, 
      return the JSON representation of the authenticated user.
      
      Setup::
      
          >>> from mock import Mock, MagicMock
          >>> from pyramid.testing import DummyRequest
          >>> from pyramid import security
          >>> from pyramid_simpleauth import model, view
          >>> _authenticate = model.authenticate
          >>> _remember = view.remember
          >>> view.remember = Mock()
          >>> model.authenticate = Mock()
      
      If the request doesn't validate, returns an empty dict::
      
          >>> dummy_request = DummyRequest(post={'foo': 'bar'})
          >>> authenticate_view(dummy_request)
          {}
      
      Otherwise tries to authenticate the credentials::
      
          >>> model.authenticate.return_value = None
          >>> valid_post = {
          ...     'username': 'thruflo',
          ...     'password': 'password'
          ... }
          >>> dummy_request = DummyRequest(post=valid_post)
          >>> return_value = authenticate_view(dummy_request)
          >>> model.authenticate.assert_called_with('thruflo', 'password')
      
      If they don't match, returns an empty dict::
      
          >>> authenticate_view(dummy_request)
          {}
      
      If they do, remembers the user and returns the user as a dict::
      
          >>> mock_user = Mock()
          >>> mock_user.canonical_id = 'abc'
          >>> def __json__(*args):
          ...     return '<user as dict>'
          >>> mock_user.__json__ = __json__
          >>> model.authenticate.return_value = mock_user
          >>> dummy_request = DummyRequest(post=valid_post)
          >>> return_value = authenticate_view(dummy_request)
          >>> view.remember.assert_called_with(dummy_request, 'abc')
          >>> return_value
          '<user as dict>'
      
      Teardown::
      
          >>> view.remember = _remember
          >>> model.authenticate = _authenticate
      
    """
    
    form = Form(request, schema=schema.Authenticate)
    if form.validate():
        d = form.data
        user = model.authenticate(d['username'], d['password'])
        if user:
            # Remember the logged in user.
            remember(request, user.canonical_id)
            # Fire a ``UserLoggedIn`` event.
            request.registry.notify(events.UserLoggedIn(request, user))
            # Return the user's public data.
            return user.__json__()
    return {}


@view_config(context=tree.AuthRoot, name='login', permission=PUBLIC,
        renderer='pyramid_simpleauth:templates/login.mako', xhr=False)
def login_view(request):
    """Render login form.  If posted a ``username`` and ``password``, attempt to
      authenticate the user using the credentials provided.  If authentication
      if successful, redirect the user whence they came.
      
      Setup::
      
          >>> from mock import Mock, MagicMock
          >>> from pyramid.testing import DummyRequest
          >>> from pyramid import security
          >>> from pyramid_simpleauth import model, view
          >>> _authenticate = model.authenticate
          >>> model.authenticate = Mock()
      
      If it's not a POST, renders the form::
      
          >>> dummy_request = DummyRequest()
          >>> dummy_request.registry.settings = {}
          >>> return_value = login_view(dummy_request)
          >>> return_value['renderer'].data
          {'failed': False}
      
      Otherwise validates the request::
      
          >>> dummy_request = DummyRequest(post={'foo': 'bar'})
          >>> dummy_request.registry.settings = {}
          >>> return_value = login_view(dummy_request)
          >>> return_value['renderer'].data['failed']
          True
      
      Otherwise tries to authenticate the credentials::
      
          >>> model.authenticate.return_value = None
          >>> valid_post = {
          ...     'username': 'thruflo',
          ...     'password': 'password'
          ... }
          >>> dummy_request = DummyRequest(post=valid_post)
          >>> dummy_request.registry.settings = {}
          >>> return_value = login_view(dummy_request)
          >>> model.authenticate.assert_called_with('thruflo', 'password')
      
      If they don't match::
      
          >>> return_value['renderer'].data['failed']
          True
      
      If they do, redirects with the user's canonical id remembered::
      
          >>> mock_user = Mock()
          >>> mock_user.canonical_id = 'abc'
          >>> model.authenticate.return_value = mock_user
          >>> dummy_request = DummyRequest(post=valid_post)
          >>> dummy_request.registry.settings = {}
          >>> return_value = login_view(dummy_request)
          >>> isinstance(return_value, HTTPFound)
          True
          >>> return_value.location
          '/'
      
      Redirecting to ``next`` if provided::
      
          >>> data = {
          ...     'username': 'thruflo',
          ...     'password': 'password',
          ...     'next': '/foo/bar'
          ... }
          >>> dummy_request = DummyRequest(post=data)
          >>> dummy_request.registry.settings = {}
          >>> return_value = login_view(dummy_request)
          >>> return_value.location
          '/foo/bar'
      
      n.b.: If ``next`` is invalid, it defaults to '/' rather than failing::
      
          >>> data['next'] = '$do.evil(h4x);'
          >>> dummy_request = DummyRequest(post=data)
          >>> return_value = login_view(dummy_request)
          >>> return_value.location
          '/'
      
      Teardown::
      
          >>> model.authenticate = _authenticate
      
    """
    
    # Validate the next param.
    next_ = request.params.get('next', request.POST.get('next'))
    try:
        next_ = schema.RequestPath.to_python(next_)
    except schema.Invalid as err:
        next_ = None
    # Validate the rest of the user input.
    form = Form(request, schema=schema.Login, defaults={'failed': False})
    if request.method == 'POST':
        if form.validate():
            d = form.data
            user = model.authenticate(d['username'], d['password'])
            if user:
                # Remember the logged in user.
                headers = remember(request, user.canonical_id)
                # Work out where to redirect to next.
                if next_:
                    location = next_
                else: # Get the default url to redirect to.
                    settings = request.registry.settings
                    route_name = settings.get('simpleauth.after_login_route', 'index')
                    try:
                        location = request.route_url(route_name, traverse=(user.username,))
                    except (KeyError, ComponentLookupError):
                        location = '/'
                # Fire a ``UserLoggedIn`` event.
                request.registry.notify(events.UserLoggedIn(request, user))
                # Redirect.
                return HTTPFound(location=location, headers=headers)
        form.data['failed'] = True
    # Set ``next`` no matter what.
    if next_:
        form.data['next'] = next_
    return {'renderer': FormRenderer(form)}


@view_config(context=tree.AuthRoot, name='logout', permission='logout')
def logout_view(request):
    """Log the user out and redirect.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid.testing import DummyRequest
          >>> from pyramid_simpleauth import view
          >>> _HTTPFound = view.HTTPFound
          >>> _forget = view.forget
          >>> view.forget = Mock()
          >>> view.forget.return_value = '<headers>'
          >>> view.HTTPFound = Mock()
          >>> view.HTTPFound.return_value = '<redirect>'
      
      Call ``forget(request)`` and redirect to '/'::
      
          >>> dummy_request = DummyRequest()
          >>> dummy_request.user = None
          >>> dummy_request.registry.settings = {}
          >>> logout_view(dummy_request)
          '<redirect>'
          >>> kwargs = {'location': '/', 'headers': '<headers>'}
          >>> view.HTTPFound.assert_called_with(**kwargs)
      
      Teardown::
      
          >>> view.HTTPFound = _HTTPFound
          >>> view.forget = _forget
      
    """
    
    # Get the default url to redirect to after logout.
    settings = request.registry.settings
    route_name = settings.get('simpleauth.after_logout_route', 'index')
    traverse = (request.user.username,) if request.user else ()
    try:
        location = request.route_url(route_name, traverse=traverse)
    except (KeyError, ComponentLookupError):
        location = '/'
    # If there is an authenticated user, fire a ``UserLoggedOut`` event.
    if request.user:
        request.registry.notify(events.UserLoggedOut(request, request.user))
    # Unset the user id from the session.
    headers = forget(request)
    # Redirect.
    return HTTPFound(location=location, headers=headers)
    

