# -*- coding: utf-8 -*-

"""Provides authentication and authorisation views."""

from base64 import urlsafe_b64decode
import inspect

from zope.interface.registry import ComponentLookupError

from pyramid.httpexceptions import HTTPForbidden, HTTPFound, HTTPUnauthorized
from pyramid.security import unauthenticated_userid
from pyramid.security import forget, remember
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC
from pyramid.view import view_config

from pyramid_simpleform import Form
from pyramid_simpleform.renderers import FormRenderer

from pyramid_simpleauth import events, model, schema, tree


def validate_next_param(request):
    "Validate the next param"
    next_ = request.params.get('next', request.POST.get('next'))
    try:
        next_ = schema.RequestPath.to_python(next_)
    except schema.Invalid:
        next_ = None
    return next_


def get_redirect_location(request, user=None, route_name='users',
                          view_name='account'):
    """Try to calculate redirect location based on the 'next' parameter of
    `request`. If there's no 'next' parameter, try to get a route from
    configuration, otherwise redirect to '/'."""
    # Next param is highest priority
    next_ = validate_next_param(request)
    if next_:
        location = next_
    else:
        # Now try configured route
        caller_name = inspect.stack()[1][3] # Get caller view function name

        # Get redirect route name
        redirect_route_name = request.registry.settings.get(
               'simpleauth.after_%s_route' % caller_name, route_name)
        if user is None:
            user = request.user

        # Username is first part of traversal path
        traversal_path = [user.username]

        # Add view name as second part of traversal path if necessary
        if view_name:
            redirect_view_name = request.registry.settings.get(
                    'simpleauth.after_%s_view' % caller_name, view_name)
            traversal_path.append(redirect_view_name)

        try:
            # Resolve route
            location = request.route_url(redirect_route_name,
                                         traverse=traversal_path)
        except (KeyError, ComponentLookupError):
            # Fallback to the homepage
            location = '/'

    return location


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
def login(request):
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
          >>> return_value = login(dummy_request)
          >>> return_value['renderer'].data
          {'failed': False}

      Otherwise validates the request::

          >>> dummy_request = DummyRequest(post={'foo': 'bar'})
          >>> dummy_request.registry.settings = {}
          >>> return_value = login(dummy_request)
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
          >>> return_value = login(dummy_request)
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
          >>> return_value = login(dummy_request)
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
          >>> return_value = login(dummy_request)
          >>> return_value.location
          '/foo/bar'

      n.b.: If ``next`` is invalid, it defaults to '/' rather than failing::

          >>> data['next'] = '$do.evil(h4x);'
          >>> dummy_request = DummyRequest(post=data)
          >>> return_value = login(dummy_request)
          >>> return_value.location
          '/'

      Teardown::

          >>> model.authenticate = _authenticate

    """

    next_ = validate_next_param(request)
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
                location = get_redirect_location(request, user,
                        route_name='index', view_name=None)
                # Fire a ``UserLoggedIn`` event.
                request.registry.notify(events.UserLoggedIn(request, user))
                # Redirect.
                return HTTPFound(location=location, headers=headers)
        form.data['failed'] = True
    # Set ``next`` no matter what.
    if next_:
        form.data['next'] = next_
    return {'renderer': FormRenderer(form)}


@view_config(context=tree.AuthRoot, name='logout', permission='logout',
        request_method='POST')
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


@view_config(context=tree.AuthRoot, name='change_username',
        permission='change_username',
        renderer='pyramid_simpleauth:templates/change_username.mako')
def change_username(request):
    "Change username"
    form = Form(request, schema=schema.ChangeUsername)
    user = request.user
    if request.method == 'POST':
        if form.validate():
            user.username = form.data['username']
            model.save(user)
            request.registry.notify(events.UserChangedUsername(request, user))
            # Get location based on new username
            location = get_redirect_location(request)
            return HTTPFound(location=location)
    # Get location based on unchanged username
    location = get_redirect_location(request)
    form.data['next'] = location
    return {'renderer': FormRenderer(form), 'user': user}


@view_config(context=tree.AuthRoot, name='change_password',
             permission='change_password',
             renderer='pyramid_simpleauth:templates/change_password.mako')
def change_password(request):
    """Change user password."""
    form = Form(request, schema=schema.ChangePassword, defaults={'failed': False})
    user = request.user
    location = get_redirect_location(request)
    if request.method == 'POST':
        if form.validate():
            d = form.data
            user = model.authenticate(user.username, d['old_password'])
            if user:
                # Save new password to the db
                user.password = model.encrypt(d['new_password'])
                model.save(user)
                request.registry.notify(events.UserChangedPassword(request, user))
                return HTTPFound(location=location)
            else:
                form.errors['old_password'] = 'Wrong current password.'

    form.data['next'] = location
    return {'renderer': FormRenderer(form), 'user': request.user}


@view_config(context=tree.AuthRoot, name="confirm", permission=PUBLIC,
             renderer='pyramid_simpleauth:templates/confirm_email_address.mako')
def confirm_email(request):
    """Confirm email address using a confirmation link"""
    try:
        encoded_id, confirmation_hash = request.matchdict['traverse'][1:]
        email_id = urlsafe_b64decode(encoded_id.encode('utf-8'))
    except (ValueError, TypeError):
        return {}
    email = model.Email.query.filter_by(id=email_id,
            confirmation_hash=confirmation_hash).first()
    if email:
        email.is_confirmed = True
        model.save(email)
        user = email.user
        event = events.EmailAddressConfirmed(request, user, 
                                             data={'email': email})
        request.registry.notify(event)
        location = get_redirect_location(request, user)
        return HTTPFound(location=location)
    else:
        return {}


@view_config(context=tree.AuthRoot, name="prefer_email",
             permission="prefer_email")
def prefer_email(request):
    user = request.user
    validator = schema.Email()
    try:
        email_address = validator.to_python(request.POST.get('email_address'))
        email = model.get_existing_email(email_address)
        if email:
            user.preferred_email = email
            model.save(user)
            event = events.EmailPreferred(request, user, data={'email': email})
            request.registry.notify(event)
        else:
            pass
    except schema.Invalid:
        pass 
    location = get_redirect_location(request)
    return HTTPFound(location=location)
