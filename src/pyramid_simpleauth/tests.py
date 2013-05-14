# -*- coding: utf-8 -*-

"""Functional tests for ``pyramid_simpleauth``."""

import unittest
from mock import Mock

from pyramid_basemodel import Session
from pyramid_simpleauth import model, tree
from pyramid_simpleauth.model import get_existing_user
import transaction

try:  # pragma: no cover
    from webtest import TestApp
except ImportError:  # pragma: no cover
    pass


def config_factory(**settings):
    """Call with settings to make and configure a configurator instance,
      binding to an in memory db.
    """

    from pyramid.config import Configurator
    from pyramid.session import UnencryptedCookieSessionFactoryConfig

    # Patch the settings to use an in memory db for testing, which should
    # be dropped every time the app is created.
    settings['sqlalchemy.url'] = 'sqlite:///:memory:'
    settings['basemodel.should_drop_all'] = True
    # Initialise the ``Configurator`` and setup a session factory.
    config = Configurator(settings=settings)
    config.set_session_factory(UnencryptedCookieSessionFactoryConfig('psst'))
    # Include the dependencies.
    config.include('pyramid_tm')
    config.include('pyramid_basemodel')
    # Include simpleauth.
    config.include('pyramid_simpleauth')
    # Return the configurator instance.
    return config


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        """Configure the Pyramid application."""

        # Configure redirect routes
        view_names = ('change_password', 'change_username', 'confirm_email',
                      'prefer_email')
        settings = dict(('simpleauth.after_%s_route' % view_name,
                         'success_path') for view_name in view_names)
        self.config = config_factory(**settings)
        # Add routes for change_password, change_username,
        # confirm_email_address and preferred_email
        self.config.add_route('success_path', 'victory_path')
        self.app = TestApp(self.config.make_wsgi_app())

    def tearDown(self):
        """Make sure the session is cleared between tests."""

        Session.remove()

    def makeUser(self, username, password):
        """Create and save a user with the credentials provided."""

        user = model.User()
        user.username = username
        user.password = model.encrypt(password)
        model.save(user)
        transaction.commit()
        Session.add(user)
        return user

    def makeUserWithEmail(self):
        "Helper method that creates a user with an email"
        user = self.makeUser(u'thruflo', u'Password')
        Session.add(user)
        user.emails.append(model.Email(address=u'foo@example.com'))
        transaction.commit()
        Session.add(user)
        return user

    def authenticate(self, **post_data):
        "Authenticate user"
        if not post_data:
            post_data = {
                'username': 'thruflo',
                'password': 'Password'
            }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        return self.app.post('/auth/authenticate', post_data, headers=headers)


class TestSignup(BaseTestCase):

    def test_render_signup_form(self):
        """A GET request to the signup view should render the signup form."""

        res = self.app.get('/auth/signup')
        self.failUnless('<input id="username" name="username"' in res.body)

    def test_signup(self):
        """Signup saves a user and their email address."""

        # Sanity check there isn't an existing user.
        existing = get_existing_user(username='thruflo')
        self.assertTrue(existing is None)
        # Signup.
        post_data = {
            'username': 'user',
            'email': 'foo@gmail.com',
            'password': 'Password',
            'confirm': 'Password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        assert res  # to satisfy pyflakes
        # Now there is a user.
        existing = get_existing_user(username='user')
        self.assertTrue(existing is not None)
        # And their email address is...
        self.assertTrue(existing.emails[0].address == 'foo@gmail.com')

    def test_signup_remember(self):
        """Signup logs the user in."""

        # The first request sets an empty session cookie.
        res = self.app.post('/auth/signup', {}, status="*")
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)
        # Signup sets a cookie to remember the user.
        post_data = {
            'username': 'user',
            'email': 'foo@gmail.com',
            'password': 'Password',
            'confirm': 'Password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)

    def test_signup_redirect(self):
        """Signup redirects to the user's profile page."""

        # Signup.
        post_data = {
            'username': 'thruflo',
            'email': 'foo@gmail.com',
            'password': 'Password',
            'confirm': 'Password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        # The response redirects to `/` by default with no routes or settings.
        self.assertTrue(res.headers['Location'] == 'http://localhost/')
        # The response redirects to the `users` route if exposed.
        self.config = config_factory()
        self.config.add_route('users', 'some/path')
        self.app = TestApp(self.config.make_wsgi_app())
        post_data = {
            'username': 'thruflo2',
            'email': 'foo+2@gmail.com',
            'password': 'Password',
            'confirm': 'Password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        self.assertTrue(
            res.headers['Location'] == 'http://localhost/some/path')
        # The response redirects to the `simpleauth.after_signup_route` route
        # if specified.
        settings = {
            'simpleauth.after_signup_route': 'flobble'
        }
        self.config = config_factory(**settings)
        self.config.add_route('flobble', 'wob')
        self.app = TestApp(self.config.make_wsgi_app())
        post_data = {
            'username': 'thruflo3',
            'email': 'foo+3@gmail.com',
            'password': 'Password',
            'confirm': 'Password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/wob')

    def test_signup_event(self):
        """Signup fires a ``UserSignedUp`` event."""

        from pyramid_simpleauth.events import UserSignedUp
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserSignedUp)
        self.app = TestApp(self.config.make_wsgi_app())
        # Signup.
        post_data = {
            'username': 'jo',
            'email': 'foo@gmail.com',
            'password': 'Password',
            'confirm': 'Password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        assert res  # to satisfy pyflakes
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))


class TestLogin(BaseTestCase):

    def test_render_login_form(self):
        """A GET request to the login view should render the login form."""

        res = self.app.get('/auth/login')
        self.failUnless('<input id="username" name="username"' in res.body)

    def test_render_login_next(self):
        """A GET request to the login view will pass through the `next` param.
        """

        res = self.app.get('/auth/login?next=/foo/bar')
        tag = '<input id="next" name="next" type="hidden" value="/foo/bar" />'
        self.failUnless(tag in res.body)

    def test_login(self):
        """Login remembers the user."""

        # Create a user.
        self.makeUser('thruflo', 'Password')
        # Login with the wrong details sets an empty session cookie.
        post_data = {
            'username': 'pooplo',
            'password': 'wrong'
        }
        res = self.app.post('/auth/login', post_data, status="*")
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)
        # Login with the right details remembers the user in the session
        # cookie.
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        res = self.app.post('/auth/login', post_data, status="*")
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)

    def test_login_redirect(self):
        """login redirects to ``next``."""

        # Create a user.
        self.makeUser('thruflo', 'Password')
        # Login with the right details redirects to `next`.
        post_data = {
            'username': 'thruflo',
            'password': 'Password',
            'next': '/foo/bar'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/foo/bar')
        # If `next` is not provided, redirects to `/`
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/')
        # Or the 'index' route if exposed.
        self.config = config_factory()
        self.config.add_route('index', 'some/path')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertEquals(res.location, 'http://localhost/some/path')
        # Or the `simpleauth.after_logout_route` route if specified and
        # exposed.
        settings = {
            'simpleauth.after_login_route': 'flobble'
        }
        self.config = config_factory(**settings)
        self.config.add_route('flobble', 'wob')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/wob')

    def test_login_event(self):
        """Login fires a ``UserLoggedIn`` event."""

        from pyramid_simpleauth.events import UserLoggedIn
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedIn)
        self.app = TestApp(self.config.make_wsgi_app())
        # Login.
        self.makeUser('thruflo', 'Password')
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        assert res  # to satisfy pyflakes
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))


class TestAuthenticate(BaseTestCase):

    def test_authenticate_requires_xhr(self):
        """Authenticate must be called with an XMLHTTPRequest."""

        # Authentication remembers the user in the session cookie.
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        res = self.app.post('/auth/authenticate', post_data, status=404)
        self.assertTrue('The resource could not be found.' in res.body)

    def test_authenticate_remembers(self):
        """Authenticate remembers the user."""

        # Create a user.
        self.makeUser('thruflo', 'Password')
        # Authentication remembers the user in the session cookie.
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        res = self.app.post('/auth/authenticate', post_data, headers=headers)
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)

    def test_authenticate_returns_json(self):
        """Authenticate returns the user's data in JSON format."""

        import json
        # Create a user.
        self.makeUser('thruflo', 'Password')
        # Returns JSON.
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        res = self.app.post('/auth/authenticate', post_data, headers=headers)
        self.assertTrue(json.loads(res.body)['username'] == 'thruflo')

    def test_authenticate_logged_in_event(self):
        """Authenticate fires a ``UserLoggedIn`` event."""

        from pyramid_simpleauth.events import UserLoggedIn
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedIn)
        self.app = TestApp(self.config.make_wsgi_app())
        # Login.
        self.makeUser('thruflo', 'Password')
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        res = self.app.post('/auth/authenticate', post_data, headers=headers)
        assert res  # to satisfy pyflakes
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))


class TestLogout(BaseTestCase):

    def test_logout(self):
        """Logout forgets the user."""

        # Create a user.
        self.makeUser('thruflo', 'Password')
        # Login.
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)
        # Logout.
        res = self.app.post('/auth/logout', status=302)
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)

    def test_logout_redirects(self):
        """Logout redirects."""

        # The response redirects to `/` by default with no routes or settings.
        res = self.app.post('/auth/logout', status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/')
        # The response redirects to the `index` route if exposed.
        self.config = config_factory()
        self.config.add_route('index', 'some/path')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.post('/auth/logout', status=302)
        self.assertTrue(
            res.headers['Location'] == 'http://localhost/some/path')
        # The response redirects to the `simpleauth.after_logout_route` route
        # if specified.
        settings = {
            'simpleauth.after_logout_route': 'flobble'
        }
        self.config = config_factory(**settings)
        self.config.add_route('flobble', 'wob')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.post('/auth/logout', status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/wob')

    def test_loggedout_event(self):
        """Logout fires a ``UserLoggedOut`` event."""

        from pyramid_simpleauth.events import UserLoggedOut
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedOut)
        self.app = TestApp(self.config.make_wsgi_app())
        # Login.
        self.makeUser('thruflo', 'Password')
        post_data = {
            'username': 'thruflo',
            'password': 'Password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        # Logout.
        res = self.app.post('/auth/logout', status=302)
        assert res  # to satisfy pyflakes
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))

    def test_loggedout_event_requires_user(self):
        """Logout only fires a ``UserLoggedOut`` event when there was an
          authenticated user.
        """

        from pyramid_simpleauth.events import UserLoggedOut
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedOut)
        self.app = TestApp(self.config.make_wsgi_app())
        # Logout.
        res = self.app.post('/auth/logout', status=302)
        assert res  # to satisfy pyflakes
        # Handler was not called.
        self.assertFalse(mock_subscriber.called)


class TestChangePassword(BaseTestCase):

    def test_wrong_old_password(self):
        "No password change if old password is not corret"

        # Create a user.
        user = self.makeUser('thruflo', 'Password')
        Session.add(user)
        old_hash = user.password

        self.authenticate()

        # Attempt to change password.
        post_data = {
            'old_password': 'foobarbaz',
            'new_password': 'swordpas',
            'new_confirm':  'swordpas',
            'next':         '/foo/bar',
        }
        res = self.app.post('/auth/change_password', post_data)

        # Verify that password hasn't changed
        Session.add(user)
        Session.refresh(user)
        self.assertTrue("Wrong current password" in res.body)
        self.assertTrue("/foo/bar" in res.body)
        self.assertEquals(user.password, old_hash)

    def test_wrong_old_password_returns_valid_user(self):
        "Bug fix: user template param must not be None"
        from pyramid_simpleauth.view import change_password
        from pyramid import testing

        # Create a user.
        user = self.makeUser('thruflo', 'Password')
        Session.add(user)

        post_data = {
            'old_password': 'foobarbaz',
            'new_password': 'sworDpas',
            'new_confirm':  'sworDpas',
        }
        request = testing.DummyRequest(post=post_data)
        request.user = user
        testing.setUp(settings={})
        res = change_password(request)

        self.assertTrue(res['user'])

    def test_new_passwords_dont_match(self):
        "No password change if new passwords don't match"

        # Create a user.
        user = self.makeUser('thruflo', 'Password')
        Session.add(user)
        old_hash = user.password

        self.authenticate()

        # Attempt to change password.
        post_data = {
            'old_password': 'Password',
            'new_password': 'swordpas',
            'new_confirm':  'oswdrpsa',
        }
        res = self.app.post('/auth/change_password', post_data)

        # Verify that password hasn't changed
        Session.add(user)
        Session.refresh(user)
        self.assertTrue("Fields do not match" in res.body)
        self.assertEquals(user.password, old_hash)

    def test_sucess(self):
        "If all conditions are met, change password"

        # Create a user.
        user = self.makeUser('thruflo', 'Password')
        Session.add(user)
        old_hash = user.password

        self.authenticate()

        # Attempt to change password.
        post_data = {
            'old_password': 'Password',
            'new_password': 'sworDpas',
            'new_confirm':  'sworDpas',
            'next':         '/foo/bar',
        }
        res = self.app.post('/auth/change_password', post_data)

        # Verify that password has changed
        Session.add(user)
        Session.refresh(user)
        self.assertNotEquals(user.password, old_hash)

        # Verify redirect
        self.assertEquals(res.headers['Location'], 'http://localhost/foo/bar')

    def test_sucess_logs_user_out(self):
        "Changing a user password logs the user out."

        from pyramid_simpleauth.events import UserLoggedOut
        from pyramid_simpleauth.model import User
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedOut)
        self.app = TestApp(self.config.make_wsgi_app())

        # Create a user.
        user = self.makeUser('thruflo', 'Password')
        Session.add(user)
        old_hash = user.password

        self.authenticate()

        # Attempt to change password.
        post_data = {
            'old_password': 'Password',
            'new_password': 'sworDpas',
            'new_confirm':  'sworDpas',
            'next':         '/foo/bar',
        }
        res = self.app.post('/auth/change_password', post_data)

        # Verify logged out.
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)

        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))


class TestChangeUsername(BaseTestCase):

    def test_success(self):
        "Change username with valid input"
        # Create a user.
        user = self.makeUser(u'thruflo', u'Password')

        # Attempt to change username
        post_data = {
            'username': u'bob',
            'next':     '/foo/bar',
        }
        self.authenticate()
        res = self.app.post('/auth/change_username', post_data)

        # Verify redirect
        self.assertEquals(res.location, 'http://localhost/foo/bar')

        # Verify that username has changed
        Session.add(user)
        self.assertEquals(user.username, 'bob')

    def test_failure(self):
        "Change username with invalid input"
        # Create a user.
        user = self.makeUser(u'thruflo', u'Password')

        # Attempt to assign bogus username
        post_data = {
            'username': u'$ @ 88 , /',
            'next':     '/foo/bar',
        }
        self.authenticate()
        res = self.app.post('/auth/change_username', post_data)

        # Verify response body
        self.assertTrue('No spaces or funny characters' in res.body)
        self.assertTrue('/foo/bar' in res.body,
                        "Response body should contain next hidden field")

        # Verify that username has not changed
        Session.add(user)
        self.assertEquals(user.username, 'thruflo')


class TestConfirmEmailAddress(BaseTestCase):

    def makeConfirmationLink(self, email):
        "Helper method that makes a valid confirmation link"
        from pyramid_simpleauth.model import get_confirmation_link
        request = Mock()
        request.route_url.return_value = '/auth/confirm'
        return get_confirmation_link(request, email)

    def test_success(self):
        "Token is valid, email address should be confirmed"
        # Create a user
        user = self.makeUserWithEmail()

        # Sanity check
        self.assertFalse(user.emails[0].is_confirmed)

        # Get valid confirmation link
        email = user.emails[0]
        confirmation_link = self.makeConfirmationLink(email)

        # Attempt to confirm email address
        res = self.app.get(confirmation_link)
        self.assertTrue(res.location.endswith('victory_path'))

        # Now configure settings with a route that doesn't exist
        settings = {'simpleauth.after_confirm_email_route': 'success_path'}
        self.config = config_factory(**settings)
        # Not adding the route!
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.get(confirmation_link)
        self.assertEquals(res.location, 'http://localhost/')

        # Verify that email address has been confirmed
        Session.add(email)
        Session.refresh(email)
        self.assertTrue(email.is_confirmed)

    def test_failure(self):
        "Token is invalid, email address should not be confirmed"
        # Create a user
        user = self.makeUserWithEmail()

        # Sanity check
        self.assertFalse(user.emails[0].is_confirmed)

        # Bogus attempts to confirm email address
        # 1. malformed link
        url = '/auth/confirm/foo'
        res = self.app.get(url)
        self.assertTrue('invalid' in res.body)

        # 2. invalid token
        email = user.emails[0]
        url = self.makeConfirmationLink(email) + 'gibberish'
        res = self.app.get(url)
        self.assertTrue('invalid' in res.body)

        # Verify that email address has been confirmed
        Session.add(email)
        Session.refresh(email)
        self.assertFalse(email.is_confirmed)


class TestPreferEmail(BaseTestCase):

    def test_success(self):
        "Set preferred email address"
        # Create user with email address
        user = self.makeUserWithEmail()
        # Add another one
        user.emails.append(model.Email(address=u'bar@example.com',
                           is_preferred=True))
        model.save(user)
        transaction.commit()
        Session.add(user)

        email1, email2 = user.emails

        # Sanity check
        self.assertNotEquals(user.preferred_email, email1)
        self.assertEquals(user.preferred_email, email2)

        # Attempt to make the address primary
        self.authenticate()
        self.app.post('/auth/prefer_email', {
            'email_address': email1.address
        })

        # Verify that email is not the user's preferred email
        Session.add(email1)
        Session.refresh(email1)
        self.assertEquals(user.preferred_email, email1)
        self.assertNotEquals(user.preferred_email, email2)

    def test_failure(self):
        "Attempt to set preferred email address with invalid input"
        # Create user with email address
        user = self.makeUserWithEmail()
        email = user.emails[0]

        # Attempt to make the address primary
        self.authenticate()
        self.app.post('/auth/prefer_email', {
            'email_address': email.address + 'not an email address'
        })

        # Email address should not be prefered
        self.assertNotEquals(user.preferred_email, email)

    def test_prefer_non_persisted_email(self):
        "Set non-persisted email object as new preferred email"
        # Create user without any email address
        user = self.makeUser('bob', '123')

        # Directly set new email as preferred email
        email = model.Email(address=u'bar@example.com')
        user.preferred_email = email
        model.save(user)
        transaction.commit()

        # Verify that the new email is now the preferred email
        Session.add(user)
        self.assertEquals(user.preferred_email.address, u'bar@example.com')

    def test_preferred_if_only_one(self):
        "If user has only one email, consider it as preferred email"
        # Create user without any email address
        user = self.makeUser('bob', '123')

        # Directly set new email as preferred email
        email = model.Email(address=u'bar@example.com')
        user.emails.append(email)
        model.save(user)
        transaction.commit()

        # Verify that the new email is now the preferred email
        Session.add(user)
        self.assertEquals(user.preferred_email.address, u'bar@example.com')


class TestDeleteUser(BaseTestCase):

    def add_user_root(self):
        "Configure app with /users/<username> route"
        self.config = config_factory()
        self.config.add_route('users', 'users/*traverse',
                              factory=tree.UserRoot, use_global_views=True)
        self.app = TestApp(self.config.make_wsgi_app())

    def test_success(self):
        "User can delete itself"
        self.add_user_root()

        user = self.makeUser('thruflo', 'Password')
        Session.add(user)

        self.authenticate()

        # Attempt to delete user
        res = self.app.get('/users/thruflo/delete_user')

        # Verify confirmation message
        self.assertTrue('Are you really sure' in res.body)

        # Verify that the user has not yet been deleted
        self.assertTrue(get_existing_user(username='thruflo') is not None)

        # Delete the user
        res = self.app.post('/users/thruflo/delete_user')

        # Verify that the user has now been deleted
        self.assertTrue(get_existing_user(username='thruflo') is None)

        # User should be logged out
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)

    def test_other_user(self):
        "Non-admin user cannot delete other user"
        self.add_user_root()

        # User to delete
        self.makeUser('alice', 'Password')

        # Login as other user
        bob = self.makeUser('bob', 'Password')
        model.save(bob)
        transaction.commit()
        self.authenticate(username='bob', password='Password')

        # Try to delete user
        res = self.app.post('/users/alice/delete_user', status=403)

        # Verify that the user has not been deleted
        self.assertTrue(get_existing_user(username='alice') is not None)
        # User should still be logged in
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)

    def test_admin(self):
        "Admin should be allowed to delete any user"
        self.add_user_root()

        # User to delete
        self.makeUser('alice', 'Password')

        # Login as admin
        admin = self.makeUser('admin', 'Password')
        admin.roles.append(model.Role(name='admin'))
        model.save(admin)
        transaction.commit()
        self.authenticate(username='admin', password='Password')

        # Delete user
        res = self.app.post('/users/alice/delete_user')

        # Verify that user has been successfully deleted
        self.assertTrue(get_existing_user(username='alice') is None)
        # Admin should still be logged in
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)
