# -*- coding: utf-8 -*-

"""Functional tests for ``pyramid_simpleauth``."""

import unittest

try: # pragma: no cover
    from webtest import TestApp
except ImportError: # pragma: no cover
    pass

def config_factory(**settings):
    """Call with settings to make and configure a configurator instance, binding
      to an in memory db.
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


class TestSignup(unittest.TestCase):
    def setUp(self):
        """Configure the Pyramid application."""
        
        self.config = config_factory()
        self.app = TestApp(self.config.make_wsgi_app())
    
    def tearDown(self):
        """Make sure the session is cleared between tests."""
        
        from pyramid_basemodel import Session
        Session.remove()
    
    def test_render_signup_form(self):
        """A GET request to the signup view should render the signup form."""
        
        res = self.app.get('/auth/signup')
        self.failUnless('<input id="username" name="username"' in res.body)
    
    def test_signup(self):
        """Signup saves a user and their email address."""
        
        from pyramid_simpleauth.model import get_existing_user
        # Sanity check there isn't an existing user.
        existing = get_existing_user(username='thruflo')
        self.assertTrue(existing is None)
        # Signup.
        post_data = {
            'username': 'user',
            'email': 'foo@gmail.com',
            'password': 'password',
            'confirm': 'password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
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
            'password': 'password',
            'confirm': 'password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)
    
    def test_signup_redirect(self):
        """Signup redirects to the user's profile page."""
        
        # Signup.
        post_data = {
            'username': 'thruflo',
            'email': 'foo@gmail.com',
            'password': 'password',
            'confirm': 'password'
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
            'password': 'password',
            'confirm': 'password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/some/path')
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
            'password': 'password',
            'confirm': 'password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/wob')
    
    def test_signup_event(self):
        """Signup fires a ``UserSignedUp`` event."""
        
        from mock import Mock
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
            'password': 'password',
            'confirm': 'password'
        }
        res = self.app.post('/auth/signup', post_data, status=302)
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))
    

class TestLogin(unittest.TestCase):
    def setUp(self):
        """Configure the Pyramid application."""
        
        self.config = config_factory()
        self.app = TestApp(self.config.make_wsgi_app())
    
    def tearDown(self):
        """Make sure the session is cleared between tests."""
        
        from pyramid_basemodel import Session
        Session.remove()
    
    def makeUser(self, username, password):
        """Create and save a user with the credentials provided."""
        
        import transaction
        from pyramid_simpleauth import model
        user = model.User()
        user.username = username
        user.password = model.encrypt(password)
        model.save(user)
        transaction.commit()
    
    def test_render_login_form(self):
        """A GET request to the login view should render the login form."""
        
        res = self.app.get('/auth/login')
        self.failUnless('<input id="username" name="username"' in res.body)
    
    def test_render_login_next(self):
        """A GET request to the login view will pass through the `next` param."""
        
        res = self.app.get('/auth/login?next=/foo/bar')
        tag = '<input id="next" name="next" type="hidden" value="/foo/bar" />'
        self.failUnless(tag in res.body)
    
    def test_login(self):
        """Login remembers the user."""
        
        # Create a user.
        self.makeUser('thruflo', 'password')
        # Login with the wrong details sets an empty session cookie.
        post_data = {
            'username': 'pooplo',
            'password': 'wrong'
        }
        res = self.app.post('/auth/login', post_data, status="*")
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)
        # Login with the right details remembers the user in the session cookie.
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        res = self.app.post('/auth/login', post_data, status="*")
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)
    
    def test_login_redirect(self):
        """login redirects to ``next``."""
        
        # Create a user.
        self.makeUser('thruflo', 'password')
        # Login with the right details redirects to `next`.
        post_data = {
            'username': 'thruflo',
            'password': 'password',
            'next': '/foo/bar'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/foo/bar')
        # If `next` is not provided, redirects to `/`
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/')
        # Or the 'index' route if exposed.
        self.config = config_factory()
        self.config.add_route('index', 'some/path')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/some/path')
        # Or the `simpleauth.after_logout_route` route if specified and exposed.
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
        
        from mock import Mock
        from pyramid_simpleauth.events import UserLoggedIn
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedIn)
        self.app = TestApp(self.config.make_wsgi_app())
        # Login.
        self.makeUser('thruflo', 'password')
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))
    

class TestAuthenticate(unittest.TestCase):
    def setUp(self):
        """Configure the Pyramid application."""
        
        self.config = config_factory()
        self.app = TestApp(self.config.make_wsgi_app())
    
    def tearDown(self):
        """Make sure the session is cleared between tests."""
        
        from pyramid_basemodel import Session
        Session.remove()
    
    def makeUser(self, username, password):
        """Create and save a user with the credentials provided."""
        
        import transaction
        from pyramid_simpleauth import model
        user = model.User()
        user.username = username
        user.password = model.encrypt(password)
        model.save(user)
        transaction.commit()
    
    def test_authenticate_requires_xhr(self):
        """Authenticate must be called with an XMLHTTPRequest."""
        
        # Authentication remembers the user in the session cookie.
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        res = self.app.post('/auth/authenticate', post_data, status=404)
        self.assertTrue('The resource could not be found.' in res.body)
    
    def test_authenticate_remembers(self):
        """Authenticate remembers the user."""
        
        # Create a user.
        self.makeUser('thruflo', 'password')
        # Authentication remembers the user in the session cookie.
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        res = self.app.post('/auth/authenticate', post_data, headers=headers)
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)
    
    def test_authenticate_returns_json(self):
        """Authenticate returns the user's data in JSON format."""
        
        import json
        # Create a user.
        self.makeUser('thruflo', 'password')
        # Returns JSON.
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        res = self.app.post('/auth/authenticate', post_data, headers=headers)
        self.assertTrue(json.loads(res.body)['username'] == 'thruflo')
    
    def test_authenticate_logged_in_event(self):
        """Authenticate fires a ``UserLoggedIn`` event."""
        
        from mock import Mock
        from pyramid_simpleauth.events import UserLoggedIn
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedIn)
        self.app = TestApp(self.config.make_wsgi_app())
        # Login.
        self.makeUser('thruflo', 'password')
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        res = self.app.post('/auth/authenticate', post_data, headers=headers)
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))
    

class TestLogout(unittest.TestCase):
    def setUp(self):
        """Configure the Pyramid application."""
        
        self.config = config_factory()
        self.app = TestApp(self.config.make_wsgi_app())
    
    def tearDown(self):
        """Make sure the session is cleared between tests."""
        
        from pyramid_basemodel import Session
        Session.remove()
    
    def makeUser(self, username, password):
        """Create and save a user with the credentials provided."""
        
        import transaction
        from pyramid_simpleauth import model
        user = model.User()
        user.username = username
        user.password = model.encrypt(password)
        model.save(user)
        transaction.commit()
    
    def test_logout(self):
        """Logout forgets the user."""
        
        # Create a user.
        self.makeUser('thruflo', 'password')
        # Login.
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        self.assertTrue(len(res.headers['Set-Cookie']) > 250)
        # Logout.
        res = self.app.get('/auth/logout', status=302)
        self.assertTrue(len(res.headers['Set-Cookie']) < 200)
    
    def test_logout_redirects(self):
        """Logout redirects."""
        
        # The response redirects to `/` by default with no routes or settings.
        res = self.app.get('/auth/logout', status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/')
        # The response redirects to the `index` route if exposed.
        self.config = config_factory()
        self.config.add_route('index', 'some/path')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.get('/auth/logout', status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/some/path')
        # The response redirects to the `simpleauth.after_logout_route` route
        # if specified.
        settings = {
            'simpleauth.after_logout_route': 'flobble'
        }
        self.config = config_factory(**settings)
        self.config.add_route('flobble', 'wob')
        self.app = TestApp(self.config.make_wsgi_app())
        res = self.app.get('/auth/logout', status=302)
        self.assertTrue(res.headers['Location'] == 'http://localhost/wob')
    
    def test_loggedout_event(self):
        """Logout fires a ``UserLoggedOut`` event."""
        
        from mock import Mock
        from pyramid_simpleauth.events import UserLoggedOut
        from pyramid_simpleauth.model import User
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedOut)
        self.app = TestApp(self.config.make_wsgi_app())
        # Login.
        self.makeUser('thruflo', 'password')
        post_data = {
            'username': 'thruflo',
            'password': 'password'
        }
        res = self.app.post('/auth/login', post_data, status=302)
        # Logout.
        res = self.app.get('/auth/logout', status=302)
        # Handler was called with the authentiated user as the second arg.
        self.assertTrue(mock_subscriber.called)
        event = mock_subscriber.call_args_list[0][0][0]
        self.assertTrue(isinstance(event.user, User))
    
    def test_loggedout_event_requires_user(self):
        """Logout only fires a ``UserLoggedOut`` event when there was an
          authenticated user.
        """
        
        from mock import Mock
        from pyramid_simpleauth.events import UserLoggedOut
        # Setup event listener.
        mock_subscriber = Mock()
        self.config = config_factory()
        self.config.add_subscriber(mock_subscriber, UserLoggedOut)
        self.app = TestApp(self.config.make_wsgi_app())
        # Logout.
        res = self.app.get('/auth/logout', status=302)
        # Handler was not called.
        self.assertFalse(mock_subscriber.called)
    

