[pyramid_simpleauth][] is a package that implements session based authentication
and role based security for a [Pyramid][] web application.

There are many other auth implementations for Pyramid, including [apex][] and 
[pyramid_signup][] and you can, of course, easily roll your own, for example
following the excellent [pyramid_auth_demo][].  This package aims to be:

* relatively simple: with a limited feature set
* extensible: with event hooks and overrideable templates
* performant: minimising db queries

# Features

If you install the package and include it in your Pyramid application, it will
lock down your application and expose views at:

* /auth/signup
* /auth/login
* /auth/authenticate (login via AJAX)
* /auth/logout
* /auth/change\_username
* /auth/change\_password
* /auth/confirm (email confirmation)
* /auth/prefer\_email (set email as the user's preferred email)

You get a `user` instance and an `is_authenticated` flag added to the `request`:

    # e.g.: in a view callable
    if request.is_authenticated:
        display = request.user.username

Plus `UserSignedUp`, `UserloggedIn`, `UserLoggedOut`, `UserChangedPassword`,
`UserChangedUsername`, `EmailPreferred` and `EmailAddressConfirmed` events to
subscribe to:

    @subscriber(UserSignedUp)
    def my_event_handler(event):
        request = event.request
        user = event.user
        # e.g.: send confirmation email

Flags at `request.is_post_login` and `request.is_post_signup`, stored in the session, 
that allow you to test whether the current request is immediately after a login or 
signup event.  And a `request.user_json` property (useful to write into a template 
to pass data to the client side).

`model.get_confirmation_link(request, email)` returns a `confirmation_link`
that will be accepted by `/auth/confirm` and that can typically be included in
an email sent to a user who wish to validate an email address.

The `EmailAddressConfirmed` and `EmailPreferred` events give you access to the
`Email` object as `event.data['email']`, eg:

    @subscriber(EmailAddressConfirmed)
    def email_address_confirmed(event):
      email_address = event.data['email'].address
      session = event.request.session
      session.flash("%s has been confirmed successfully" % email_address)


# Install

Install using `pip` or `easy_install`, e.g.:

    pip install pyramid_simpleauth

# Configure

Include the package along with a session factory, `pyramid_tm` and `pyramid_basemodel`
in the configuration portion of your Pyramid app:

    # Configure a session factory, here, we're using `pyramid_beaker`.
    config.include('pyramid_beaker')
    config.set_session_factory(session_factory_from_settings(settings))
    
    # Either include `pyramid_tm` or deal with committing transactions yourself.
    config.include('pyramid_tm')
    
    # Either include `pyramid_basemodel` and provide an `sqlalchemy.url` in your
    # `.ini` settings, or bind the SQLAlchemy models and scoped `Session` to a
    # database engine yourself.
    config.include('pyramid_basemodel')
    
    # Include the package.
    config.include('pyramid_simpleauth')

The signup and login forms inherit from a base layout template.  You can override
this base layout template by writing your own, e.g.:

    # my_package:my_templates/layout.mako
    <!DOCTYPE HTML>
    <html>
      <head>
        <title>${self.subtitle()}</title>
        <link href="my_great.css" rel="stylesheet" type="text/css" />
      </head>
      <body>
        <div class="my-great-markup">
          ${next.body()}
        </duv>
      </body>
    </html>
    
Then in your main app factory / package configuration use, e.g.:

    config.override_asset(to_override='pyramid_simpleauth:templates/layout.mako',
                          override_with='my_package:my_templates/layout.mako')

Or you can nuke the signup and login templates directly, e.g.:

    config.override_asset(to_override='pyramid_simpleauth:templates/signup.mako',
                          override_with='my_package:my_templates/foo.mako')
    config.override_asset(to_override='pyramid_simpleauth:templates/login.mako',
                          override_with='my_package:my_templates/bar.mako')

To change the url path for the authentication views, specify a 
`simpleauth.url_prefix` in your application's `.ini` configuration:

    # defaults to 'auth', resulting in urls that start with `/auth/...`
    simpleauth.url_prefix = 'another'

You can also specify where to redirect to after signup, login, logout, username
change, password change, email confirmation or preferred email selection. These
are all configured using *route names*, with the route being provided the
additional traversal information of the user's username and an optional view
name.  (This means you can expose a simple named route, or a hybrid route, as
you prefer.  The hybrid route will attempt traversal on the username).

To redirect to a different named route after signup / login or logout use:

    simpleauth.after_signup_route = 'another' # defaults to 'users'
    simpleauth.after_login_route = 'another' # defaults to 'index'
    simpleauth.after_logout_route = 'another' # defaults to 'index'

Note that a `next` parameter passed to the login page, password
change page, username change page, email confirmation page or preferred email
selection page will take precedence over the specific routes.

To redirect to a different route and view after login, password change, username
change, email confirmation or preferred email selection, use configuration
directives such as:

    simpleauth.after_confirm_email_route = 'basepath' # defaults to 'users'
    simpleauth.after_confirm_email_view = 'viewname', # defaults to 'account'

This would redirect user bob to `/basepath/bob/viewname`. Redirect configuration
directives for each of those views are named following the patterns
`simpleauth.after_<view_name>_route` and `simpleauth.after_<view_name>_view`,
where `<view_name>` can be any of `login`, `change_username`,
`change_password`, `confirm_email` and `prefer_email`.

Be careful in the case of username change because if your `next` URL contains a
username, it won't be valid anymore after the username has changed, eg. if you
instruct the username change page to redirect to `/basepath/bob/viewname` but
the username changes to become alice, the redirect will cause a "page not found"
error. In this case, if you want to include a username in your custom redirect,
you should use the configuration-based redirect location will take into account
the new username.

By default the app redirects after signup to a route named 'users'.  This is
not exposed by `pyramid_simpleauth` by default but the package does provide a 
`.tree.UserRoot` root factory that looks up `.model.User`s by username and a
default `__acl__` property on the `.model.User` class.  These are entirely
optional: you can choose instead to use a different named route, or expose
a simple named route using, e.g.:

    config.add_route('users', 'some/path')

However, if you want to use the machinery provided, with the baked in security
and traversal, you can expose a user profile view, or perhaps a welcome page at 
`/users/:username` using, e.g.:

    config.add_route('users', 'users/*traverse', factory=UserRoot,
                     use_global_views=True)

To avoid configuring the authorisation and authentication policies (e.g.: if you're
going to set these up yourself) use:

    simpleauth.set_auth_policies = false

To avoid locking down your app to require a 'view' permission for all views by
default (secure but perhaps draconian):

    simpleauth.set_default_permission = False

# Tests

I've only tested the package under Python 2.6 and 2.7 atm.  It should work under
Python 3 but I have problems installing the `passlib` dependency (or any decent
password encryption library) under Python 3.

You'll need `nose`, `coverage`, `mock` and `WebTest`.  Then, e.g.:

    $ nosetests --cover-package=pyramid_simpleauth --cover-tests --with-doctest --with-coverage
    ..........................................
    Name                        Stmts   Miss  Cover   Missing
    ---------------------------------------------------------
    pyramid_simpleauth             19      0   100%   
    pyramid_simpleauth.events      26      0   100%   
    pyramid_simpleauth.hooks       13      0   100%   
    pyramid_simpleauth.model       56      0   100%   
    pyramid_simpleauth.schema      83      0   100%   
    pyramid_simpleauth.tests      197      0   100%   
    pyramid_simpleauth.tree        18      0   100%   
    pyramid_simpleauth.view        76      0   100%   
    ---------------------------------------------------------
    TOTAL                         488      0   100%   
    ----------------------------------------------------------------------
    Ran 42 tests in 16.408s

    OK

[apex]: https://github.com/cd34/apex
[pyramid]: http://pyramid.readthedocs.org
[pyramid_auth_demo]: https://github.com/mmerickel/pyramid_auth_demo
[pyramid_signup]: https://github.com/sontek/pyramid_signup
[pyramid_simpleauth]: http://github.com/thruflo/pyramid_simpleauth
