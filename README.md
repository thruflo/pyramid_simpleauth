[pyramid_simpleauth][] is a package that implements session based authentication
and role based security for a [Pyramid][] web application.

There are many other auth implementations for Pyramid, including [apex][] and 
[pyramid_signup][] and you can, of course, easily roll your own, for example
following the excellent [pyramid_auth_demo][].  This package aims to be:

* relatively simple, targeting a limited set of features
* extensible, with event hooks and overrideable templates
* performant, with, by default, one sql query per authenticated request

# Usage

To use, include the package (e.g. in your main application factory):

    config.include('pyramid_simpleauth')

This locks down your application and exposes:

* /auth/signup
* /auth/login
* /auth/authenticate (login via AJAX)
* /auth/logout

Adds a `user` property to the current `request`:

    # e.g.: in a view callable
    if request.is_authenticated:
        display = request.user.username

And provides `UserSignedUp`, `UserloggedIn` and `UserLoggedOut` events:

    @subscriber(UserSignedUp)
    def my_event_handler(event):
        request = event.request
        user = event.user
        # e.g.: send confirmation email

# Templates

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

Or you can override the signup and login templates individually, e.g.:

    config.override_asset(to_override='pyramid_simpleauth:templates/signup.mako',
                          override_with='my_package:my_templates/foo.mako')
    config.override_asset(to_override='pyramid_simpleauth:templates/login.mako',
                          override_with='my_package:my_templates/bar.mako')

# Settings

To change the url path for the authentication views, specify a 
`simpleauth.url_prefix` in your application's `.ini` configuration:

    # defaults to 'auth'
    simpleauth.url_prefix = 'another'

To change where to redirect to after login (when a `next` parameter is not passed
to the login page) and after logout:

    simpleauth.default_after_login_url = '/welcome/back'
    simpleauth.after_logout_url = '/come/again'

To avoid configuring the authorisation and authentication policies (e.g.: if you're
going to set these up yourself) use:

    simpleauth.set_auth_policies = false

To avoid locking down your app to require a 'view' permission for all views by
default (secure but perhaps draconian):

    simpleauth.set_default_permission = False

[apex]: https://github.com/cd34/apex
[pyramid]: http://pyramid.readthedocs.org
[pyramid_auth_demo]: https://github.com/mmerickel/pyramid_auth_demo
[pyramid_signup]: https://github.com/sontek/pyramid_signup
[pyramid_simpleauth]: http://github.com/thruflo/pyramid_simpleauth
