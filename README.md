[pyramid_simpleauth][] is a package that provides an SQLAlchemy `User` class with the
relations and views required to manage:

* authentication via login form or Twitter
* role based authorisation

To use it, you may need to provide some `simpleauth.*` settings and then 
include the package:

    config.include('pyramid_simpleauth')

By default, the package will expose the various views on `/auth/...`.  To use
a different prefix specify:

    simpleauth.url_prefix = '/another'

Ditto where to redirect to after login (when a `next` parameter is not passed
to the login page) and after logout:

    simpleauth.default_after_login_url = '/welcome/back'
    simpleauth.after_logout_url = '/come/again'

[pyramid_simpleauth]: http://github.com/thruflo/pyramid_simpleauth
