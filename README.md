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

To enable Twitter authentication, use:

    simpleauth.enable_twitter_authentication = true
    simpleauth.oauth_consumer_key = <yourkey>
    simpleauth.oauth_consumer_secret = <yoursecret>

XXX todo layout
XXX todo ...

[pyramid_simpleauth]: http://github.com/thruflo/pyramid_simpleauth
