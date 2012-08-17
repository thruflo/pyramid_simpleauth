<%inherit file="pyramid_simpleauth:templates/layout.mako" />

<%def name="subtitle()">Change username</%def>

<%namespace name="change_usernname_form"
file="pyramid_simpleauth:templates/change_username_form.mako" />

${change_usernname_form.body(renderer)}
