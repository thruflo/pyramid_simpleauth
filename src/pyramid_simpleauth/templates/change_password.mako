<%inherit file="pyramid_simpleauth:templates/layout.mako" />

<%def name="subtitle()">Change password</%def>

<%namespace name="change_password_form"
file="pyramid_simpleauth:templates/change_password_form.mako" />

${change_password_form.body(renderer)}
