<%inherit file="pyramid_simpleauth:templates/layout.mako" />

<%def name="subtitle()">Confirm email address</%def>

<p>
% if success:
    Your email address has been successfully confirmed.
% else:
    This confirmation link is invalid.
% endif
</p>
