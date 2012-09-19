<%inherit file="pyramid_simpleauth:templates/layout.mako" />
<%def name="subtitle()">Confirm delete account</%def>
<%namespace name="delete_user_form"
            file="pyramid_simpleauth:templates/delete_user_form.mako" />

${delete_user_form.body(renderer)}
