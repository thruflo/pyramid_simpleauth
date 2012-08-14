<%inherit file="pyramid_simpleauth:templates/layout.mako" />
<%namespace name="form" file="pyramid_simpleauth:templates/form.mako" />

<%def name="subtitle()">Change password</%def>

${renderer.begin(request.path)}
  ${renderer.csrf_token()}
  % if renderer.form.data['failed']:
    <div class="alert alert-error">
      Password change failed.
    </div>
  % endif
  ${form.field(renderer, 'password', 'old_password')}
  ${form.field(renderer, 'password', 'new_password')}
  ${form.field(renderer, 'password', 'new_confirm')}
  <div class="buttons">
    ${renderer.submit("submit", "Change password")}
  </div>
${renderer.end()}

<hr />
