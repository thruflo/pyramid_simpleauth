<%page args="renderer" />
<%namespace name="form" file="pyramid_simpleauth:templates/form.mako" />

${renderer.begin(request.path)}
  ${renderer.csrf_token()}
  % if renderer.form.data['failed']:
    <div class="alert alert-error">
      Password change failed.
    </div>
  % endif
  ${form.field(renderer, 'password', 'old_password', label="Current password")}
  ${form.field(renderer, 'password', 'new_password', label="New password")}
  ${form.field(renderer, 'password', 'new_confirm', label="Confirm new password")}
  <div class="buttons">
    ${renderer.submit("submit", "Change password")}
  </div>
${renderer.end()}

<hr />

