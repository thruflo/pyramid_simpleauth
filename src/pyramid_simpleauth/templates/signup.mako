<%inherit file="pyramid_simpleauth:templates/layout.mako" />
<%namespace name="form" file="pyramid_simpleauth:templates/form.mako" />

<%def name="subtitle()">Signup</%def>

${renderer.begin(request.path)}
  ${renderer.csrf_token()}
  % if renderer.form.data['failed']:
    <div class="alert alert-error">
      Authentication failed.
    </div>
  % endif
  ${form.field(renderer, 'text', 'username')}
  ${form.field(renderer, 'text', 'email')}
  ${form.field(renderer, 'password', 'password')}
  ${form.field(renderer, 'password', 'confirm')}
  <div class="buttons">
    ${renderer.submit("submit", "Signup")}
  </div>
${renderer.end()}

<hr />
<p>
  Already have an account?
  <a href="${request.route_url('simpleauth', traverse=('login',))}">
    Login here</a>.
</p>
