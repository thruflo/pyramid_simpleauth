<%inherit file="pyramid_simpleauth:templates/layout.mako" />
<%namespace name="form" file="pyramid_simpleauth:templates/form.mako" />

<%def name="subtitle()">Login</%def>

${renderer.begin(request.resource_url(request.root, 'login'))}
  ${renderer.csrf_token()}
  ${renderer.hidden("next")}
  % if renderer.form.data['failed']:
    <div class="alert alert-error">
      Login failed.
    </div>
  % endif
  ${form.field(renderer, 'text', 'username')}
  ${form.field(renderer, 'password', 'password')}
  <div class="buttons">
    ${renderer.submit("submit", "Login")}
  </div>
${renderer.end()}

<hr />
<p>
  Don't have an account yet?
  <a href="${request.resource_url(request.context, 'signup')}">
    Sign up now</a>.
</p>
