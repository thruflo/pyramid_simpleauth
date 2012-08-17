<%page args="renderer" />
<%namespace name="form" file="pyramid_simpleauth:templates/form.mako" />

${renderer.begin(request.path)}
  ${renderer.csrf_token()}
  ${form.field(renderer, 'text', 'username', label="New username")}
  ${form.field(renderer, 'hidden', 'next', label=False)}
  <div class="buttons">
    ${renderer.submit("submit", "Change username")}
  </div>
${renderer.end()}

<hr />

