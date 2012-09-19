<%page args="renderer" />
<%namespace name="form" file="pyramid_simpleauth:templates/form.mako" />

${renderer.begin(request.path)}
  <p>
    Are you really sure you want to delete ${user.username}? This action cannot be
    cancelled. If you delete this account, it will be completely destroyed.
  </p>
  ${renderer.csrf_token()}
  <div class="buttons">
    ${renderer.submit("submit", "Delete user %s" % user.username, class_="btn btn-danger")}
  </div>
${renderer.end()}
