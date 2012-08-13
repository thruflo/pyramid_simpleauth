<%def name="field(renderer, field_type, name, label=None, **kwargs)">
  <div class="control-group ${renderer.is_error(name) and 'error' or ''}">
    <div class="controls">
      % if not label is False:
        ${renderer.label(name, label=label)}
      % endif
      ${getattr(renderer, field_type)(name, **kwargs)}
      % for error_message in renderer.errors_for(name):
        <span class="help-inline">${error_message}</span>
      % endfor
    </div>
  </div>
</%def>
