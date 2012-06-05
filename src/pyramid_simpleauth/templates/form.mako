<%def name="field(renderer, field_type, name, **kwargs)">
  <div class="control-group ${renderer.is_error(name) and 'error' or ''}">
    <label>
      ${renderer.label(name)}
    </label>
    <div class="controls">
      ${getattr(renderer, field_type)(name, **kwargs)}
      % for error_message in renderer.errors_for(name):
        <span class="help-inline">${error_message}</span>
      % endfor
    </div>
  </div>
</%def>
