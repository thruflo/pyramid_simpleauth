<%def name="field(renderer, field_type, name, label=None, **kwargs)">
  <div class="control-group ${name}-control ${renderer.is_error(name) and 'error' or ''}">
    <div class="controls">
      % if not label is False:
        ${renderer.label(name, label=label)}
      % endif
      ${getattr(renderer, field_type)(name, **kwargs)}
      <span class="help help-inline">
        % for error_message in renderer.errors_for(name):
          ${error_message}
        % endfor
      </span>
    </div>
  </div>
</%def>
