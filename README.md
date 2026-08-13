## Module:

### Directives:

    Syntax:  json_loads $var value;
    Default: ——
    Context: http, server, location

Parses `value` (a complex value — may contain nginx variables) as JSON and stores it in `$var`.
`$var` becomes a special typed variable; it must not be printed directly — only `json_dumps` can read it back.
If `value` isn't valid JSON, `$var` becomes empty and the error is logged.

    Syntax:  json_dumps $var $source [key_or_index ...];
    Default: ——
    Context: http, server, location

Reads the JSON previously loaded into `$source` by `json_loads`, optionally walks into it by object
key / array index (each argument is itself a complex value, so it may contain nginx variables), and
stores the result in `$var`:

- No `key_or_index` arguments: `$var` is set to the whole value, dumped as compact JSON.
- With arguments: each one descends one level — into an object by key, into an array by numeric index.
  If the final value is a JSON string, `$var` gets the raw string (no quotes); otherwise it gets a
  compact JSON dump of that value (e.g. `null`, `42`, `{"a":1}`).
- A missing key, an out-of-range index, or `$source` not pointing at a value `json_loads` produced:
  `$var` becomes empty (not an error response) and a diagnostic is written to error_log.

Only depends on `libjansson`; no other nginx modules are required.
