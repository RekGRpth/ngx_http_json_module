## Module:

### Directives:

    Syntax:  json_loads $var value;
    Default: ——
    Context: http, server, location

Parses `value` (a complex value — may contain nginx variables) as JSON and stores it in `$var`.
Printing `$var` gives the source JSON text; the parsed JSON behind it is only reachable through
`json_dumps`. A copy of `$var` (e.g. `set $copy $var`) is plain text and isn't accepted by `json_dumps`.
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
- A missing key, an out-of-range index, or a key / index applied to a scalar (string, number, `true`,
  `false`, `null`): `$var` becomes empty, nothing is logged.
- An array index that isn't a non-negative integer, or `$source` not holding a value `json_loads`
  produced: `$var` becomes empty and the error is logged.

None of these cases produce an error response.

### Scope:

Like other nginx variables, `$var` names are global, but each `json_loads` / `json_dumps` definition
applies only to the block it's in and the blocks nested inside it: a location inherits the definitions
from its server and http blocks and may redefine the same name. A name used in a location with no
definition for it there is empty. Defining the same name twice in one block is a configuration error
(`duplicate json variable`).

Values are computed on first use and cached for the rest of the request, including after internal
redirects (`error_page`, `rewrite ... last`): a later change to the variables in `value` or keys, or a
different definition in the location redirected to, doesn't affect an already computed value.

Only depends on `libjansson`; no other nginx modules are required.
