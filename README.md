## Module:

### Directives:

    Syntax:	 json_load $json string;
    Default: ——
    Context: http, server, location

Loads string (may contains variables) into (json) variable $json.

    Syntax:	 json_dump $string $json [name ...];
    Default: ——
    Context: http, server, location

Dumps (json) variable $json into (string) variable $string (may point path by names).

    Syntax:	 json_var $variable { ... }
    Default: ——
    Context: http, server, location

Creates a new variable whose value is a dumped json containing the items listed within the block.
Parameters inside the `json_var` block specify a field that should be included in the resulting json.
Each parameter has to contain two arguments - key and value.
The value can contain nginx variables.

### Embedded Variables:

Module supports embedded variables:

    $json_headers

returns whole headers as dumped json

    $json_cookies

returns whole cookies as dumped json

    $json_get_vars

returns whole get variables as dumped json

    $json_post_vars

returns whole post variables as dumped json (only in case of application/x-www-form-urlencoded or application/json or multipart/form-data)
