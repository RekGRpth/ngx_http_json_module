## Module:

### Directives:

    Syntax:	 json_loads $json string;
    Default: ——
    Context: http, server, location

Loads string (may contains variables) into (json) variable $json.

    Syntax:	 json_dumps $string $json [name ...];
    Default: ——
    Context: http, server, location

Dumps (json) variable $json into (string) variable $string (may point path by names).
