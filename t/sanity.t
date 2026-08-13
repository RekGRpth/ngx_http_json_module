# vi:ft=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: json_loads + json_dumps round-trips a whole JSON object
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"a":1,"b":[1,2,3],"c":{"d":"e"}}';
        json_loads $token_json $token;
        json_dumps $out $token_json;
        return 200 $out;
    }
--- request
GET /echo
--- response_body chomp
{"a":1,"b":[1,2,3],"c":{"d":"e"}}


=== TEST 2: json_dumps extracts a string value by object key
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"name":"alice","age":30}';
        json_loads $token_json $token;
        json_dumps $out $token_json name;
        return 200 $out;
    }
--- request
GET /echo
--- response_body chomp
alice


=== TEST 3: json_dumps extracts a value by array index
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"items":["x","y","z"]}';
        json_loads $token_json $token;
        json_dumps $out $token_json items 1;
        return 200 $out;
    }
--- request
GET /echo
--- response_body chomp
y


=== TEST 4: json_dumps on a missing object key yields an empty value instead of a 500
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"a":1}';
        json_loads $token_json $token;
        json_dumps $missing $token_json b;
        return 200 "[$missing]";
    }
--- request
GET /echo
--- response_body chomp
[]


=== TEST 5: json_dumps on an out-of-range array index yields an empty value instead of a 500
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"items":["x"]}';
        json_loads $token_json $token;
        json_dumps $missing $token_json items 5;
        return 200 "[$missing]";
    }
--- request
GET /echo
--- response_body chomp
[]


=== TEST 6: json_dumps on a key whose value is JSON null still dumps the literal null
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"a":null}';
        json_loads $token_json $token;
        json_dumps $out $token_json a;
        return 200 $out;
    }
--- request
GET /echo
--- response_body chomp
null


=== TEST 7: json_dumps on a variable never produced by json_loads fails cleanly instead of dereferencing it as a pointer
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $fake "1234567890123456";
        json_dumps $out $fake;
        return 200 ok;
    }
--- request
GET /echo
--- error_code: 500
--- error_log
!ngx_http_json_box_t magic


=== TEST 8: json_dumps rejects a source variable of the wrong length outright
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $short "abc";
        json_dumps $out $short;
        return 200 ok;
    }
--- request
GET /echo
--- error_code: 500
--- error_log
vv->len != sizeof(ngx_http_json_box_t)


=== TEST 9: json_loads on invalid JSON fails cleanly
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token 'not valid json';
        json_loads $token_json $token;
        return 200 ok;
    }
--- request
GET /echo
--- error_code: 500
--- error_log
!json_loadb


=== TEST 10: json_dumps rejects a non-numeric array index
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"items":["x","y","z"]}';
        json_loads $token_json $token;
        json_dumps $out $token_json items foo;
        return 200 ok;
    }
--- request
GET /echo
--- error_code: 500
--- error_log
ngx_atoi = NGX_ERROR


=== TEST 11: json_dumps silently ignores extra path segments once the value is no longer a container
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        set $token '{"a":"b"}';
        json_loads $token_json $token;
        json_dumps $out $token_json a extra;
        return 200 $out;
    }
--- request
GET /echo
--- response_body chomp
b


=== TEST 12: json_dumps on a source variable that was never computed fails cleanly
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        json_dumps $out $http_x_definitely_missing;
        return 200 ok;
    }
--- request
GET /echo
--- error_code: 500
--- error_log
!vv->data


=== TEST 13: json_dumps rejects a source variable name without a leading dollar sign
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ndk_http_module.so;
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_json_module.so;
--- config
    location /echo {
        json_dumps $out token;
        return 200 ok;
    }
--- request
GET /echo
--- must_die
--- error_log
invalid variable name
