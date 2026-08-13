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


=== TEST 4: json_dumps on a variable never produced by json_loads fails cleanly instead of dereferencing it as a pointer
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


=== TEST 5: json_dumps rejects a source variable of the wrong length outright
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
