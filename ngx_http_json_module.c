#include <jansson.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_json_module;

static u_char *ngx_http_json_headers_set(ngx_http_request_t *r, u_char *p, size_t *size) {
    char first = 1;
    if (p) *p++ = '{';
    ngx_list_part_t *part = &r->headers_in.headers.part;
    do {
        ngx_table_elt_t *header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (!p) *size += (sizeof("\"\":\"\",") - 1) + header[i].key.len + header[i].value.len + ngx_escape_json(NULL, header[i].value.data, header[i].value.len); else {
                if (!first) *p++ = ',';
                *p++ = '"';
                p = ngx_copy(p, header[i].key.data, header[i].key.len);
                *p++ = '"'; *p++ = ':'; *p++ = '"';
                p = (u_char *)ngx_escape_json(p, header[i].value.data, header[i].value.len);
                *p++ = '"';
                first = 0;
            }
        }
        part = part->next;
    } while (part);
    if (p) *p++ = '}';
    else p = ngx_palloc(r->pool, *size);
    return p;
}

static ngx_int_t ngx_http_json_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    size_t size = sizeof("{}") - 1 - 1;
    u_char *p = ngx_http_json_headers_set(r, NULL, &size);
    if (!p) goto err;
    v->data = p;
    p = ngx_http_json_headers_set(r, p, NULL);
    v->len = p - v->data;
    if (v->len > size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_var_headers: result length %l exceeded allocated length %l", v->len, size); goto err; }
    return NGX_OK;
err:
    ngx_str_set(v, "null");
    return NGX_OK;
}

static ngx_http_variable_t ngx_http_json_variables[] = {
  { ngx_string("json_headers1"),
    NULL,
    ngx_http_json_headers,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
/*  { ngx_string("json_cookies1"),
    NULL,
    ngx_http_json_cookies,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
  { ngx_string("json_get_vars1"),
    NULL,
    ngx_http_json_get_vars,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
  { ngx_string("json_post_vars1"),
    NULL,
    ngx_http_json_post_vars,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },*/
  { ngx_null_string,
    NULL,
    NULL,
    0,
    0,
    0 }
};

static ngx_int_t ngx_http_json_add_variables(ngx_conf_t *cf) {
    for (ngx_http_variable_t *v = ngx_http_json_variables; v->name.len; v++) {
        ngx_http_variable_t *var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!var) return NGX_ERROR;
        *var = *v;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_json_loads_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    ngx_http_complex_value_t *cv = (ngx_http_complex_value_t *)data;
    ngx_str_t value;
    if (ngx_http_complex_value(r, cv, &value) != NGX_OK) return NGX_OK;
    json_t *json = json_loadb((char *)value.data, value.len, 0, NULL);
    if (!json) return NGX_OK;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { json_decref(json); return NGX_OK; }
    cln->handler = (ngx_pool_cleanup_pt)json_decref;
    cln->data = json;
    v->data = (u_char *)json;
    v->len = sizeof(json_t);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_http_json_loads_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]); return NGX_CONF_ERROR; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) return NGX_CONF_ERROR;
    v->get_handler = ngx_http_json_loads_handler;
    ngx_http_complex_value_t *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (!cv) return NGX_CONF_ERROR;
    ngx_http_compile_complex_value_t ccv = {cf, &value[2], cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    v->data = (uintptr_t)cv;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_json_dumps_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    ngx_array_t *args = (ngx_array_t *)data;
    ngx_str_t *name = args->elts;
    ngx_http_variable_value_t *var = ngx_http_get_variable(r, name, ngx_hash_key(name->data, name->len));
    if (!var || !var->data || var->len != sizeof(json_t)) return NGX_OK;
    json_t *json = (json_t *)var->data;
    for (ngx_uint_t i = 1; json && (i < args->nelts); i++) {
        char key[name[i].len + 1];
        ngx_memcpy(key, name[i].data, name[i].len);
        key[name[i].len] = '\0';
        json = json_object_get(json, key);
    }
    const char *value = json_string_value(json);
    if (!value) value = json_dumps(json, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
    if (!value) return NGX_OK;
    v->data = (u_char *)value;
    v->len = ngx_strlen(value);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_http_json_dumps_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[2].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[2]); return NGX_CONF_ERROR; }
    value[2].len--;
    value[2].data++;
    if (value[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]); return NGX_CONF_ERROR; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) return NGX_CONF_ERROR;
    v->get_handler = ngx_http_json_dumps_handler;
    ngx_array_t *args = ngx_array_create(cf->pool, cf->args->nelts - 2, sizeof(ngx_str_t));
    if (!args) return NGX_CONF_ERROR;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        ngx_str_t *s = ngx_array_push(args);
        if (!s) return NGX_CONF_ERROR;
        *s = value[i];
    }
    v->data = (uintptr_t)args;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_json_commands[] = {
  { ngx_string("json_loads"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_http_json_loads_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("json_dumps"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
    ngx_http_json_dumps_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_json_module_ctx = {
    ngx_http_json_add_variables, /* preconfiguration */
    NULL,                        /* postconfiguration */

    NULL,                        /* create main configuration */
    NULL,                        /* init main configuration */

    NULL,                        /* create server configuration */
    NULL,                        /* merge server configuration */

    NULL,                        /* create location configuration */
    NULL                         /* merge location configuration */
};

ngx_module_t ngx_http_json_module = {
    NGX_MODULE_V1,
    &ngx_http_json_module_ctx,   /* module context */
    ngx_http_json_commands,      /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};
