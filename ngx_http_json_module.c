#include <jansson.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_json_module;

static char *ngx_str_t_to_char(ngx_pool_t *pool, ngx_str_t s) {
    char *c = ngx_pcalloc(pool, (s.len + 1) * sizeof(char));
    if (!c) return NULL;
    ngx_memcpy(c, s.data, s.len);
    return c;
}

static ngx_str_t char_to_ngx_str_t(ngx_pool_t *pool, char *c) {
    size_t len = ngx_strlen(c);
    ngx_str_t s = {len, ngx_pnalloc(pool, len * sizeof(char))};
    if (s.data) ngx_memcpy(s.data, c, len); else s.len = 0;
    return s;
}

static ngx_int_t ngx_http_json_loads(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    ngx_http_complex_value_t *cv = (ngx_http_complex_value_t *)data;
    ngx_str_t value;
    if (ngx_http_complex_value(r, cv, &value) != NGX_OK) return NGX_OK;
    char *buf = ngx_str_t_to_char(r->pool, value);
    if (!buf) return NGX_OK;
    json_t *json = json_loads(buf, 0, NULL);
    if (!json) return NGX_OK;
    v->data = (u_char *)json;
    v->len = sizeof(json_t);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_conf_json_loads(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]); return NGX_CONF_ERROR; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) return NGX_CONF_ERROR;
    v->get_handler = ngx_http_json_loads;
    ngx_http_complex_value_t *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (!cv) return NGX_CONF_ERROR;
    ngx_http_compile_complex_value_t ccv = {cf, &value[2], cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    v->data = (uintptr_t)cv;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_json_dumps(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    ngx_array_t *args = (ngx_array_t *)data;
    ngx_str_t *name = args->elts;
    return NGX_OK;
}

static char *ngx_conf_json_dumps(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[2].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[2]); return NGX_CONF_ERROR; }
    value[2].len--;
    value[2].data++;
    ngx_int_t index = ngx_http_get_variable_index(cf, &value[2]);
    if (index == NGX_ERROR) return NGX_CONF_ERROR;
    if (value[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]); return NGX_CONF_ERROR; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) return NGX_CONF_ERROR;
    v->get_handler = ngx_http_json_dumps;
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
    ngx_conf_json_loads,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("json_dumps"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
    ngx_conf_json_dumps,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_json_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_json_module = {
    NGX_MODULE_V1,
    &ngx_http_json_module_ctx, /* module context */
    ngx_http_json_commands,    /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING
};