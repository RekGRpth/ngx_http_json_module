#include <ngx_http.h>

#include <jansson.h>

ngx_module_t ngx_http_json_module;

#define NGX_HTTP_JSON_MAGIC "NGXJSON1"

typedef struct {
    u_char   magic[8];
    json_t  *json;
} ngx_http_json_box_t;

typedef struct {
    ngx_int_t     src_index;
    ngx_array_t  *keys; /* ngx_http_complex_value_t[], may be NULL */
} ngx_http_json_dumps_ctx_t;

static void ngx_http_json_cleanup(void *data) {
    json_decref((json_t *)data);
}

static ngx_int_t ngx_http_json_loads_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_complex_value_t *cv = (ngx_http_complex_value_t *)data;
    ngx_str_t text;
    if (ngx_http_complex_value(r, cv, &text) != NGX_OK) { *v = ngx_http_variable_null_value; return NGX_OK; }
    json_error_t error;
    json_t *json = json_loadb((char *)text.data, text.len, JSON_DECODE_ANY, &error);
    if (!json) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!json_loadb: %s", error.text); *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { json_decref(json); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); *v = ngx_http_variable_null_value; return NGX_OK; }
    cln->handler = ngx_http_json_cleanup;
    cln->data = json;
    ngx_http_json_box_t *box = ngx_palloc(r->pool, sizeof(ngx_http_json_box_t));
    if (!box) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_memcpy(box->magic, NGX_HTTP_JSON_MAGIC, sizeof(box->magic));
    box->json = json;
    v->data = (u_char *)box;
    v->len = sizeof(*box);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_http_json_dumps_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_json_dumps_ctx_t *ctx = (ngx_http_json_dumps_ctx_t *)data;
    ngx_http_variable_value_t *src = ngx_http_get_indexed_variable(r, ctx->src_index);
    if (!src) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); *v = ngx_http_variable_null_value; return NGX_OK; }
    if (!src->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!vv->data"); *v = ngx_http_variable_null_value; return NGX_OK; }
    if (src->len != sizeof(ngx_http_json_box_t)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "vv->len != sizeof(ngx_http_json_box_t)"); *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_http_json_box_t *box = (ngx_http_json_box_t *)src->data;
    if (ngx_memcmp(box->magic, NGX_HTTP_JSON_MAGIC, sizeof(box->magic)) != 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_box_t magic"); *v = ngx_http_variable_null_value; return NGX_OK; }
    json_t *json = box->json;
    ngx_uint_t nkeys = ctx->keys ? ctx->keys->nelts : 0;
    ngx_http_complex_value_t *keys = ctx->keys ? ctx->keys->elts : NULL;
    if (json_is_object(json) || json_is_array(json)) {
        for (ngx_uint_t i = 0; json && i < nkeys; i++) {
            ngx_str_t key;
            if (ngx_http_complex_value(r, &keys[i], &key) != NGX_OK) { *v = ngx_http_variable_null_value; return NGX_OK; }
            switch (json_typeof(json)) {
                case JSON_OBJECT: {
                    u_char *k = ngx_pnalloc(r->pool, key.len + 1);
                    if (!k) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); *v = ngx_http_variable_null_value; return NGX_OK; }
                    (void)ngx_cpystrn(k, key.data, key.len + 1);
                    json = json_object_get(json, (const char *)k);
                } break;
                case JSON_ARRAY: {
                    ngx_int_t index = ngx_atoi(key.data, key.len);
                    if (index == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi = NGX_ERROR"); *v = ngx_http_variable_null_value; return NGX_OK; }
                    json = json_array_get(json, (size_t)index);
                } break;
                default: break;
            }
        }
    }
    if (!json) { *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_flag_t dumped = !nkeys;
    const char *value = nkeys ? json_string_value(json) : json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT);
    if (nkeys && !value) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!json_string_value"); value = json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT); dumped = 1; }
    if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!json_dumps"); *v = ngx_http_variable_null_value; return NGX_OK; }
    size_t len = ngx_strlen(value);
    u_char *out;
    if (dumped) {
        out = ngx_pnalloc(r->pool, len);
        if (!out) { free((void *)value); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); *v = ngx_http_variable_null_value; return NGX_OK; }
        ngx_memcpy(out, value, len);
        free((void *)value);
    } else {
        out = (u_char *)value;
    }
    v->data = out;
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_http_json_loads_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { return "invalid variable name"; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!var) { return NGX_CONF_ERROR; }
    ngx_http_complex_value_t *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (!cv) { return NGX_CONF_ERROR; }
    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { return NGX_CONF_ERROR; }
    var->get_handler = ngx_http_json_loads_variable;
    var->data = (uintptr_t)cv;
    return NGX_CONF_OK;
}

static char *ngx_http_json_dumps_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { return "invalid variable name"; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!var) { return NGX_CONF_ERROR; }
    if (value[2].data[0] != '$') { return "invalid variable name"; }
    value[2].len--;
    value[2].data++;
    ngx_int_t src_index = ngx_http_get_variable_index(cf, &value[2]);
    if (src_index == NGX_ERROR) { return "ngx_http_get_variable_index == NGX_ERROR"; }
    ngx_http_json_dumps_ctx_t *ctx = ngx_palloc(cf->pool, sizeof(ngx_http_json_dumps_ctx_t));
    if (!ctx) { return NGX_CONF_ERROR; }
    ctx->src_index = src_index;
    ctx->keys = NULL;
    ngx_uint_t nkeys = cf->args->nelts - 3;
    if (nkeys) {
        ctx->keys = ngx_array_create(cf->pool, nkeys, sizeof(ngx_http_complex_value_t));
        if (!ctx->keys) { return NGX_CONF_ERROR; }
        for (ngx_uint_t i = 0; i < nkeys; i++) {
            ngx_http_complex_value_t *cv = ngx_array_push(ctx->keys);
            if (!cv) { return NGX_CONF_ERROR; }
            ngx_http_compile_complex_value_t ccv;
            ngx_memzero(&ccv, sizeof(ccv));
            ccv.cf = cf;
            ccv.value = &value[3 + i];
            ccv.complex_value = cv;
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { return NGX_CONF_ERROR; }
        }
    }
    var->get_handler = ngx_http_json_dumps_variable;
    var->data = (uintptr_t)ctx;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_json_commands[] = {
  { .name = ngx_string("json_dumps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
    .set = ngx_http_json_dumps_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("json_loads"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ngx_http_json_loads_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_json_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = NULL,
    .merge_loc_conf = NULL
};

ngx_module_t ngx_http_json_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_json_ctx,
    .commands = ngx_http_json_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
