#include <ngx_http.h>

#include <jansson.h>

ngx_module_t ngx_http_json_module;

/* a parsed json_loads value, kept in its request pool cleanup so that it survives internal redirects (which reset r->ctx) */
typedef struct {
    json_t      *json;
    ngx_uint_t   index;
    u_char      *data;
    size_t       len;
} ngx_http_json_value_t;

typedef struct {
    ngx_http_complex_value_t  cv;
    ngx_uint_t                index;
} ngx_http_json_loads_ctx_t;

typedef struct {
    ngx_int_t     src_index;
    ngx_str_t     src_name;
    ngx_array_t  *keys; /* ngx_http_complex_value_t[], may be NULL */
} ngx_http_json_dumps_ctx_t;

typedef struct {
    ngx_uint_t                index;
    ngx_http_get_variable_pt  handler;
    uintptr_t                 data;
} ngx_http_json_var_t;

typedef struct {
    ngx_array_t  *vars; /* ngx_http_json_var_t[], may be NULL */
} ngx_http_json_loc_conf_t;

static void ngx_http_json_cleanup(void *data) {
    ngx_http_json_value_t *jv = data;
    json_decref(jv->json);
}

static ngx_int_t ngx_http_json_loads_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_json_loads_ctx_t *ctx = (ngx_http_json_loads_ctx_t *)data;
    ngx_str_t text;
    if (ngx_http_complex_value(r, &ctx->cv, &text) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_complex_value"); *v = ngx_http_variable_null_value; return NGX_OK; }
    json_error_t error;
    json_t *json = json_loadb((char *)text.data, text.len, JSON_DECODE_ANY, &error);
    if (!json) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!json_loadb: %s", error.text); *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_json_value_t));
    if (!cln) { json_decref(json); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_http_json_value_t *jv = cln->data;
    jv->json = json;
    jv->index = ctx->index;
    jv->data = text.data;
    jv->len = text.len;
    cln->handler = ngx_http_json_cleanup;
    v->data = text.data;
    v->len = text.len;
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
    json_t *json = NULL;
    for (ngx_pool_cleanup_t *cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler != ngx_http_json_cleanup) continue;
        ngx_http_json_value_t *jv = cln->data;
        if (jv->index == (ngx_uint_t)ctx->src_index && jv->data == src->data && jv->len == src->len) { json = jv->json; break; }
    }
    if (!json) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"$%V\" is not a json_loads value", &ctx->src_name); *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_uint_t nkeys = ctx->keys ? ctx->keys->nelts : 0;
    ngx_http_complex_value_t *keys = ctx->keys ? ctx->keys->elts : NULL;
    for (ngx_uint_t i = 0; json && i < nkeys; i++) {
        ngx_str_t key;
        if (ngx_http_complex_value(r, &keys[i], &key) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_complex_value"); *v = ngx_http_variable_null_value; return NGX_OK; }
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
            default: json = NULL; break;
        }
    }
    if (!json) { *v = ngx_http_variable_null_value; return NGX_OK; }
    ngx_flag_t dumped = !nkeys;
    const char *value = nkeys ? json_string_value(json) : json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT);
    if (nkeys && !value) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "!json_string_value"); value = json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT); dumped = 1; }
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

static ngx_int_t ngx_http_json_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_json_loc_conf_t *jlcf = ngx_http_get_module_loc_conf(r, ngx_http_json_module);
    if (jlcf->vars) {
        ngx_http_json_var_t *var = jlcf->vars->elts;
        for (ngx_uint_t i = 0; i < jlcf->vars->nelts; i++) if (var[i].index == data) return var[i].handler(r, v, var[i].data);
    }
    v->not_found = 1;
    return NGX_OK;
}

static char *ngx_http_json_add_variable(ngx_conf_t *cf, ngx_http_json_loc_conf_t *jlcf, ngx_str_t *name, ngx_http_get_variable_pt handler, uintptr_t data) {
    ngx_http_variable_t *var = ngx_http_add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE);
    if (!var) { return NGX_CONF_ERROR; }
    ngx_int_t index = ngx_http_get_variable_index(cf, name);
    if (index == NGX_ERROR) { return NGX_CONF_ERROR; }
    if (!jlcf->vars && !(jlcf->vars = ngx_array_create(cf->pool, 4, sizeof(ngx_http_json_var_t)))) { return NGX_CONF_ERROR; }
    ngx_http_json_var_t *jv = jlcf->vars->elts;
    for (ngx_uint_t i = 0; i < jlcf->vars->nelts; i++) if (jv[i].index == (ngx_uint_t)index) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate json variable \"$%V\"", name); return NGX_CONF_ERROR; }
    if (!(jv = ngx_array_push(jlcf->vars))) { return NGX_CONF_ERROR; }
    jv->index = index;
    jv->handler = handler;
    jv->data = data;
    var->get_handler = ngx_http_json_variable;
    var->data = index;
    return NGX_CONF_OK;
}

static char *ngx_http_json_loads_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { return "invalid variable name"; }
    value[1].len--;
    value[1].data++;
    ngx_http_json_loads_ctx_t *ctx = ngx_palloc(cf->pool, sizeof(ngx_http_json_loads_ctx_t));
    if (!ctx) { return NGX_CONF_ERROR; }
    ngx_int_t index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) { return NGX_CONF_ERROR; }
    ctx->index = index;
    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &ctx->cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { return NGX_CONF_ERROR; }
    return ngx_http_json_add_variable(cf, conf, &value[1], ngx_http_json_loads_variable, (uintptr_t)ctx);
}

static char *ngx_http_json_dumps_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { return "invalid variable name"; }
    value[1].len--;
    value[1].data++;
    if (value[2].data[0] != '$') { return "invalid variable name"; }
    value[2].len--;
    value[2].data++;
    ngx_int_t src_index = ngx_http_get_variable_index(cf, &value[2]);
    if (src_index == NGX_ERROR) { return NGX_CONF_ERROR; }
    ngx_http_json_dumps_ctx_t *ctx = ngx_palloc(cf->pool, sizeof(ngx_http_json_dumps_ctx_t));
    if (!ctx) { return NGX_CONF_ERROR; }
    ctx->src_index = src_index;
    ctx->src_name = value[2];
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
    return ngx_http_json_add_variable(cf, conf, &value[1], ngx_http_json_dumps_variable, (uintptr_t)ctx);
}

static void *ngx_http_json_create_loc_conf(ngx_conf_t *cf) {
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_json_loc_conf_t));
}

static char *ngx_http_json_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_json_loc_conf_t *prev = parent;
    ngx_http_json_loc_conf_t *conf = child;
    if (!prev->vars) { return NGX_CONF_OK; }
    if (!conf->vars) { conf->vars = prev->vars; return NGX_CONF_OK; }
    ngx_http_json_var_t *pv = prev->vars->elts;
    for (ngx_uint_t i = 0; i < prev->vars->nelts; i++) {
        ngx_http_json_var_t *cv = conf->vars->elts;
        ngx_uint_t j;
        for (j = 0; j < conf->vars->nelts; j++) if (cv[j].index == pv[i].index) break;
        if (j < conf->vars->nelts) continue;
        ngx_http_json_var_t *jv = ngx_array_push(conf->vars);
        if (!jv) { return NGX_CONF_ERROR; }
        *jv = pv[i];
    }
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
    .create_loc_conf = ngx_http_json_create_loc_conf,
    .merge_loc_conf = ngx_http_json_merge_loc_conf
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
