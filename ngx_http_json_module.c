#include <jansson.h>
#include <ndk.h>
#include <ngx_http.h>

ngx_module_t ngx_http_json_module;

typedef struct {
    ngx_uint_t index;
    ngx_uint_t nelts;
} ngx_http_json_index_nelts_t;

static ngx_int_t ngx_http_json_loads_func(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    json_error_t error;
    json_t *json = json_loadb((char *)v->data, v->len, JSON_DECODE_ANY, &error);
    if (!json) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!json_loadb: %s", error.text); return NGX_ERROR; }
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { json_decref(json); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = (ngx_pool_cleanup_pt)json_decref;
    cln->data = json;
    val->data = (u_char *)json;
    val->len = sizeof(*json);
    return NGX_OK;
}

static ngx_int_t ngx_http_json_dumps_func(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_json_index_nelts_t *index_nelts = data;
    ngx_http_variable_value_t *vv = ngx_http_get_indexed_variable(r, index_nelts->index);
    if (!vv) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
    if (!vv->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!vv->data"); return NGX_ERROR; }
    if (vv->len != sizeof(json_t)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "vv->len != sizeof(json_t)"); return NGX_ERROR; }
    json_t *json = (json_t *)vv->data;
    if (json_is_object(json) || json_is_array(json)) {
        for (ngx_uint_t i = 0; json && i < index_nelts->nelts; i++) switch (json_typeof(json)) {
            case JSON_OBJECT: {
                u_char *key = ngx_pnalloc(r->pool, v[i].len + 1);
                if (!key) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                (void)ngx_cpystrn(key, v[i].data, v[i].len + 1);
                json = json_object_get(json, (const char *)key);
            } break;
            case JSON_ARRAY: {
                ngx_int_t index = ngx_atoi(v[i].data, v[i].len);
                if (index == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi = NGX_ERROR"); return NGX_ERROR; }
                json = json_array_get(json, (size_t)index);
            } break;
            default: break;
        }
    }
    const char *value = index_nelts->nelts ? json_string_value(json) : json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT);
    if (index_nelts->nelts && !value) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!json_string_value"); value = json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT); }
    if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!json_dumps"); return NGX_ERROR; }
    val->data = (u_char *)value;
    val->len = ngx_strlen(value);
    return NGX_OK;
}

static char *ngx_http_json_dumps_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[2].data[0] != '$') return "invalid variable name";
    elts[2].len--;
    elts[2].data++;
    ngx_int_t index = ngx_http_get_variable_index(cf, &elts[2]);
    if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    ngx_http_json_index_nelts_t *index_nelts = ngx_palloc(cf->pool, sizeof(*index_nelts));
    if (!index_nelts) return "!ngx_palloc";
    index_nelts->index = (ngx_uint_t) index;
    index_nelts->nelts = cf->args->nelts - 3;
    ndk_set_var_t filter = { NDK_SET_VAR_MULTI_VALUE_DATA, ngx_http_json_dumps_func, index_nelts->nelts, index_nelts };
    return ndk_set_var_multi_value_core(cf, &elts[1], &elts[3], &filter);
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
    .set = ndk_set_var_value,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = &(ndk_set_var_t){ NDK_SET_VAR_VALUE, ngx_http_json_loads_func, 1, NULL } },
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
