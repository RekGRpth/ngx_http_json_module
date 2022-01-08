#include <jq.h>
#include <jv.h>
#include <ngx_http.h>

ngx_module_t ngx_http_json_module;

typedef struct {
    ngx_flag_t enable;
} ngx_http_json_loc_conf_t;

typedef struct {
    ngx_flag_t enable;
} ngx_http_json_main_conf_t;

typedef struct {
    ngx_flag_t done;
    ngx_flag_t waiting_more_body;
} ngx_http_json_ctx_t;

typedef struct {
    ngx_uint_t flags;
    ngx_uint_t index;
} ngx_http_json_var_flags_index_t;

typedef struct {
    ngx_http_complex_value_t cv;
    ngx_str_t command;
    ngx_str_t name;
    ngx_str_t value;
    ngx_uint_t index;
    ngx_uint_t json;
    uintptr_t escape;
} ngx_http_json_var_field_t;

typedef struct {
    ngx_array_t *fields;
    ngx_conf_t *cf;
    ngx_http_json_loc_conf_t *conf;
} ngx_http_json_var_ctx_t;

typedef struct {
    ngx_str_t key;
    ngx_array_t value;
} ngx_http_json_key_value_t;

static void ngx_http_json_jv_free(jv *root) {
    jv_free(*root);
}

enum {
    NGX_JSON_INVALID = JV_KIND_INVALID,
    NGX_JSON_NULL = JV_KIND_NULL,
    NGX_JSON_FALSE = JV_KIND_FALSE,
    NGX_JSON_TRUE = JV_KIND_TRUE,
    NGX_JSON_NUMBER = JV_KIND_NUMBER,
    NGX_JSON_STRING = JV_KIND_STRING,
    NGX_JSON_ARRAY = JV_KIND_ARRAY,
    NGX_JSON_OBJECT = JV_KIND_OBJECT,
    NGX_JSON_PARSE
};

static ngx_str_t *ngx_http_json_value(ngx_http_request_t *r, ngx_array_t *array, ngx_str_t *key) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_json_key_value_t *elts = array->elts;
    ngx_uint_t j;
    for (j = 0; j < array->nelts; j++) if (key->len == elts[j].key.len && !ngx_strncasecmp(key->data, elts[j].key.data, key->len)) { elts = &elts[j]; break; }
    if (j == array->nelts) elts = NULL;
    if (!elts) {
        if (!(elts = ngx_array_push(array))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NULL; }
        ngx_memzero(elts, sizeof(*elts));
    }
    if (!elts->value.elts && ngx_array_init(&elts->value, r->pool, 1, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NULL; }
    ngx_str_t *value = ngx_array_push(&elts->value);
    if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NULL; }
    elts->key = *key;
    return value;
}

static ngx_array_t *ngx_http_json_headers_array(ngx_http_request_t *r, ngx_list_part_t *part) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *array = ngx_array_create(r->pool, 1, sizeof(ngx_http_json_key_value_t));
    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NULL; }
    for (; part; part = part->next) {
        ngx_table_elt_t *elts = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (!elts[i].key.len) continue;
            if (!elts[i].value.len) continue;
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "elts[%i] = %V:%V", i, &elts[i].key, &elts[i].value);
            ngx_str_t *value = ngx_http_json_value(r, array, &elts[i].key);
            if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_value"); return NULL; }
            *value = elts[i].value;
        }
    }
    return array;
}

static size_t ngx_http_json_len(ngx_http_request_t *r, ngx_array_t *array) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    size_t len = 0;
    ngx_http_json_key_value_t *elts = array->elts;
    for (ngx_uint_t i = 0; i < array->nelts; i++) {
        if (i) len += sizeof(",") - 1;
        len += sizeof("\"\":") - 1 + elts[i].key.len + ngx_escape_json(NULL, elts[i].key.data, elts[i].key.len);
        ngx_str_t *value = elts[i].value.elts;
        switch (elts[i].value.nelts) {
            case 1: {
                if (!value[0].data) len += sizeof("null") - 1;
                else len += sizeof("\"\"") - 1 + value[0].len + ngx_escape_json(NULL, value[0].data, value[0].len);
            } break;
            default: {
                len += sizeof("[]") - 1;
                for (ngx_uint_t j = 0; j < elts[i].value.nelts; j++) {
                    if (j) len += sizeof(",") - 1;
                    if (!value[j].data) len += sizeof("null") - 1;
                    else len += sizeof("\"\"") - 1 + value[j].len + ngx_escape_json(NULL, value[j].data, value[j].len);
                }
            } break;
        }
    }
    len += sizeof("{}") - 1;
    return len;
}

static u_char *ngx_http_json_data(ngx_http_request_t *r, ngx_array_t *array, u_char *p) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    *p++ = '{';
    ngx_http_json_key_value_t *elts = array->elts;
    for (ngx_uint_t i = 0; i < array->nelts; i++) {
        if (i) *p++ = ',';
        *p++ = '"';
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "elts[%i].key = %V", i, &elts[i].key);
        p = (u_char *)ngx_escape_json(p, elts[i].key.data, elts[i].key.len);
        *p++ = '"'; *p++ = ':';
        ngx_str_t *value = elts[i].value.elts;
        switch (elts[i].value.nelts) {
            case 1: {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "value = %V", &value[0]);
                if (!value[0].data) p = ngx_copy(p, "null", sizeof("null") - 1); else {
                    *p++ = '"';
                    p = (u_char *)ngx_escape_json(p, value[0].data, value[0].len);
                    *p++ = '"';
                }
            } break;
            default: {
                *p++ = '[';
                for (ngx_uint_t j = 0; j < elts[i].value.nelts; j++) {
                    if (j) *p++ = ',';
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "value[%i] = %V", j, &value[j]);
                    if (!value[j].data) p = ngx_copy(p, "null", sizeof("null") - 1); else {
                        *p++ = '"';
                        p = (u_char *)ngx_escape_json(p, value[j].data, value[j].len);
                        *p++ = '"';
                    }
                }
                *p++ = ']';
            } break;
        }
    }
    *p++ = '}';
    return p;
}

static ngx_int_t ngx_http_json_response_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *array = ngx_http_json_headers_array(r, &r->headers_out.headers.part);
    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_headers_array"); return NGX_ERROR; }
    if (!r->headers_out.date) {
        ngx_str_t key = ngx_string("Date");
        ngx_str_t *value = ngx_http_json_value(r, array, &key);
        if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_value"); return NGX_ERROR; }
        *value = ngx_cached_http_time;
    }
    if (r->headers_out.content_type.len) {
        ngx_str_t key = ngx_string("Content-Type");
        ngx_str_t *value = ngx_http_json_value(r, array, &key);
        if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_value"); return NGX_ERROR; }
        *value = r->headers_out.content_type;
    }
    v->len = ngx_http_json_len(r, array);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    if (ngx_http_json_data(r, array, v->data) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_data != v->data + v->len"); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_http_json_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *array = ngx_http_json_headers_array(r, &r->headers_in.headers.part);
    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_headers_array"); return NGX_ERROR; }
    v->len = ngx_http_json_len(r, array);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    if (ngx_http_json_data(r, array, v->data) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_data != v->data + v->len"); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

/*static ngx_int_t ngx_http_json_parse(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_uint_t index = (ngx_uint_t)data;
    ngx_http_variable_value_t *vv = ngx_http_get_indexed_variable(r, index);
    if (!vv) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
    if (!vv->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!vv->data"); return NGX_ERROR; }
    if (!vv->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!vv->len"); return NGX_ERROR; }
    jv *root = ngx_palloc(r->pool, sizeof(*root));
    if (!root) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NGX_ERROR; }
    *root = jv_parse_sized((const char *)vv->data, vv->len);
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { ngx_http_json_jv_free(root); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = (ngx_pool_cleanup_pt)ngx_http_json_jv_free;
    cln->data = root;
    if (!jv_is_valid(*root)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jv_is_valid"); return NGX_ERROR; }
    v->data = (u_char *)root;
    v->len = sizeof(*root);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}*/

static ngx_array_t *ngx_http_json_cookies_array(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *array = ngx_array_create(r->pool, 1, sizeof(ngx_http_json_key_value_t));
    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NULL; }
    ngx_table_elt_t **elts = r->headers_in.cookies.elts;
    for (ngx_uint_t i = 0; i < r->headers_in.cookies.nelts; i++) {
        if (!elts[i]->value.len) continue;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "elts[%i] = %V:%V", i, &elts[i]->key, &elts[i]->value);
        for (u_char *start = elts[i]->value.data, *end = elts[i]->value.data + elts[i]->value.len; start < end; ) {
            ngx_str_t key;
            for (key.data = start; start < end && *start != '='; start++);
            key.len = start - key.data;
            start++;
            ngx_str_t *value = ngx_http_json_value(r, array, &key);
            if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_value"); return NULL; }
            for (value->data = start; start < end && *start != ';'; start++);
            value->len = start - value->data;
            start++;
        }
    }
    return array;
}

static ngx_int_t ngx_http_json_cookies(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *array = ngx_http_json_cookies_array(r);
    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_cookies_array"); return NGX_ERROR; }
    v->len = ngx_http_json_len(r, array);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    if (ngx_http_json_data(r, array, v->data) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_data != v->data + v->len"); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_array_t *ngx_http_json_get_vars_array(ngx_http_request_t *r, u_char *start, u_char *end, ngx_array_t *array) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!array && !(array = ngx_array_create(r->pool, 1, sizeof(ngx_http_json_key_value_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NULL; }
    while (start < end) {
        for (; start < end && (*start == '=' || *start == '&'); start++);
        ngx_str_t key;
        for (key.data = start; start < end && *start != '=' && *start != '&'; start++);
        key.len = start - key.data;
        u_char *src = key.data;
        u_char *dst = ngx_pnalloc(r->pool, key.len);
        if (!dst) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NULL; }
        ngx_memcpy(dst, key.data, key.len);
        key.data = dst;
        ngx_unescape_uri(&dst, &src, key.len, NGX_UNESCAPE_URI);
        key.len = dst - key.data;
        ngx_str_t *value = ngx_http_json_value(r, array, &key);
        if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_value"); return NULL; }
        ngx_str_null(value);
        if (start < end && *start++ != '&') {
            for (value->data = start; start < end && *start != '&'; start++);
            value->len = start - value->data;
            src = value->data;
            dst = ngx_pnalloc(r->pool, value->len);
            if (!dst) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NULL; }
            ngx_memcpy(dst, value->data, value->len);
            value->data = dst;
            ngx_unescape_uri(&dst, &src, value->len, NGX_UNESCAPE_URI);
            value->len = dst - value->data;
        }
    }
    return array;
}

static ngx_int_t ngx_http_json_get_vars(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *array = ngx_http_json_get_vars_array(r, r->args.data, r->args.data + r->args.len, NULL);
    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_get_vars_array"); return NGX_ERROR; }
    v->len = ngx_http_json_len(r, array);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    if (ngx_http_json_data(r, array, v->data) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_data != v->data + v->len"); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_array_t *ngx_http_json_post_vars_array(ngx_http_request_t *r, ngx_str_t *boundary, u_char *start, u_char *end, ngx_array_t *array) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!array && !(array = ngx_array_create(r->pool, 1, sizeof(ngx_http_json_key_value_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NULL; }
//    if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NULL; }
    for (u_char *val; start < end; start += 2) {
        if (ngx_strncmp(start, boundary->data + 2, boundary->len - 2)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_strncmp"); return NULL; }
        start += boundary->len - 2;
        if (ngx_strncmp(start, (u_char *)"\r\nContent-Disposition: form-data; name=\"=", sizeof("\r\nContent-Disposition: form-data; name=\"") - 1)) break;
        start += sizeof("\r\nContent-Disposition: form-data; name=\"") - 1;
        ngx_str_t key;
        if ((val = ngx_strstrn(start, "\";", sizeof("\";") - 1 - 1))) {
            key.len = val - start;
            key.data = start;
            if (!(val = ngx_strstrn(start, "\r\n\r\n", sizeof("\r\n\r\n") - 1 - 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_strstrn"); return NULL; }
            val += sizeof("\r\n\r\n") - 1;
        } else if ((val = ngx_strstrn(start, "\"\r\n\r\n", sizeof("\"\r\n\r\n") - 1 - 1))) {
            key.len = val - start;
            key.data = start;
            val += sizeof("\"\r\n\r\n") - 1;
        } else { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_strstrn"); return NULL; }
        ngx_str_t *value = ngx_http_json_value(r, array, &key);
        if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_value"); return NULL; }
        if (!(start = ngx_strstrn(val, (char *)boundary->data, boundary->len - 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_strstrn"); return NULL; }
        value->data = val;
        value->len = start - val;
    }
    return array;
}

static ngx_buf_t *ngx_http_json_read_request_body_to_buffer(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->request_body) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!r->request_body"); return NULL; }
    ngx_buf_t *buf = ngx_create_temp_buf(r->pool, r->headers_in.content_length_n + 1);
    if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NULL; }
    buf->memory = 1;
    buf->temporary = 0;
    ngx_memset(buf->start, '\0', r->headers_in.content_length_n + 1);
    for (ngx_chain_t *chain = r->request_body->bufs; chain && chain->buf; chain = chain->next) {
        off_t len = ngx_buf_size(chain->buf);
        if (len >= r->headers_in.content_length_n) {
            buf->start = buf->pos;
            buf->last = buf->pos;
            len = r->headers_in.content_length_n;
        }
        if (chain->buf->in_file) {
            ssize_t n = ngx_read_file(chain->buf->file, buf->start, len, 0);
            if (n == NGX_FILE_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_read_file == NGX_FILE_ERROR"); return NULL; }
            buf->last = buf->last + len;
            ngx_delete_file(chain->buf->file->name.data);
            chain->buf->file->fd = NGX_INVALID_FILE;
        } else {
            buf->last = ngx_copy(buf->start, chain->buf->pos, len);
        }
        buf->start = buf->last;
    }
    return buf;
}

static ngx_int_t ngx_http_json_post_vars(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (r->headers_in.content_length_n <= 0) { ngx_str_set(v, "{}"); goto ret; }
    ngx_buf_t *buf = ngx_http_json_read_request_body_to_buffer(r);
    if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_read_request_body_to_buffer"); return NGX_ERROR; }
    if (!r->headers_in.content_type) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!r->headers_in.content_type"); return NGX_ERROR; }
    if (r->headers_in.content_type->value.len == sizeof("application/x-www-form-urlencoded") - 1 && !ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/x-www-form-urlencoded", sizeof("application/x-www-form-urlencoded") - 1)) {
        ngx_array_t *array = ngx_http_json_get_vars_array(r, buf->pos, buf->last, NULL);
        if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_get_vars_array"); return NGX_ERROR; }
        v->len = ngx_http_json_len(r, array);
        if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (ngx_http_json_data(r, array, v->data) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_data != v->data + v->len"); return NGX_ERROR; }
    } else if (r->headers_in.content_type->value.len >= sizeof("application/json") - 1 && !ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/json", sizeof("application/json") - 1)) {
        v->len = ngx_buf_size(buf);
        if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (ngx_copy(v->data, buf->pos, v->len) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_copy != v->data + v->len"); return NGX_ERROR; }
    } else if (r->headers_in.content_type->value.len > sizeof("multipart/form-data") - 1 && !ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"multipart/form-data", sizeof("multipart/form-data") - 1)) {
        if (ngx_strncmp(r->headers_in.content_type->value.data, (u_char *)"multipart/form-data; boundary=", sizeof("multipart/form-data; boundary=") - 1)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_strncmp"); return NGX_ERROR; }
        size_t boundary_len = r->headers_in.content_type->value.len - (sizeof("multipart/form-data; boundary=") - 1);
        u_char *boundary_data = ngx_pnalloc(r->pool, boundary_len + 4);
        if (!boundary_data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        ngx_memcpy(boundary_data, "\r\n--", sizeof("\r\n--") - 1);
        ngx_memcpy(boundary_data + 4, r->headers_in.content_type->value.data + sizeof("multipart/form-data; boundary=") - 1, boundary_len);
        boundary_len += 4;
        ngx_str_t boundary = {boundary_len, boundary_data};
        ngx_array_t *array = ngx_http_json_post_vars_array(r, &boundary, buf->pos, buf->last, NULL);
        if (!array) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_json_post_vars_array"); return NGX_ERROR; }
        v->len = ngx_http_json_len(r, array);
        if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (ngx_http_json_data(r, array, v->data) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_data != v->data + v->len"); return NGX_ERROR; }
    } else { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unsupported content type %V", &r->headers_in.content_type->value); ngx_str_set(v, "{}"); }
ret:
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_http_variable_t ngx_http_json_variables[] = {
  { .name = ngx_string("json_response_headers"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_response_headers,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },
  /*{ .name = ngx_string("json_response_headers_parse"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_parse,
    .data = (uintptr_t)&(ngx_str_t)ngx_string("json_response_headers"),
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },*/
  { .name = ngx_string("json_headers"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_headers,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },
  /*{ .name = ngx_string("json_headers_parse"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_parse,
    .data = (uintptr_t)&(ngx_str_t)ngx_string("json_headers"),
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },*/
  { .name = ngx_string("json_cookies"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_cookies,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },
  /*{ .name = ngx_string("json_cookies_parse"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_parse,
    .data = (uintptr_t)&(ngx_str_t)ngx_string("json_cookies"),
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },*/
  { .name = ngx_string("json_get_vars"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_get_vars,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },
  /*{ .name = ngx_string("json_get_vars_parse"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_parse,
    .data = (uintptr_t)&(ngx_str_t)ngx_string("json_get_vars"),
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },*/
  { .name = ngx_string("json_post_vars"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_post_vars,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },
  /*{ .name = ngx_string("json_post_vars_parse"),
    .set_handler = NULL,
    .get_handler = ngx_http_json_parse,
    .data = (uintptr_t)&(ngx_str_t)ngx_string("json_post_vars"),
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    .index = 0 },*/
    ngx_http_null_variable
};

static ngx_int_t ngx_http_json_preconfiguration(ngx_conf_t *cf) {
    for (ngx_http_variable_t *v = ngx_http_json_variables; v->name.len; v++) {
        ngx_http_variable_t *var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!var) return NGX_ERROR;
        *var = *v;
        if (var->data) {
            ngx_str_t *name = (ngx_str_t *)var->data;
            ngx_int_t index = ngx_http_get_variable_index(cf, name);
            if (index == NGX_ERROR) return NGX_ERROR;
            var->data = (uintptr_t)index;
        }
        if (var->get_handler == ngx_http_json_post_vars) {
            ngx_http_json_main_conf_t *hjmc = ngx_http_conf_get_module_main_conf(cf, ngx_http_json_module);
            hjmc->enable = 1;
        }
    }
    return NGX_OK;
}

static void ngx_http_json_post_read(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_json_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_json_module);
    ctx->done = 1;
    r->main->count--;
    if (ctx->waiting_more_body) { ctx->waiting_more_body = 0; ngx_http_core_run_phases(r); }
}

static ngx_int_t ngx_http_json_handler(ngx_http_request_t *r) {
    ngx_http_json_loc_conf_t *hjlc = ngx_http_get_module_loc_conf(r, ngx_http_json_module);
    if (!hjlc->enable) return NGX_DECLINED;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_json_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_json_module);
    if (ctx) {
        if (ctx->done) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx->done"); return NGX_DECLINED; }
        return NGX_DONE;
    }
    if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT) return NGX_DECLINED;
    if (r->headers_in.content_type == NULL || r->headers_in.content_type->value.data == NULL) return NGX_DECLINED;
    if (!(ctx = ngx_pcalloc(r->pool, sizeof(*ctx)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_http_set_ctx(r, ctx, ngx_http_json_module);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "start to read client request body");
    ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_json_post_read);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_read_client_request_body = %i", rc); return rc; }
    if (rc == NGX_AGAIN) { ctx->waiting_more_body = 1; return NGX_DONE; }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "has read the request body in one run");
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_json_postconfiguration(ngx_conf_t *cf) {
    ngx_http_json_main_conf_t *hjmc = ngx_http_conf_get_module_main_conf(cf, ngx_http_json_module);
    if (!hjmc->enable) return NGX_OK;
    ngx_http_core_main_conf_t *core_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *handler = ngx_array_push(&core_main_conf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (!handler) return NGX_ERROR;
    *handler = ngx_http_json_handler;
    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_loc_conf->client_body_in_single_buffer = 1;
    return NGX_OK;
}

static ngx_int_t ngx_http_json_load_func(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    jv *root = ngx_palloc(r->pool, sizeof(*root));
    if (!root) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NGX_ERROR; }
    *root = jv_parse_sized((const char *)v->data, v->len);
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { ngx_http_json_jv_free(root); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = (ngx_pool_cleanup_pt)ngx_http_json_jv_free;
    cln->data = root;
    if (!jv_is_valid(*root)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jv_is_valid"); return NGX_ERROR; }
    val->data = (u_char *)root;
    val->len = sizeof(*root);
    return NGX_OK;
}

static ngx_int_t ngx_http_json_dump_func(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_json_var_flags_index_t *flags_index = data;
    ngx_http_variable_value_t *vv = ngx_http_get_indexed_variable(r, flags_index->index);
    if (!vv) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
    if (!vv->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!vv->data"); return NGX_ERROR; }
    jv *input = (jv *)vv->data;
    if (vv->len != sizeof(*input)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "vv->len != sizeof(*input)"); return NGX_ERROR; }
    u_char *str = ngx_pnalloc(r->pool, v->len + 1);
    if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    (void)ngx_cpystrn(str, v->data, v->len + 1);
    jq_state *jq = jq_init();
    if (!jq) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jq_init"); return NGX_ERROR; }
    ngx_int_t rc = NGX_ERROR;
    if (!(jq_compile(jq, (const char *)str))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jq_compile"); goto jq_teardown_jq; }
    jq_start(jq, jv_copy(*input), 0);
    jv actual = jq_next(jq);
    if (!jv_is_valid(actual)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jv_is_valid"); goto jq_teardown_jq; }
    jv string = jv_dump_string(actual, flags_index->flags);
    if (!jv_is_valid(string)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jv_is_valid"); goto jv_free_string; }
    ngx_str_t value = {jv_string_length_bytes(jv_copy(string)), (u_char *)jv_string_value(string)};
    val->data = ngx_pstrdup(r->pool, &value);
    val->len = value.len;
    rc = NGX_OK;
jv_free_string:
    jv_free(string);
jq_teardown_jq:
    jq_teardown(&jq);
    return rc;
}

static char *ngx_http_json_dump_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *args = cf->args->elts;
    if (args[2].data[0] != '$') return "invalid variable name";
    args[2].len--;
    args[2].data++;
    ngx_int_t index = ngx_http_get_variable_index(cf, &args[2]);
    if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    ngx_http_json_var_flags_index_t *flags_index = ngx_palloc(cf->pool, sizeof(*flags_index));
    if (!flags_index) return "!ngx_palloc";
    flags_index->index = (ngx_uint_t) index;
    flags_index->flags = 0;
    static const ngx_conf_bitmask_t b[] = {
        { ngx_string("ASCII"), JV_PRINT_ASCII },
        { ngx_string("COLOR"), JV_PRINT_COLOR },
        { ngx_string("COLOUR"), JV_PRINT_COLOUR },
        { ngx_string("INVALID"), JV_PRINT_INVALID },
        { ngx_string("ISATTY"), JV_PRINT_ISATTY },
        { ngx_string("PRETTY"), JV_PRINT_PRETTY },
        { ngx_string("REFCOUNT"), JV_PRINT_REFCOUNT },
        { ngx_string("SORTED"), JV_PRINT_SORTED },
        { ngx_string("SPACE0"), JV_PRINT_SPACE0 },
        { ngx_string("SPACE1"), JV_PRINT_SPACE1 },
        { ngx_string("SPACE2"), JV_PRINT_SPACE2 },
        { ngx_string("TAB"), JV_PRINT_TAB },
        { ngx_null_string, 0 }
    };
    ngx_uint_t i, j;
    for (j = 4; j < cf->args->nelts; j++) {
        for (i = 0; b[i].name.len; i++) if (b[i].name.len == args[j].len && !ngx_strncasecmp(b[i].name.data, args[j].data, b[i].name.len)) { flags_index->flags |= b[i].mask; break; }
        if (!b[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: value \"%V\" must be \"ASCII\", \"COLOR\", \"COLOUR\", \"INVALID\", \"ISATTY\", \"PRETTY\", \"REFCOUNT\", \"SORTED\", \"SPACE0\", \"SPACE1\", \"SPACE2\" or \"TAB\"", &cmd->name, &args[j]); return NGX_CONF_ERROR; }
    }
    ndk_set_var_t filter = { NDK_SET_VAR_VALUE_DATA, ngx_http_json_dump_func, 1, flags_index };
    return ndk_set_var_multi_value_core(cf, &args[1], &args[3], &filter);
}

static size_t ngx_http_json_var_len(ngx_http_request_t *r, ngx_array_t *fields) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    size_t len = 0;
    ngx_http_json_var_field_t *args = fields->elts;
    for (ngx_uint_t i = 0; i < fields->nelts; i++) {
        if (!args[i].name.len) continue;
        if (ngx_http_complex_value(r, &args[i].cv, &args[i].value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        if (!args[i].value.len) continue;
        if (len) len++;
        len += sizeof("\"\":") - 1 + args[i].name.len;
        if (args[i].json) len += args[i].value.len; else {
            args[i].escape = ngx_escape_json(NULL, args[i].value.data, args[i].value.len);
            len += sizeof("\"\"") - 1 + args[i].value.len + args[i].escape;
        }
    }
    len += sizeof("{}") - 1;
    return len;
}

static u_char *ngx_http_json_var_data(u_char *p, ngx_array_t *fields) {
    *p++ = '{';
    u_char *var = p;
    ngx_http_json_var_field_t *args = fields->elts;
    for (ngx_uint_t i = 0; i < fields->nelts; i++) {
        if (!args[i].name.len) continue;
        if (!args[i].value.len) continue;
        if (p != var) *p++ = ',';
        *p++ = '"';
        p = ngx_copy(p, args[i].name.data, args[i].name.len);
        *p++ = '"';
        *p++ = ':';
        if (args[i].json) p = ngx_copy(p, args[i].value.data, args[i].value.len); else {
            *p++ = '"';
            if (args[i].escape) p = (u_char *)ngx_escape_json(p, args[i].value.data, args[i].value.len);
            else p = ngx_copy(p, args[i].value.data, args[i].value.len);
            *p++ = '"';
        }
    }
    *p++ = '}';
    return p;
}

static ngx_int_t ngx_http_json_var_http_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *fields = (ngx_array_t *)data;
    v->len = ngx_http_json_var_len(r, fields);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))){ ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    if (ngx_http_json_var_data(v->data, fields) != v->data + v->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_var_data != v->data + v->len"); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_http_json_var_conf_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *args = cf->args->elts;
    if (cf->args->nelts != 2) return "cf->args->nelts != 2";
    ngx_http_json_var_ctx_t *ctx = cf->ctx;
    ngx_http_json_var_field_t *field = ngx_array_push(ctx->fields);
    if (!field) return "!ngx_array_push";
    field->value = args[1];
    field->json = field->value.data[0] == '$'
       && ((field->value.len - 1 == sizeof("json_response_headers") - 1 && !ngx_strncasecmp(field->value.data + 1, (u_char *)"json_response_headers", sizeof("json_response_headers") - 1))
        || (field->value.len - 1 == sizeof("json_headers") - 1 && !ngx_strncasecmp(field->value.data + 1, (u_char *)"json_headers", sizeof("json_headers") - 1))
        || (field->value.len - 1 == sizeof("json_cookies") - 1 && !ngx_strncasecmp(field->value.data + 1, (u_char *)"json_cookies", sizeof("json_cookies") - 1))
        || (field->value.len - 1 == sizeof("json_get_vars") - 1 && !ngx_strncasecmp(field->value.data + 1, (u_char *)"json_get_vars", sizeof("json_get_vars") - 1))
        || (field->value.len - 1 == sizeof("json_post_vars") - 1 && !ngx_strncasecmp(field->value.data + 1, (u_char *)"json_post_vars", sizeof("json_post_vars") - 1)));
    if (field->value.len - 1 == sizeof("json_post_vars") - 1 && !ngx_strncasecmp(field->value.data + 1, (u_char *)"json_post_vars", sizeof("json_post_vars") - 1)) ctx->conf->enable = 1;
    ngx_http_compile_complex_value_t ccv = {ctx->cf, &field->value, &field->cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    field->name = args[0];
    return NGX_CONF_OK;
}

static char *ngx_http_json_var_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *args = cf->args->elts;
    ngx_str_t name = args[1];
    if (name.data[0] != '$') return "invalid variable name";
    name.len--;
    name.data++;
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE);
    if (!var) return "!ngx_http_add_variable";
    var->get_handler = ngx_http_json_var_http_handler;
    ngx_array_t *fields = ngx_array_create(cf->pool, 1, sizeof(ngx_http_json_var_field_t));
    if (!fields) return "!ngx_array_create";
    var->data = (uintptr_t)fields;
    ngx_conf_t save = *cf;
    ngx_http_json_var_ctx_t ctx = {
        .cf = &save,
        .conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_json_module),
        .fields = fields,
    };
    cf->ctx = &ctx;
    cf->handler = ngx_http_json_var_conf_handler;
    char *rv = ngx_conf_parse(cf, NULL);
    *cf = save;
    if (rv != NGX_CONF_OK) return rv;
    return rv;
}

/*static ngx_int_t ngx_http_json_var_parse_func(ngx_http_request_t *r, ngx_str_t *val, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    jv *root = ngx_palloc(r->pool, sizeof(*root));
    if (!root) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NGX_ERROR; }
    *root = jv_object();
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { ngx_http_json_jv_free(root); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = (ngx_pool_cleanup_pt)ngx_http_json_jv_free;
    cln->data = root;
    ngx_array_t *fields = data;
    ngx_http_json_var_field_t *elts = fields->elts;
    for (ngx_uint_t i = 0; i < fields->nelts; i++) {
        jv value;
        switch (elts[i].json) {
            case NGX_JSON_TRUE: value = jv_true(); break;
            case NGX_JSON_FALSE: value = jv_false(); break;
            case NGX_JSON_NULL: value = jv_null(); break;
            case NGX_JSON_STRING: {
                if (ngx_http_complex_value(r, &elts[i].cv, &elts[i].value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
                value = jv_string_sized((const char *)elts[i].value.data, elts[i].value.len);
            } break;
            case NGX_JSON_NUMBER: {
                if (ngx_http_complex_value(r, &elts[i].cv, &elts[i].value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
                if (!elts[i].value.len) continue;
                u_char *point = ngx_strnstr(elts[i].value.data, ".", elts[i].value.len);
                ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "elts[%i].name = %V, elts[%i].value = %V", i, &elts[i].name, i, &elts[i].value);
                if (!point) {
                    ngx_int_t n = ngx_atoi(elts[i].value.data, elts[i].value.len);
                    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
                    value = jv_number((double)n);
                } else {
                    size_t p = elts[i].value.data + elts[i].value.len - point - 1;
                    ngx_int_t n = ngx_atofp(elts[i].value.data, elts[i].value.len, p);
                    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atofp == NGX_ERROR"); return NGX_ERROR; }
                    double d = n;
                    while (p--) d /= 10.0;
                    value = jv_number(d);
                }
            } break;
            case NGX_JSON_PARSE: {
                if (ngx_http_complex_value(r, &elts[i].cv, &elts[i].value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
//                if (!elts[i].value.len) continue;
                value = jv_parse_sized((const char *)elts[i].value.data, elts[i].value.len);
            } break;
            default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unknown json type %d", elts[i].json); return NGX_ERROR;
        }
        if (!jv_is_valid(value)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jv_is_valid"); return NGX_ERROR; }
        jv name = jv_string_sized((const char *)elts[i].name.data, elts[i].name.len);
        if (!jv_is_valid(name)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!jv_is_valid"); return NGX_ERROR; }
        *root = jv_object_set(*root, name, value);
    }
    val->data = (u_char *)root;
    val->len = sizeof(*root);
    return NGX_OK;
}*/

/*static char *ngx_http_json_var_parse_conf_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_json_var_ctx_t *ctx = cf->ctx;
    ngx_http_json_var_field_t *field = ngx_array_push(ctx->fields);
    if (!field) return "!ngx_array_push";
    ngx_str_t *args = cf->args->elts;
    field->name = args[0];
    field->command = args[1];
    if (field->command.len == sizeof("true") - 1 && !ngx_strncasecmp(field->command.data, (u_char *)"true", sizeof("true") - 1)) { if (cf->args->nelts != 2) return "cf->args->nelts != 2"; field->json = NGX_JSON_TRUE; return NGX_CONF_OK; }
    if (field->command.len == sizeof("false") - 1 && !ngx_strncasecmp(field->command.data, (u_char *)"false", sizeof("false") - 1)) { if (cf->args->nelts != 2) return "cf->args->nelts != 2"; field->json = NGX_JSON_FALSE; return NGX_CONF_OK; }
    if (field->command.len == sizeof("null") - 1 && !ngx_strncasecmp(field->command.data, (u_char *)"null", sizeof("null") - 1)) { if (cf->args->nelts != 2) return "cf->args->nelts != 2"; field->json = NGX_JSON_NULL; return NGX_CONF_OK; }
    if (cf->args->nelts != 3) return "cf->args->nelts != 3";
    field->value = args[2];
    ngx_http_compile_complex_value_t ccv = {ctx->cf, &field->value, &field->cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    if (field->command.len == sizeof("string") - 1 && !ngx_strncasecmp(field->command.data, (u_char *)"string", sizeof("string") - 1)) { field->json = NGX_JSON_STRING; return NGX_CONF_OK; }
    if (field->command.len == sizeof("number") - 1 && !ngx_strncasecmp(field->command.data, (u_char *)"number", sizeof("number") - 1)) { field->json = NGX_JSON_NUMBER; return NGX_CONF_OK; }
    if (field->command.len == sizeof("parse") - 1 && !ngx_strncasecmp(field->command.data, (u_char *)"parse", sizeof("parse") - 1)) { field->json = NGX_JSON_PARSE; return NGX_CONF_OK; }
    return "invalid command";
}

static char *ngx_http_json_var_parse_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_array_t *fields = ngx_array_create(cf->pool, 1, sizeof(ngx_http_json_var_field_t));
    if (!fields) return "!ngx_array_create";
    ndk_set_var_t filter = {NDK_SET_VAR_DATA, ngx_http_json_var_parse_func, 0, fields};
    ngx_str_t *args = cf->args->elts;
    char *rv = ndk_set_var_core(cf, &args[1], &filter);
    if (rv != NGX_CONF_OK) return rv;
    ngx_conf_t save = *cf;
    ngx_http_json_var_ctx_t ctx = {&save, fields};
    cf->ctx = &ctx;
    cf->handler = ngx_http_json_var_parse_conf_handler;
    rv = ngx_conf_parse(cf, NULL);
    *cf = save;
    if (rv != NGX_CONF_OK) return rv;
    if (fields->nelts <= 0) return "no fields defined";
    return rv;
}*/

static ngx_command_t ngx_http_json_commands[] = {
  { .name = ngx_string("json_dump"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
    .set = ngx_http_json_dump_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("json_load"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ndk_set_var_value,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = &(ndk_set_var_t){ NDK_SET_VAR_VALUE, ngx_http_json_load_func, 1, NULL } },
  { .name = ngx_string("json_var"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
    .set = ngx_http_json_var_conf,
    .conf = 0,
    .offset = 0,
    .post = NULL },
  /*{ .name = ngx_string("json_var_parse"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
    .set = ngx_http_json_var_parse_conf,
    .conf = 0,
    .offset = 0,
    .post = NULL },*/
    ngx_null_command
};

static void *ngx_http_json_create_main_conf(ngx_conf_t *cf) {
    ngx_http_json_main_conf_t *hjmc = ngx_pcalloc(cf->pool, sizeof(*hjmc));
    if (!hjmc) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    return hjmc;
}

static void *ngx_http_json_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_json_loc_conf_t *hjlc = ngx_pcalloc(cf->pool, sizeof(*hjlc));
    if (!hjlc) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    hjlc->enable = NGX_CONF_UNSET;
    return hjlc;
}

static char *ngx_http_json_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_json_loc_conf_t *prev = parent;
    ngx_http_json_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_json_ctx = {
    .preconfiguration = ngx_http_json_preconfiguration,
    .postconfiguration = ngx_http_json_postconfiguration,
    .create_main_conf = ngx_http_json_create_main_conf,
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
