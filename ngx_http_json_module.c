#include <jansson.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_json_module;

typedef struct {
    ngx_str_t name;
    ngx_http_complex_value_t cv;
    ngx_str_t value;
    uintptr_t escape;
} ngx_http_json_var_field_t;

typedef struct {
    ngx_conf_t *cf;
    ngx_array_t *fields; // of ngx_http_json_var_field_t
} ngx_http_json_var_ctx_t;

static ngx_int_t ngx_http_json_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    size_t size = sizeof("{}") - 1;
    ngx_list_part_t *part = &r->headers_in.headers.part;
    for (ngx_table_elt_t *header = part->elts; part; part = part->next) for (ngx_uint_t i = 0; i < part->nelts; i++) size += (sizeof("\"\":\"\",") - 1) + header[i].key.len + header[i].value.len + ngx_escape_json(NULL, header[i].value.data, header[i].value.len); 
    u_char *p = ngx_palloc(r->pool, size);
    if (!p) goto err;
    v->data = p;
    *p++ = '{';
    part = &r->headers_in.headers.part;
    for (ngx_table_elt_t *header = part->elts; part; part = part->next) for (ngx_uint_t i = 0; i < part->nelts; i++) {
        if (p != v->data + 1) *p++ = ',';
        *p++ = '"';
        p = ngx_copy(p, header[i].key.data, header[i].key.len);
        *p++ = '"'; *p++ = ':'; *p++ = '"';
        p = (u_char *)ngx_escape_json(p, header[i].value.data, header[i].value.len);
        *p++ = '"';
    }
    *p++ = '}';
    v->len = p - v->data;
    if (v->len > size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_headers: result length %l exceeded allocated length %l", v->len, size); goto err; }
    return NGX_OK;
err:
    ngx_str_set(v, "null");
    return NGX_OK;
}

static size_t ngx_http_json_cookies_size(u_char *start, u_char *end) {
    size_t size;
    for (size = 0; start < end; start++, size++) {
        while (start < end && *start == ' ') start++;
        if (*start == '\\' || *start == '"') size++;
        else if (*start == ';') size += sizeof("\"\":\"\",") - 1;
    }
    return size;
}

static u_char *ngx_http_json_cookies_data(u_char *p, u_char *start, u_char *end, u_char *cookies) {
    while (start < end) {
        while (start < end && *start == ' ') start++;
        if (p != cookies) *p++ = ',';
        *p++ = '"';
        for (; start < end && *start != '='; *p++ = *start++) if (*start == '\\' || *start == '"') *p++ = '\\';
        start++; *p++ = '"'; *p++ = ':'; *p++ = '"';
        for (; start < end && *start != ';'; *p++ = *start++) if (*start == '\\' || *start == '"') *p++ = '\\'; 
        start++; *p++ = '"';
    }
    return p;
}

static ngx_int_t ngx_http_json_cookies(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    size_t size = sizeof("{}\"\":\"\"") - 1;
    ngx_table_elt_t **h = r->headers_in.cookies.elts;
    for (ngx_uint_t i = 0; i < r->headers_in.cookies.nelts; i++) size += ngx_http_json_cookies_size(h[i]->value.data, h[i]->value.data + h[i]->value.len);
    u_char *p = ngx_palloc(r->pool, size);
    if (!p) goto err;
    v->data = p;
    *p++ = '{';
    for (ngx_uint_t i = 0; i < r->headers_in.cookies.nelts; i++) p = ngx_http_json_cookies_data(p, h[i]->value.data, h[i]->value.data + h[i]->value.len, v->data + 1);
    *p++ = '}';
    v->len = p - v->data;
    if (v->len > size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_cookies: result length %l exceeded allocated length %l", v->len, size); goto err; }
    return NGX_OK;
err:
    ngx_str_set(v, "null");
    return NGX_OK;
}

static size_t ngx_http_json_vars_size(u_char *start, u_char *end) {
    size_t size;
    for (size = sizeof("{}\"\":\"\"") - 1; start < end; start++, size++) {
        if (*start == '\\' || *start == '"') size++;
        else if (*start == '&') size += sizeof("\"\":\"\",") - 1;
    }
    return size + 2;
}

#define unescape_characters { \
    switch (*start) { \
        case '%': { \
            start++; \
            c = *start++; \
            if (c >= 0x30) c -= 0x30; \
            if (c >= 0x10) c -= 0x07; \
            *p = (c << 4); \
            c = *start++; \
            if (c >= 0x30) c -= 0x30; \
            if (c >= 0x10) c -= 0x07; \
            *p += c; \
            c = *p; \
        } break; \
        case '+': { c = ' '; start++; } break; \
        default: c = *start++; \
    } \
    if (c == '\\' || c == '"') *p++ = '\\'; \
    *p++ = c; \
}
static u_char *ngx_http_json_vars_data(u_char *p, u_char *start, u_char *end, u_char *args) {
    for (u_char c; start < end; ) {
        if (p != args) *p++ = ',';
        *p++ = '"';
        while (start < end && (*start == '=' || *start == '&')) start++;
        while (start < end && *start != '=' && *start != '&') unescape_characters
        *p++ = '"'; *p++ = ':';
        if (start < end && *start++ != '&') {
            *p++ = '"';
            while (start < end && *start != '&') unescape_characters
            *p++ = '"';
        } else {
            *p++ = 'n'; *p++ = 'u'; *p++ = 'l'; *p++ = 'l';
        }
    }
    return p;
}

static ngx_int_t ngx_http_json_get_vars(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    size_t size = ngx_http_json_vars_size(r->args.data, r->args.data + r->args.len);
    u_char *p = ngx_palloc(r->pool, size);
    if (!p) goto err;
    v->data = p;
    *p++ = '{';
    p = ngx_http_json_vars_data(p, r->args.data, r->args.data + r->args.len, v->data + 1);
    *p++ = '}';
    v->len = p - v->data;
    if (v->len > size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_get_vars: result length %l exceeded allocated length %l", v->len, size); goto err; }
    return NGX_OK;
err:
    ngx_str_set(v, "null");
    return NGX_OK;
}

static u_char *ngx_http_json_post_vars_data(u_char *p, ngx_pool_t *pool, u_char *content_type, u_char *echo_request_body, u_char *body) {
    u_char *mime_type_end_ptr = (u_char *)ngx_strchr(content_type, ';');
    if (!mime_type_end_ptr) return NULL;
    u_char *boundary_start_ptr = ngx_strstrn(mime_type_end_ptr, "boundary=", sizeof("boundary=") - 1 - 1);
    if (!boundary_start_ptr) return NULL;
    boundary_start_ptr += sizeof("boundary=") - 1;
    u_char *boundary_end_ptr = boundary_start_ptr + strcspn((char *)boundary_start_ptr, " ;\n\r");
    if (boundary_end_ptr == boundary_start_ptr) return NULL;
    ngx_str_t boundary = {boundary_end_ptr - boundary_start_ptr + 4, ngx_palloc(pool, boundary_end_ptr - boundary_start_ptr + 4 + 1)};
    if (!boundary.data) return NULL;
    (void) ngx_cpystrn(boundary.data + 4, boundary_start_ptr, boundary_end_ptr - boundary_start_ptr + 1);
    boundary.data[0] = '\r'; boundary.data[1] = '\n'; boundary.data[2] = '-'; boundary.data[3] = '-'; boundary.data[boundary.len] = '\0';
    for (
        u_char *s = echo_request_body, *name_start_ptr;
        (name_start_ptr = ngx_strstrn(s, "\r\nContent-Disposition: form-data; name=\"", sizeof("\r\nContent-Disposition: form-data; name=\"") - 1 - 1)) != NULL;
        s += boundary.len
    ) {
        name_start_ptr += sizeof("\r\nContent-Disposition: form-data; name=\"") - 1;
        u_char *name_end_ptr = ngx_strstrn(name_start_ptr, "\"\r\n\r\n", sizeof("\"\r\n\r\n") - 1 - 1);
        if (!name_end_ptr) return NULL;
        if (p != body) *p++ = ',';
        *p++ = '"';
        p = (u_char*)ngx_escape_json(p, name_start_ptr, name_end_ptr - name_start_ptr);
        *p++ = '"'; *p++ = ':';
        u_char *value_start_ptr = name_end_ptr + sizeof("\"\r\n\r\n") - 1;
        u_char *value_end_ptr = ngx_strstrn(value_start_ptr, (char *)boundary.data, boundary.len - 1);
        if (!value_end_ptr) return NULL;
        *p++ = '"';
        p = (u_char*)ngx_escape_json(p, value_start_ptr, value_end_ptr - value_start_ptr);
        *p++ = '"';
    }
    return p;
}

static ngx_int_t ngx_http_json_post_vars(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    ngx_str_t echo_request_body_var = ngx_string("echo_request_body");
    ngx_http_variable_value_t *echo_request_body = ngx_http_get_variable(r, &echo_request_body_var, ngx_hash_key(echo_request_body_var.data, echo_request_body_var.len));
    if (echo_request_body->data && r->headers_in.content_type) {
        if (ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/x-www-form-urlencoded", sizeof("application/x-www-form-urlencoded") - 1) == 0) {
            size_t size = ngx_http_json_vars_size(echo_request_body->data, echo_request_body->data + echo_request_body->len);
            u_char *p = ngx_palloc(r->pool, size);
            if (!p) goto err;
            v->data = p;
            *p++ = '{';
            p = ngx_http_json_vars_data(p, echo_request_body->data, echo_request_body->data + echo_request_body->len, v->data + 1);
            *p++ = '}';
            v->len = p - v->data;
            if (v->len > size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_post_vars: result length %l exceeded allocated length %l", v->len, size); goto err; }
        } else if (ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/json", sizeof("application/json") - 1) == 0) {
            u_char *p = ngx_palloc(r->pool, echo_request_body->len);
            if (!p) goto err;
            v->data = p;
            p = ngx_copy(p, echo_request_body->data, echo_request_body->len);
            v->len = p - v->data;
            if (v->len > echo_request_body->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_post_vars: result length %l exceeded allocated length %l", v->len, echo_request_body->len); goto err; }
        } else if (ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"multipart/form-data", sizeof("multipart/form-data") - 1) == 0) {
            u_char *p = ngx_palloc(r->pool, echo_request_body->len);
            if (!p) goto err;
            v->data = p;
            *p++ = '{';
            p = ngx_http_json_post_vars_data(p, r->pool, r->headers_in.content_type->value.data, echo_request_body->data, v->data + 1);
            if (!p) goto err;
            *p++ = '}';
            v->len = p - v->data;
            if (v->len > echo_request_body->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_post_vars: result length %l exceeded allocated length %l", v->len, echo_request_body->len); goto err; }
        } else goto err;
    } else goto err;
    return NGX_OK;
err:
    ngx_str_set(v, "null");
    return NGX_OK;
}

static ngx_http_variable_t ngx_http_json_variables[] = {
  { ngx_string("json_headers"),
    NULL,
    ngx_http_json_headers,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
  { ngx_string("json_cookies"),
    NULL,
    ngx_http_json_cookies,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
  { ngx_string("json_get_vars"),
    NULL,
    ngx_http_json_get_vars,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
  { ngx_string("json_post_vars"),
    NULL,
    ngx_http_json_post_vars,
    0,
    NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
    0 },
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
    json_error_t error;
    json_t *json = json_loadb((char *)value.data, value.len, JSON_DECODE_ANY, &error);
    if (!json) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "json decode error: %s", error.text); return NGX_OK; }
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
    if (!value) value = json_dumps(json, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_COMPACT);
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

static ngx_int_t ngx_http_json_var_http_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_array_t *ctx = (ngx_array_t *)data;
    ngx_http_json_var_field_t *fields = ctx->elts;
    size_t size = sizeof("{}");
    for (ngx_uint_t i = 0; i < ctx->nelts; i++) {
        if (ngx_http_complex_value(r, &fields[i].cv, &fields[i].value) != NGX_OK) return NGX_ERROR;
        fields[i].escape = ngx_escape_json(NULL, fields[i].value.data, fields[i].value.len);
        size += sizeof("\"\":\"\",") + fields[i].name.len + fields[i].value.len + fields[i].escape;
    }
    u_char *p = ngx_palloc(r->pool, size);
    if (!p) return NGX_ERROR;
    v->data = p;
    *p++ = '{';
    for (ngx_uint_t i = 0; i < ctx->nelts; i++) {
        if (i > 0) *p++ = ',';
        *p++ = '"';
        p = ngx_copy(p, fields[i].name.data, fields[i].name.len);
        *p++ = '"';
        *p++ = ':';
        if ((ngx_strncasecmp(fields[i].name.data, (u_char *)"json_headers", sizeof("json_headers") - 1) == 0)
         || (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_cookies", sizeof("json_cookies") - 1) == 0)
         || (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_get_vars", sizeof("json_get_vars") - 1) == 0)
         || (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_post_vars", sizeof("json_post_vars") - 1) == 0)
        ) p = ngx_copy(p, fields[i].value.data, fields[i].value.len); else {
            *p++ = '"';
            if (fields[i].escape) p = (u_char *)ngx_escape_json(p, fields[i].value.data, fields[i].value.len);
            else p = ngx_copy(p, fields[i].value.data, fields[i].value.len);
            *p++ = '"';
        }
    }
    *p++ = '}';
    *p = '\0';
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - v->data;
    if (v->len >= size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_json_var_variable: result length %uD exceeded allocated length %uz", (uint32_t)v->len, size); return NGX_ERROR; }
    return NGX_OK;
}

static char *ngx_http_json_var_conf_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_json_var_ctx_t *ctx = cf->ctx;
    ngx_http_json_var_field_t *item = ngx_array_push(ctx->fields);
    if (!item) return NGX_CONF_ERROR;
    ngx_str_t *value = cf->args->elts;
    ngx_http_compile_complex_value_t ccv = {ctx->cf, &value[1], &item->cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    item->name = value[0];
    return NGX_CONF_OK;
}

static char *ngx_http_json_var_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    ngx_str_t name = value[1];
    if (name.data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &name); return NGX_CONF_ERROR; }
    name.len--;
    name.data++;
    ngx_array_t *fields = ngx_array_create(cf->pool, 4, sizeof(ngx_http_json_var_field_t));
    if (!fields) return NGX_CONF_ERROR;
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE);
    if (!var) return NGX_CONF_ERROR;
    var->get_handler = ngx_http_json_var_http_handler;
    var->data = (uintptr_t)fields;
    ngx_conf_t save = *cf;
    ngx_http_json_var_ctx_t ctx = {&save, fields};
    cf->ctx = &ctx;
    cf->handler = ngx_http_json_var_conf_handler;
    char *rv = ngx_conf_parse(cf, NULL);
    *cf = save;
    if (rv != NGX_CONF_OK) return rv;
    if (fields->nelts <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no fields defined in \"json_var\" block"); return NGX_CONF_ERROR; }
    return rv;
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
  { ngx_string("json_var"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
    ngx_http_json_var_conf,
    0,
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
