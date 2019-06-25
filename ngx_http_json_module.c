#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

typedef struct {
    ngx_str_t certificate;
    ngx_str_t certificate_key;
    ngx_array_t *password;
    ngx_ssl_t *ssl;
} ngx_http_sign_loc_conf_t;

ngx_module_t ngx_http_sign_module;

static void *ngx_http_sign_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_sign_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sign_loc_conf_t));
    if (!conf) return NULL;
    conf->password = NGX_CONF_UNSET_PTR;
    return conf;
}

static ngx_int_t ngx_http_sign_set_ssl(ngx_conf_t *cf, ngx_http_sign_loc_conf_t *sign) {
    sign->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (!sign->ssl) return NGX_ERROR;
    sign->ssl->log = cf->log;
    if (ngx_ssl_create(sign->ssl, 0, NULL) != NGX_OK) return NGX_ERROR;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_ssl_cleanup_ctx(sign->ssl); return NGX_ERROR; }
    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = sign->ssl;
    if (sign->certificate.len) {
        if (sign->certificate_key.len == 0) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no \"sign_certificate_key\" is defined for certificate \"%V\"", &sign->certificate); return NGX_ERROR; }
        if (ngx_ssl_certificate(cf, sign->ssl, &sign->certificate, &sign->certificate_key, sign->password) != NGX_OK) return NGX_ERROR;
    }
    return NGX_OK;
}

static char *ngx_http_sign_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_sign_loc_conf_t *prev = parent;
    ngx_http_sign_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_ptr_value(conf->password, prev->password, NULL);
    if (ngx_http_sign_set_ssl(cf, conf) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}

static char *ngx_http_sign_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_sign_loc_conf_t *sign = conf;
    if (sign->password != NGX_CONF_UNSET_PTR) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    sign->password = ngx_ssl_read_password_file(cf, &value[1]);
    if (!sign->password) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_sign_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    ngx_http_sign_loc_conf_t *sign = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);
    if (!sign->ssl) return NGX_OK;
    X509 *signcert = SSL_CTX_get0_certificate(sign->ssl->ctx);
    if (!signcert) return NGX_OK;
    EVP_PKEY *pkey = SSL_CTX_get0_privatekey(sign->ssl->ctx);
    if (!pkey) return NGX_OK;
    ngx_http_complex_value_t *cv = (ngx_http_complex_value_t *)data;
    ngx_str_t value;
    if (ngx_http_complex_value(r, cv, &value) != NGX_OK) return NGX_OK;
    u_char *str = NULL;
    BIO *in = BIO_new_mem_buf(value.data, value.len);
    if (!in) return NGX_OK;
    PKCS7 *p7 = PKCS7_sign(signcert, pkey, NULL, in, PKCS7_BINARY|PKCS7_DETACHED);
    if (!p7) goto ret;
    int len = ASN1_item_i2d((ASN1_VALUE *)p7, &str, ASN1_ITEM_rptr(PKCS7));
    if (len <= 0) goto ret;
    ngx_str_t var = {ngx_base64_encoded_length(len), ngx_pcalloc(r->pool, ngx_base64_encoded_length(len))};
    ngx_encode_base64(&var, &((ngx_str_t){len, str}));
    v->data = var.data;
    v->len = var.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
ret:
    if (p7) PKCS7_free(p7);
    if (in) BIO_free(in);
    if (str) free(str);
    return NGX_OK;
}

static char *ngx_http_sign_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]); return NGX_CONF_ERROR; }
    value[1].len--;
    value[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) { return NGX_CONF_ERROR; }
    ngx_int_t index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) { return NGX_CONF_ERROR; }
    v->get_handler = ngx_http_sign_var;
    ngx_http_complex_value_t *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (!cv) return NGX_CONF_ERROR;
    ngx_http_compile_complex_value_t ccv = {cf, &value[2], cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    v->data = (uintptr_t)cv;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_sign_commands[] = {
  { ngx_string("sign_certificate"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_sign_loc_conf_t, certificate),
    NULL },
  { ngx_string("sign_certificate_key"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_sign_loc_conf_t, certificate_key),
    NULL },
  { ngx_string("sign_password_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_sign_ssl_password_file,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("sign_set"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_http_sign_set,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_sign_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_sign_create_loc_conf, /* create location configuration */
    ngx_http_sign_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_sign_module = {
    NGX_MODULE_V1,
    &ngx_http_sign_module_ctx, /* module context */
    ngx_http_sign_commands,    /* module directives */
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
