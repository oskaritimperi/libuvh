#ifndef UVH_H
#define UVH_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <uv.h>

#define UVH_MAX_HEADERS 50

#define HTTP_STATUS_CODE_MAP(XX) \
    XX(100, CONTINUE, "Continue") \
    XX(101, SWITCHING_PROTOCOLS, "Switching Protocols") \
    XX(200, OK, "OK") \
    XX(201, CREATED, "Created") \
    XX(202, ACCEPTED, "Accepted") \
    XX(203, NON_AUTHORITATIVE_INFORMATION, "Non-Authoritative Information") \
    XX(204, NO_CONTENT, "No Content") \
    XX(205, RESET_CONTENT, "Reset Content") \
    XX(206, PARTIAL_CONTENT, "Partial Content") \
    XX(300, MULTIPLE_CHOICES, "Multiple Choices") \
    XX(301, MOVED_PERMANENTLY, "Moved Permanently") \
    XX(302, FOUND, "Found") \
    XX(303, SEE_OTHER, "See Other") \
    XX(304, NOT_MODIFIED, "Not Modified") \
    XX(305, USE_PROXY, "Use Proxy") \
    XX(307, TEMPORARY_REDIRECT, "Temporary Redirect") \
    XX(400, BAD_REQUEST, "Bad Request") \
    XX(401, UNAUTHORIZED, "Unauthorized") \
    XX(402, PAYMENT_REQUIRED, "Payment Required") \
    XX(403, FORBIDDEN, "Forbidden") \
    XX(404, NOT_FOUND, "Not Found") \
    XX(405, METHOD_NOT_ALLOWED, "Method Not Allowed") \
    XX(406, NOT_ACCEPTABLE, "Not Acceptable") \
    XX(407, PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required") \
    XX(408, REQUEST_TIMEOUT, "Request Timeout") \
    XX(409, CONFLICT, "Conflict") \
    XX(410, GONE, "Gone") \
    XX(411, LENGTH_REQUIRED, "Length Required") \
    XX(412, PRECONDITION_FAILED, "Precondition Failed") \
    XX(413, REQUEST_ENTITY_TOO_LARGE, "Request Entity Too Large") \
    XX(414, REQUEST_URI_TOO_LONG, "Request-URI Too Long") \
    XX(415, UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type") \
    XX(416, REQUESTED_RANGE_NOT_SATISFIABLE, "Requested Range Not Satisfiable") \
    XX(417, EXPECTATION_FAILED, "Expectation Failed") \
    XX(418, IM_A_TEAPOT, "I'm a teapot") /* ;-) */ \
    XX(500, INTERNAL_SERVER_ERROR, "Internal Server Error") \
    XX(501, NOT_IMPLEMENTED, "Not Implemented") \
    XX(502, BAD_GATEWAY, "Bad Gateway") \
    XX(503, SERVICE_UNAVAILABLE, "Service Unavailable") \
    XX(504, GATEWAY_TIMEOUT, "Gateway Timeout") \
    XX(505, HTTP_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported")

enum
{
#define XX(CODE, NAME, STR) HTTP_##NAME = CODE,
    HTTP_STATUS_CODE_MAP(XX)
#undef XX
};

struct uvh_request;

typedef int (*uvh_request_handler_cb)(struct uvh_request *);

struct uvh_server
{
    void *data;
    uvh_request_handler_cb request_handler;
};

struct uvh_request
{
    struct uvh_server *server;

    struct
    {
        const char *name;
        const char *value;
    } headers[UVH_MAX_HEADERS];

    int header_count;

    const char *method;
    const char *version;

    struct
    {
        const char *full;
        const char *schema;
        const char *host;
        const char *port;
        const char *path;
        const char *query;
        const char *fragment;
        const char *userinfo;
    } url;

    const char *content;
    int content_length;
};

struct uvh_server *uvh_server_init(uv_loop_t *loop, void *data,
    uvh_request_handler_cb request_handler);

int uvh_server_listen(struct uvh_server *server, const char *address,
    short port);

void uvh_request_write(struct uvh_request *req, const char *data,
    size_t len);

#ifdef __GNUC__
void uvh_request_writef(struct uvh_request *req, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
#else
void uvh_request_writef(struct uvh_request *req, const char *fmt, ...);
#endif

void uvh_request_write_status(struct uvh_request *req, int status);

void uvh_request_write_header(struct uvh_request *req,
    const char *name, const char *value);

const char *http_status_code_str(int code);

const char *uvh_request_get_header(struct uvh_request *req,
    const char *name);

#endif /* UVH_H */
