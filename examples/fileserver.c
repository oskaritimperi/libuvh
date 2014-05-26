#include <uvh.h>
#include <stdlib.h>
#include "../src/sds.h"

#include <fcntl.h>

#define MAX_CHUNK 1024

struct fileserver
{
    sds root;
};

struct chunker
{
    uv_fs_t open_req;
    uv_fs_t read_req;
    struct fileserver *fileserver;
    struct uvh_request *req;
    sds real_path;
    sds req_path;
    char buffer[MAX_CHUNK];
};

struct dirreq
{
    uv_fs_t readdir_req;
    struct fileserver *fileserver;
    struct uvh_request *req;
    sds real_path;
    sds req_path;
};

sds path_join(sds a, sds b)
{
    sds result;

    if (b[0] == '/')
        return sdsdup(b);

    result = sdsdup(a);

    if (result[sdslen(result)-1] != '/')
        result = sdscatlen(result, "/", 1);

    return sdscatsds(result, b);
}

void on_readdir(uv_fs_t *req)
{
    struct dirreq *dirreq = (struct dirreq *) req->data;
    char *buf = (char *) req->ptr;
    int i = 0;

    uvh_request_writef(dirreq->req, "<html><body><h2>%s</h2><ul>",
        dirreq->req_path);

    for (i = 0; i < req->result; ++i)
    {
        sds filename = sdsnew(buf);
        sds path = path_join(dirreq->req_path, filename);

        uvh_request_writef(dirreq->req, "<li><a href=\"%s\">%s</a></li>",
            path, filename);

        sdsfree(filename);
        sdsfree(path);

        buf += strlen(buf) + 1;
    }

    uvh_request_writef(dirreq->req, "%s", "</ul></body></html>");

    uvh_request_end(dirreq->req);

    uv_fs_req_cleanup(req);

    sdsfree(dirreq->real_path);
    sdsfree(dirreq->req_path);
    free(dirreq);
}

void handle_dir(struct uvh_request *req, sds req_path, sds real_path)
{
    struct dirreq *dirreq = calloc(1, sizeof(*dirreq));

    dirreq->fileserver = (struct fileserver *) req->server->data;
    dirreq->req = req;
    dirreq->readdir_req.data = dirreq;
    dirreq->real_path = real_path;
    dirreq->req_path = req_path;

    uv_fs_readdir(uv_default_loop(), &dirreq->readdir_req, real_path, O_RDONLY,
        &on_readdir);
}

void on_read(uv_fs_t *req)
{
    struct chunker *chunker = (struct chunker *) req->data;

    uv_fs_req_cleanup(req);

    printf("on_read: result: %d\n", (int)req->result);

    if (req->result > 0)
    {
        uvh_request_write(chunker->req, chunker->buffer, req->result);

        uv_fs_read(req->loop, &chunker->read_req, chunker->open_req.result,
            chunker->buffer, MAX_CHUNK, -1, &on_read);

        return;
    }

    // error or eof

    uv_fs_t close_req;
    uv_fs_close(req->loop, &close_req, chunker->open_req.result, NULL);

    uvh_request_write(chunker->req, NULL, 0);

    sdsfree(chunker->req_path);
    sdsfree(chunker->real_path);
    free(chunker);
}

void on_open(uv_fs_t *req)
{
    struct chunker *chunker = (struct chunker *) req->data;

    if (req->result == -1)
    {
        fprintf(stderr, "error opening: %s\n", chunker->real_path);
        uvh_request_write_status(chunker->req, HTTP_INTERNAL_SERVER_ERROR);
        uvh_request_end(chunker->req);
        sdsfree(chunker->req_path);
        sdsfree(chunker->real_path);
        free(chunker);
    }
    else
    {
        // Pass NULL as callback, so we can write chunks when we want to.
        // The request is done when an empty chunk is written.
        uvh_request_stream(chunker->req, NULL, NULL);

        uv_fs_read(req->loop, &chunker->read_req, req->result, chunker->buffer,
            MAX_CHUNK, -1, &on_read);
    }

    uv_fs_req_cleanup(req);
}

void handle_file(struct uvh_request *req, sds req_path, sds real_path)
{
    struct chunker *chunker = calloc(1, sizeof(*chunker));
    chunker->open_req.data = chunker;
    chunker->read_req.data = chunker;
    chunker->real_path = real_path;
    chunker->req_path = req_path;
    chunker->req = req;
    chunker->fileserver = (struct fileserver *) req->server->data;

    uv_fs_open(uv_default_loop(), &chunker->open_req, chunker->real_path,
        O_RDONLY, 0, &on_open);
}

int request_handler(struct uvh_request *req)
{
    printf("%s\n", __FUNCTION__);

    struct fileserver *fileserver;
    sds real_path;
    sds req_path;

    fileserver = (struct fileserver *) req->server->data;

    req_path = sdsnew(req->url.path);
    sds req_path2 = sdsnew(req_path+1);
    real_path = path_join(fileserver->root, req_path2);
    sdsfree(req_path2);

    printf("req path: %s\n", req_path);
    printf("stat: <%s>\n", real_path);

    uv_fs_t stat_req;
    uv_fs_stat(uv_default_loop(), &stat_req, real_path, NULL);

    if (S_ISDIR(stat_req.statbuf.st_mode))
    {
        handle_dir(req, req_path, real_path);
    }
    else if (S_ISREG(stat_req.statbuf.st_mode))
    {
        handle_file(req, req_path, real_path);
    }
    else
    {
        sdsfree(real_path);
        sdsfree(req_path);
        uvh_request_write_status(req, HTTP_NOT_FOUND);
        uvh_request_end(req);
    }

    uv_fs_req_cleanup(&stat_req);

    return 0;
}

void ctrlc_handler(uv_signal_t *handle, int signum)
{
    struct uvh_server *server = handle->data;
    uvh_server_stop(server);
    uv_close((uv_handle_t *) handle, NULL);
    (void) signum;
}

int main(int argc, char **argv)
{
    uv_signal_t sig;
    struct fileserver fileserver;
    struct uvh_server *server;

    if (argc != 2)
    {
        printf("usage: %s document-root\n", argv[0]);
        return 1;
    }

    memset(&fileserver, 0, sizeof(fileserver));

    fileserver.root = sdsnew(argv[1]);

    server = uvh_server_init(uv_default_loop(), &fileserver, &request_handler);

    if (!server)
        goto error;

    if (uvh_server_listen(server, "127.0.0.1", 9898))
        goto error;

    uv_signal_init(uv_default_loop(), &sig);
    sig.data = server;
    uv_signal_start(&sig, &ctrlc_handler, SIGINT);

    printf("root: %s\n", fileserver.root);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    printf("done\n");

    uvh_server_free(server);
    sdsfree(fileserver.root);

    return 0;

error:

    fprintf(stderr, "error: %s\n",
        uv_strerror(uv_last_error(uv_default_loop())));

    return 1;
}
