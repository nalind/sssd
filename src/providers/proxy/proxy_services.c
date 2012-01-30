/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "providers/proxy/proxy.h"
#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb_services.h"

#define BUFLEN  1024

errno_t
proxy_save_service(struct sysdb_ctx *sysdb,
                   struct servent *svc,
                   bool lowercase,
                   uint64_t cache_timeout)
{
    errno_t ret;
    char *cased_name;
    const char **protocols;
    const char **cased_aliases;
    TALLOC_CTX *tmp_ctx;
    size_t num_aliases, i;
    time_t now = time(NULL);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    cased_name = sss_get_cased_name(tmp_ctx, svc->s_name, !lowercase);
    if (!cased_name) {
        ret = ENOMEM;
        goto done;
    }

    protocols = talloc_array(tmp_ctx, const char *, 2);
    if (!protocols) {
        ret = ENOMEM;
        goto done;
    }

    protocols[0] = sss_get_cased_name(protocols, svc->s_proto,
                                      !lowercase);
    if (!protocols[0]) {
        ret = ENOMEM;
        goto done;
    }
    protocols[1] = NULL;

    /* Count the aliases */
    for(num_aliases = 0; svc->s_aliases[num_aliases]; num_aliases++);

    if (num_aliases >= 1) {
        cased_aliases = talloc_array(tmp_ctx, const char *, num_aliases + 1);
        if (!cased_aliases) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < num_aliases; i++) {
            cased_aliases[i] = sss_get_cased_name(tmp_ctx, svc->s_aliases[i],
                                                  !lowercase);
            if (!cased_aliases[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
        cased_aliases[num_aliases] = NULL;
    } else {
        cased_aliases = NULL;
    }

    ret = sysdb_store_service(sysdb,
                              cased_name,
                              ntohs(svc->s_port),
                              cased_aliases,
                              protocols,
                              NULL, NULL,
                              cache_timeout,
                              now);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_serv_byname(struct proxy_id_ctx *ctx,
                struct sysdb_ctx *sysdb,
                struct sss_domain_info *dom,
                const char *name,
                const char *protocol)
{
    errno_t ret;
    enum nss_status status;
    struct servent *result;
    TALLOC_CTX *tmp_ctx;
    char buffer[BUFLEN];

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    result = talloc_zero(tmp_ctx, struct servent);
    if (!result) {
        ret = ENOMEM;
        goto done;
    }

    status = ctx->ops.getservbyname_r(name, protocol, result,
                                      buffer, BUFLEN, &ret);
    if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_NOTFOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("getservbyname_r failed for service [%s].\n", name));
        return ret;
    }

    if (status == NSS_STATUS_NOTFOUND) {
        /* Make sure we remove it from the cache */
        ret = sysdb_svc_delete(sysdb, name, 0, protocol);
    } else {

        /* Results found. Save them into the cache */
        ret = proxy_save_service(sysdb, result,
                                 !dom->case_sensitive,
                                 ctx->entry_cache_timeout);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_serv_byport(struct proxy_id_ctx *ctx,
                struct sysdb_ctx *sysdb,
                struct sss_domain_info *dom,
                const char *be_filter,
                const char *protocol)
{
    errno_t ret;
    enum nss_status status;
    struct servent *result;
    TALLOC_CTX *tmp_ctx;
    uint16_t port;
    char buffer[BUFLEN];

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    result = talloc_zero(tmp_ctx, struct servent);
    if (!result) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    port = htons(strtouint16(be_filter, NULL, 0));
    if (errno) {
        ret = errno;
        goto done;
    }

    status = ctx->ops.getservbyport_r(port, protocol, result,
                                      buffer, BUFLEN, &ret);
    if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_NOTFOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("getservbyport_r failed for service [%s].\n", be_filter));
        return ret;
    }

    if (status == NSS_STATUS_NOTFOUND) {
        /* Make sure we remove it from the cache */
        ret = sysdb_svc_delete(sysdb, NULL, port, protocol);
    } else {
        /* Results found. Save them into the cache */
        ret = proxy_save_service(sysdb, result,
                                 !dom->case_sensitive,
                                 ctx->entry_cache_timeout);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
get_const_aliases(TALLOC_CTX *mem_ctx,
                  char **aliases,
                  const char ***const_aliases)
{
    errno_t ret;
    size_t i, num_aliases;
    const char **alias_list = NULL;

    for (num_aliases = 0; aliases[num_aliases]; num_aliases++);

    alias_list = talloc_zero_array(mem_ctx, const char *, num_aliases + 1);
    if (!alias_list) return ENOMEM;

    for (i = 0; aliases[i]; i++) {
        alias_list[i] = talloc_strdup(alias_list, aliases[i]);
        if (!alias_list[i]) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
    *const_aliases = alias_list;

done:
    if (ret != EOK) {
        talloc_zfree(alias_list);
    }
    return ret;
}

errno_t
enum_services(struct proxy_id_ctx *ctx,
              struct sysdb_ctx *sysdb,
              struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct servent *svc;
    enum nss_status status;
    size_t buflen;
    char *buffer;
    char *newbuf;
    errno_t ret, sret;
    time_t now = time(NULL);
    const char *protocols[2] = { NULL, NULL };

    DEBUG(SSSDBG_TRACE_FUNC, ("Enumerating services\n"));

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    svc = talloc(tmpctx, struct servent);
    if (!svc) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setservent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

again:
    /* always zero out the svc structure */
    memset(svc, 0, sizeof(struct servent));

    /* get entry */
    status = ctx->ops.getservent_r(svc, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto done;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(SSSDBG_TRACE_FUNC, ("Enumeration completed.\n"));

        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) goto done;

        in_transaction = false;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("Service found (%s, %d/%s)\n",
               svc->s_name, svc->s_port, svc->s_proto));

        protocols[0] = svc->s_proto;

        const char **const_aliases;
        ret = get_const_aliases(tmpctx, svc->s_aliases, &const_aliases);
        if (ret != EOK) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to store service [%s]. Ignoring.\n",
                   strerror(ret)));
            goto again; /* next */
        }

        ret = sysdb_store_service(sysdb,
                                  svc->s_name,
                                  svc->s_port,
                                  const_aliases,
                                  protocols,
                                  NULL, NULL,
                                  ctx->entry_cache_timeout,
                                  now);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to store service [%s]. Ignoring.\n",
                   strerror(ret)));
        }
        goto again; /* next */

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        ret = EIO;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("proxy -> getservent_r failed (%d)[%s]\n",
               ret, strerror(ret)));
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not cancel transaction! [%s]\n",
                   strerror(sret)));
        }
    }
    ctx->ops.endservent();
    return ret;
}