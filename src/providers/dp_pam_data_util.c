/*
    SSSD

    Utilities to for tha pam_data structure

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include "providers/data_provider.h"


#define PAM_SAFE_ITEM(item) item ? item : "not set"

static const char *pamcmd2str(int cmd) {
    switch (cmd) {
    case SSS_PAM_AUTHENTICATE:
        return "PAM_AUTHENTICATE";
    case SSS_PAM_SETCRED:
        return "PAM_SETCRED";
    case SSS_PAM_ACCT_MGMT:
        return "PAM_ACCT_MGMT";
    case SSS_PAM_OPEN_SESSION:
        return "PAM_OPEN_SESSION";
    case SSS_PAM_CLOSE_SESSION:
        return "PAM_CLOSE_SESSION";
    case SSS_PAM_CHAUTHTOK:
        return "PAM_CHAUTHTOK";
    case SSS_PAM_CHAUTHTOK_PRELIM:
        return "PAM_CHAUTHTOK_PRELIM";
    default:
        return "UNKNOWN";
    }
}

int pam_data_destructor(void *ptr)
{
    struct pam_data *pd = talloc_get_type(ptr, struct pam_data);
    struct multi_step_request_item *item = pd->multi_step.request_list;

    /* make sure to wipe any password from memory before freeing */
    sss_authtok_wipe_password(pd->authtok);
    sss_authtok_wipe_password(pd->newauthtok);

    while (item != NULL) {
        sss_authtok_set_empty(item->value);
        item = item->next;
    }

    return 0;
}

struct pam_data *create_pam_data(TALLOC_CTX *mem_ctx)
{
    struct pam_data *pd;

    pd = talloc_zero(mem_ctx, struct pam_data);
    if (pd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        goto failed;
    }

    pd->authtok = sss_authtok_new(pd);
    if (pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        goto failed;
    }

    pd->newauthtok = sss_authtok_new(pd);
    if (pd->newauthtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        goto failed;
    }

    talloc_set_destructor((TALLOC_CTX *) pd, pam_data_destructor);

    return pd;

failed:
    talloc_free(pd);
    return NULL;
}

errno_t copy_pam_data(TALLOC_CTX *mem_ctx, struct pam_data *src,
                      struct pam_data **dst)
{
    struct pam_data *pd = NULL;
    struct multi_step_request_item **dstitem, *srcitem;
    errno_t ret;

    pd = create_pam_data(mem_ctx);
    if (pd == NULL) {
        ret =  ENOMEM;
        goto failed;
    }

    pd->cmd  = src->cmd;
    pd->priv = src->priv;

    pd->domain = talloc_strdup(pd, src->domain);
    if (pd->domain == NULL && src->domain != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->user = talloc_strdup(pd, src->user);
    if (pd->user == NULL && src->user != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->service = talloc_strdup(pd, src->service);
    if (pd->service == NULL && src->service != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->tty = talloc_strdup(pd, src->tty);
    if (pd->tty == NULL && src->tty != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->ruser = talloc_strdup(pd, src->ruser);
    if (pd->ruser == NULL && src->ruser != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->rhost = talloc_strdup(pd, src->rhost);
    if (pd->rhost == NULL && src->rhost != NULL) {
        ret =  ENOMEM;
        goto failed;
    }

    pd->cli_pid = src->cli_pid;

    /* if structure pam_data was allocated on stack and zero initialized,
     * than src->authtok and src->newauthtok are NULL, therefore
     * instead of copying, new empty authtok will be created.
     */
    if (src->authtok) {
        ret = sss_authtok_copy(src->authtok, pd->authtok);
        if (ret) {
            goto failed;
        }
    } else {
        pd->authtok = sss_authtok_new(pd);
        if (pd->authtok == NULL) {
            ret = ENOMEM;
            goto failed;
        }
    }

    if (src->newauthtok) {
        ret = sss_authtok_copy(src->newauthtok, pd->newauthtok);
        if (ret) {
            goto failed;
        }
    } else {
        pd->newauthtok = sss_authtok_new(pd);
        if (pd->newauthtok == NULL) {
            ret = ENOMEM;
            goto failed;
        }
    }

    pd->multi_step.multi_step = src->multi_step.multi_step;
    pd->multi_step.request = src->multi_step.request;
    srcitem = src->multi_step.request_list;
    dstitem = &pd->multi_step.request_list;
    while (srcitem != NULL) {
        *dstitem = talloc_ptrtype(pd, srcitem);
        if (*dstitem == NULL) {
            ret = ENOMEM;
            goto failed;
        }
        (*dstitem)->group = srcitem->group;
        (*dstitem)->id = srcitem->id;
        (*dstitem)->value = sss_authtok_new(*dstitem);
        (*dstitem)->next = NULL;
        if ((*dstitem)->value == NULL) {
            ret = ENOMEM;
            goto failed;
        }
        ret = sss_authtok_copy(srcitem->value, (*dstitem)->value);
        if (ret != EOK) {
            goto failed;
        }
        dstitem = &((*dstitem)->next);
    }

    *dst = pd;

    return EOK;

failed:
    talloc_free(pd);
    DEBUG(1, ("copy_pam_data failed: (%d) %s.\n", ret, strerror(ret)));
    return ret;
}

void pam_print_data(int l, struct pam_data *pd)
{
    struct multi_step_request_item *item;

    DEBUG(l, ("command: %s\n", pamcmd2str(pd->cmd)));
    DEBUG(l, ("domain: %s\n", PAM_SAFE_ITEM(pd->domain)));
    DEBUG(l, ("user: %s\n", PAM_SAFE_ITEM(pd->user)));
    DEBUG(l, ("service: %s\n", PAM_SAFE_ITEM(pd->service)));
    DEBUG(l, ("tty: %s\n", PAM_SAFE_ITEM(pd->tty)));
    DEBUG(l, ("ruser: %s\n", PAM_SAFE_ITEM(pd->ruser)));
    DEBUG(l, ("rhost: %s\n", PAM_SAFE_ITEM(pd->rhost)));
    DEBUG(l, ("authtok type: %d (%s)\n",
              sss_authtok_get_type(pd->authtok),
              sss_authtok_get_type_name(pd->authtok)));
    DEBUG(l, ("newauthtok type: %d (%s)\n",
              sss_authtok_get_type(pd->newauthtok),
              sss_authtok_get_type_name(pd->newauthtok)));
    DEBUG(l, ("priv: %d\n", pd->priv));
    DEBUG(l, ("cli_pid: %d\n", pd->cli_pid));
    DEBUG(l, ("multi_step: %s\n", pd->multi_step.multi_step ? "yes" : "no"));
    if (pd->multi_step.multi_step) {
        DEBUG(l, ("client context: %d\n", pd->multi_step.client_context_id));
        switch (pd->multi_step.request) {
        case multi_step_one_shot:
            DEBUG(l, ("subrequest: one-shot\n"));
            break;
        case multi_step_start:
            DEBUG(l, ("subrequest: start\n"));
            break;
        case multi_step_continue:
            DEBUG(l, ("subrequest: continue\n"));
            break;
        case multi_step_cancel:
            DEBUG(l, ("subrequest: cancel\n"));
            break;
        default:
            break;
        }
        for (item = pd->multi_step.request_list;
             item != NULL;
             item = item->next) {
            DEBUG(l, ("authtok %d.%d: %d (%s)",
                  item->group, item->id,
                  sss_authtok_get_type(item->value),
                  sss_authtok_get_type_name(item->value)));
        }
    }
}

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, const uint8_t *data)
{
    struct response_data *new;

    new = talloc(pd, struct response_data);
    if (new == NULL) return ENOMEM;

    new->type = type;
    new->len = len;
    new->data = talloc_memdup(pd, data, len);
    if (new->data == NULL) return ENOMEM;
    new->do_not_send_to_client = false;
    new->next = pd->resp_list;
    pd->resp_list = new;

    return EOK;
}

static int pam_add_non_response(struct pam_data *pd,
                                int32_t group, int32_t id,
                                int type)
{
    unsigned char *buf, *p;
    uint32_t c;

    buf = talloc_zero_size(pd, 3 * sizeof(int32_t));
    if (buf == NULL) return ENOMEM;

    p = buf;

    memcpy(p, &group, sizeof(group));
    p += sizeof(group);

    memcpy(p, &id, sizeof(id));
    p += sizeof(id);

    c = type;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    pam_add_response(pd, SSS_PAM_ITEM_AUTH_REQUEST, p - buf, buf);

    talloc_free(buf);

    return EOK;
}

int pam_add_password_response(struct pam_data *pd,
                              int32_t group, int32_t id)
{
    return pam_add_non_response(pd, group, id,
                                SSS_PAM_PROMPT_PASSWORD);
}

int pam_add_scan_proximity_device_response(struct pam_data *pd,
                                           int32_t group, int32_t id)
{
    return pam_add_non_response(pd, group, id,
                                SSS_PAM_PROMPT_SCAN_PROXIMITY_DEVICE);
}

int pam_add_swipe_finger_response(struct pam_data *pd,
                                  int32_t group, int32_t id)
{
    return pam_add_non_response(pd, group, id,
                                SSS_PAM_PROMPT_SWIPE_FINGER);
}

int pam_add_secret_response(struct pam_data *pd,
                            int32_t group, int32_t id,
                            size_t len, const uint8_t *data)
{
    unsigned char *buf, *p;
    uint32_t c;

    buf = talloc_zero_size(pd, 4 * sizeof(int32_t) + len);
    if (buf == NULL) return ENOMEM;

    p = buf;

    memcpy(p, &group, sizeof(group));
    p += sizeof(group);

    memcpy(p, &id, sizeof(id));
    p += sizeof(id);

    c = SSS_PAM_PROMPT_SECRET;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    c = len;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    if (len > 0) {
        memcpy(p, data, len);
        p += len;
    }

    pam_add_response(pd, SSS_PAM_ITEM_AUTH_REQUEST, p - buf, buf);

    talloc_free(buf);

    return EOK;
}

int pam_add_otp_response(struct pam_data *pd,
                         int32_t group, int32_t id,
                         size_t slen, const uint8_t *service,
                         size_t vlen, const uint8_t *vendor)
{
    unsigned char *buf, *p;
    uint32_t c;

    buf = talloc_zero_size(pd, 5 * sizeof(int32_t) + slen + vlen);
    if (buf == NULL) return ENOMEM;
    p = buf;

    memcpy(p, &group, sizeof(group));
    p += sizeof(group);

    memcpy(p, &id, sizeof(id));
    p += sizeof(id);

    c = SSS_PAM_PROMPT_OTP;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    c = slen;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    if (slen > 0) {
        memcpy(p, service, slen);
        p += slen;
    }

    c = vlen;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    if (vlen > 0) {
        memcpy(p, vendor, vlen);
        p += vlen;
    }

    pam_add_response(pd, SSS_PAM_ITEM_AUTH_REQUEST, p - buf, buf);
    talloc_free(buf);

    return EOK;
}

int pam_add_smart_card_response(struct pam_data *pd,
                                int32_t group, int32_t id,
                                size_t mlen, const uint8_t *module,
                                int32_t slot_id,
                                size_t slen, const uint8_t *slot,
                                size_t tlen, const uint8_t *token)
{
    unsigned char *buf, *p;
    uint32_t c;

    buf = talloc_zero_size(pd, 7 * sizeof(int32_t) + mlen + slen + tlen);
    if (buf == NULL) return ENOMEM;
    p = buf;

    memcpy(p, &group, sizeof(group));
    p += sizeof(group);

    memcpy(p, &id, sizeof(id));
    p += sizeof(id);

    c = SSS_PAM_PROMPT_SMART_CARD_PIN;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    c = mlen;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    if (mlen > 0) {
        memcpy(p, module, mlen);
        p += mlen;
    }

    c = slot_id;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    c = slen;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    if (slen > 0) {
        memcpy(p, slot, slen);
        p += slen;
    }

    c = tlen;
    memcpy(p, &c, sizeof(c));
    p += sizeof(c);

    if (tlen > 0) {
        memcpy(p, token, tlen);
        p += tlen;
    }

    pam_add_response(pd, SSS_PAM_ITEM_AUTH_REQUEST, p - buf, buf);
    talloc_free(buf);

    return EOK;
}

int pam_add_insert_smart_card_response(struct pam_data *pd,
                                       int32_t group, int32_t id,
                                       size_t mlen, const uint8_t *module,
                                       int32_t slot_id,
                                       size_t slen, const uint8_t *slot)
{
    return pam_add_smart_card_response(pd, group, id,
                                       mlen, module,
                                       slot_id,
                                       slen, slot,
                                       0, NULL);
}
