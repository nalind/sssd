/*
   SSSD

   Data Provider, auth utils

   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include <stdarg.h>
#include "data_provider.h"

bool dp_pack_pam_request(DBusMessage *msg, struct pam_data *pd)
{
    dbus_bool_t db_ret;
    const char *service;
    const char *tty;
    const char *ruser;
    const char *rhost;
    uint32_t authtok_type;
    uint32_t authtok_length;
    uint8_t *authtok_data;
    uint32_t new_authtok_type;
    uint32_t new_authtok_length;
    uint8_t *new_authtok_data;
    dbus_bool_t multi_step;
    uint32_t multi_step_request;
    struct multi_step_request_item *multi_step_item;
    uint32_t multi_step_item_type;
    uint32_t multi_step_item_length;
    uint8_t *multi_step_item_data;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;

    if (pd->user == NULL) return false;
    service = pd->service ? pd->service : "";
    tty = pd->tty ? pd->tty : "";
    ruser = pd->ruser ? pd->ruser : "";
    rhost = pd->rhost ? pd->rhost : "";
    authtok_type = (uint32_t)sss_authtok_get_type(pd->authtok);
    authtok_data = sss_authtok_get_data(pd->authtok);
    authtok_length = sss_authtok_get_size(pd->authtok);
    new_authtok_type = (uint32_t)sss_authtok_get_type(pd->newauthtok);
    new_authtok_data = sss_authtok_get_data(pd->newauthtok);
    new_authtok_length = sss_authtok_get_size(pd->newauthtok);
    multi_step = pd->multi_step.multi_step;
    multi_step_request = pd->multi_step.request;
    multi_step_item = pd->multi_step.request_list;

    db_ret = dbus_message_append_args(msg,
                                      DBUS_TYPE_INT32,  &(pd->cmd),
                                      DBUS_TYPE_STRING, &(pd->user),
                                      DBUS_TYPE_STRING, &(pd->domain),
                                      DBUS_TYPE_STRING, &service,
                                      DBUS_TYPE_STRING, &tty,
                                      DBUS_TYPE_STRING, &ruser,
                                      DBUS_TYPE_STRING, &rhost,
                                      DBUS_TYPE_UINT32, &authtok_type,
                                      DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                      &authtok_data, authtok_length,
                                      DBUS_TYPE_UINT32, &new_authtok_type,
                                      DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                      &new_authtok_data, new_authtok_length,
                                      DBUS_TYPE_INT32, &(pd->priv),
                                      DBUS_TYPE_UINT32, &(pd->cli_pid),
                                      DBUS_TYPE_BOOLEAN, &(multi_step),
                                      DBUS_TYPE_UINT32, &(multi_step_request),
                                      DBUS_TYPE_INT32,
                                      &(pd->multi_step.client_context_id),
                                      DBUS_TYPE_INVALID);
    if (!db_ret) {
        DEBUG(1, ("dbus_message_append_args failed.\n"));
        return false;
    }

    dbus_message_iter_init_append(msg, &iter);

    db_ret = dbus_message_iter_open_container(&iter,
                                              DBUS_TYPE_ARRAY,
                                              DBUS_STRUCT_BEGIN_CHAR_AS_STRING
                                              DBUS_TYPE_INT32_AS_STRING
                                              DBUS_TYPE_INT32_AS_STRING
                                              DBUS_TYPE_UINT32_AS_STRING
                                              DBUS_TYPE_ARRAY_AS_STRING
                                              DBUS_TYPE_BYTE_AS_STRING
                                              DBUS_STRUCT_END_CHAR_AS_STRING,
                                              &array_iter);
    if (!db_ret) {
        return false;
    }

    multi_step_item = pd->multi_step.request_list;
    while (multi_step_item != NULL) {
        db_ret = dbus_message_iter_open_container(&array_iter,
                                                  DBUS_TYPE_STRUCT, NULL,
                                                  &struct_iter);
        if (!db_ret)  {
            return false;
        }

        db_ret = dbus_message_iter_append_basic(&struct_iter,
                                                DBUS_TYPE_INT32,
                                                &multi_step_item->group);
        if (!db_ret) {
            return false;
        }

        db_ret = dbus_message_iter_append_basic(&struct_iter,
                                                DBUS_TYPE_INT32,
                                                &multi_step_item->id);
        if (!db_ret) {
            return false;
        }

        multi_step_item_type = sss_authtok_get_type(multi_step_item->value);
        db_ret = dbus_message_iter_append_basic(&struct_iter,
                                                DBUS_TYPE_UINT32,
                                                &multi_step_item_type);
        if (!db_ret) {
            return false;
        }

        multi_step_item_data = sss_authtok_get_data(multi_step_item->value);
        multi_step_item_length = sss_authtok_get_size(multi_step_item->value);
        db_ret = dbus_message_iter_append_fixed_array(&struct_iter,
                                                      DBUS_TYPE_BYTE,
                                                      multi_step_item_data,
                                                      multi_step_item_length);
        if (!db_ret) {
            return false;
        }

        db_ret = dbus_message_iter_close_container(&array_iter, &struct_iter);
        if (!db_ret) {
            return false;
        }

        multi_step_item = multi_step_item->next;
    }

    db_ret = dbus_message_iter_close_container(&iter, &struct_iter);
    if (!db_ret) {
        return false;
    }

    return db_ret;
}

static dbus_bool_t dp_unpack_some_dbus_args(DBusMessage *msg,
                                            DBusMessageIter *iter,
                                            int first_arg_type,
                                            ...)
{
    va_list ap;
    int expected_arg_type, expected_element_type, i = 0;
    void *arg_ptr;
    int *arg_n_ptr;
    dbus_bool_t ret = FALSE;

    va_start(ap, first_arg_type);
    for (expected_arg_type = first_arg_type;
         expected_arg_type != DBUS_TYPE_INVALID;
         expected_arg_type = va_arg(ap, int)) {
         if (i++ && !dbus_message_iter_next(iter)) {
             goto done;
         }
         if (dbus_message_iter_get_arg_type(iter) != expected_arg_type) {
             goto done;
         }
         if (expected_arg_type == DBUS_TYPE_ARRAY) {
             expected_element_type = va_arg(ap, int);
             if (expected_element_type == DBUS_TYPE_INVALID) {
                 goto done;
             }
         }
         arg_ptr = va_arg(ap, void *);
         if (expected_arg_type != DBUS_TYPE_ARRAY) {
             dbus_message_iter_get_basic(iter, arg_ptr);
         } else {
             arg_n_ptr = va_arg(ap, int *);
             dbus_message_iter_get_fixed_array(iter, arg_ptr, arg_n_ptr);
         }
    }
    ret = TRUE;
done:
    va_end(ap);
    return ret;
}

bool dp_unpack_pam_request(DBusMessage *msg, TALLOC_CTX *mem_ctx,
                           struct pam_data **new_pd, DBusError *dbus_error)
{
    dbus_bool_t db_ret;
    DBusMessageIter iter, array_iter, struct_iter;
    int ret;
    struct pam_data pd;
    uint32_t authtok_type;
    uint32_t authtok_length;
    uint8_t *authtok_data;
    uint32_t new_authtok_type;
    uint32_t new_authtok_length;
    uint8_t *new_authtok_data;
    dbus_bool_t multi_step;
    uint32_t multi_step_request;
    uint32_t multi_step_authtok_type;
    int multi_step_authtok_length;
    uint8_t *multi_step_authtok_data;
    struct multi_step_request_item *multi_step_item, **multi_step_tail;

    memset(&pd, 0, sizeof(pd));

    if (!dbus_message_iter_init(msg, &iter)) {
        return false;
    }
    db_ret = dp_unpack_some_dbus_args(msg, &iter,
                                      DBUS_TYPE_INT32,  &(pd.cmd),
                                      DBUS_TYPE_STRING, &(pd.user),
                                      DBUS_TYPE_STRING, &(pd.domain),
                                      DBUS_TYPE_STRING, &(pd.service),
                                      DBUS_TYPE_STRING, &(pd.tty),
                                      DBUS_TYPE_STRING, &(pd.ruser),
                                      DBUS_TYPE_STRING, &(pd.rhost),
                                      DBUS_TYPE_UINT32, &authtok_type,
                                      DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                      &authtok_data, &authtok_length,
                                      DBUS_TYPE_UINT32, &new_authtok_type,
                                      DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                      &new_authtok_data, &new_authtok_length,
                                      DBUS_TYPE_INT32, &(pd.priv),
                                      DBUS_TYPE_UINT32, &(pd.cli_pid),
                                      DBUS_TYPE_BOOLEAN, &(multi_step),
                                      DBUS_TYPE_UINT32, &(multi_step_request),
                                      DBUS_TYPE_INT32,
                                      &(pd.multi_step.client_context_id),
                                      DBUS_TYPE_INVALID);

    if (!db_ret) {
        DEBUG(1, ("dbus_message_get_args failed.\n"));
        return false;
    }

    pd.multi_step.multi_step = multi_step;
    pd.multi_step.request = multi_step_request;
    multi_step_tail = &pd.multi_step.request_list;
    *multi_step_tail = NULL;

    db_ret = dbus_message_iter_open_container(&iter,
                                              DBUS_TYPE_ARRAY,
                                              DBUS_STRUCT_BEGIN_CHAR_AS_STRING
                                              DBUS_TYPE_INT32_AS_STRING
                                              DBUS_TYPE_INT32_AS_STRING
                                              DBUS_TYPE_UINT32_AS_STRING
                                              DBUS_TYPE_ARRAY_AS_STRING
                                              DBUS_TYPE_BYTE_AS_STRING
                                              DBUS_STRUCT_END_CHAR_AS_STRING,
                                              &array_iter);
    if (!db_ret) {
        return false;
    }

    for (;;) {
        multi_step_item = talloc_ptrtype(mem_ctx, multi_step_item);
        if (multi_step_item == NULL) {
            return false;
        }

        db_ret = dbus_message_iter_open_container(&array_iter,
                                                  DBUS_TYPE_STRUCT, NULL,
                                                  &struct_iter);
        if (!db_ret)  {
            break;
        }

        if (!dp_unpack_some_dbus_args(msg, &iter,
                                      DBUS_TYPE_INT32,
                                      &multi_step_item->group,
                                      DBUS_TYPE_INT32,
                                      &multi_step_item->id,
                                      DBUS_TYPE_UINT32,
                                      &multi_step_authtok_type,
                                      DBUS_TYPE_ARRAY,
                                      DBUS_TYPE_BYTE,
                                      &multi_step_authtok_data,
                                      &multi_step_authtok_length,
                                      DBUS_TYPE_INVALID)) {
            return false;
        }

        multi_step_item->value = sss_authtok_new(multi_step_item);
        if (multi_step_item->value == NULL) {
            return false;
        }

        if (sss_authtok_set(multi_step_item->value,
                            multi_step_authtok_type,
                            multi_step_authtok_data,
                            multi_step_authtok_length) != 0) {
            return false;
        }

        db_ret = dbus_message_iter_close_container(&array_iter, &struct_iter);
        if (!db_ret) {
            return false;
        }

        *multi_step_tail = multi_step_item;
        multi_step_tail = &multi_step_item->next;;
    }

    db_ret = dbus_message_iter_close_container(&iter, &array_iter);
    if (!db_ret) {
        return false;
    }

    ret = copy_pam_data(mem_ctx, &pd, new_pd);
    if (ret != EOK) {
        DEBUG(1, ("copy_pam_data failed.\n"));
        return false;
    }

    ret = sss_authtok_set((*new_pd)->authtok, authtok_type,
                          authtok_data, authtok_length);
    if (ret) {
        DEBUG(1, ("Failed to set auth token: %d [%s]\n", ret, strerror(ret)));
        return false;
    }
    ret = sss_authtok_set((*new_pd)->newauthtok, new_authtok_type,
                          new_authtok_data, new_authtok_length);
    if (ret) {
        DEBUG(1, ("Failed to set auth token: %d [%s]\n", ret, strerror(ret)));
        return false;
    }

    return true;
}

bool dp_pack_pam_response(DBusMessage *msg, struct pam_data *pd)
{
    dbus_bool_t dbret;
    struct response_data *resp;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    DBusMessageIter data_iter;

    dbus_message_iter_init_append(msg, &iter);

    /* Append the PAM status */
    dbret = dbus_message_iter_append_basic(&iter,
                                   DBUS_TYPE_UINT32, &(pd->pam_status));
    if (!dbret) {
        return false;
    }

    /* Create an array of response structures */
    dbret = dbus_message_iter_open_container(&iter,
                                             DBUS_TYPE_ARRAY, "(uay)",
                                             &array_iter);
    if (!dbret) {
        return false;
    }

    resp = pd->resp_list;
    while (resp != NULL) {
        /* Create a DBUS struct */
        dbret = dbus_message_iter_open_container(&array_iter,
                                                 DBUS_TYPE_STRUCT, NULL,
                                                 &struct_iter);
        if (!dbret) {
            return false;
        }

        /* Add the response type */
        dbret = dbus_message_iter_append_basic(&struct_iter,
                                               DBUS_TYPE_UINT32,
                                               &(resp->type));
        if (!dbret) {
            return false;
        }

        /* Add the response message */
        dbret = dbus_message_iter_open_container(&struct_iter,
                                                 DBUS_TYPE_ARRAY, "y",
                                                 &data_iter);
        if (!dbret) {
            return false;
        }
        dbret = dbus_message_iter_append_fixed_array(&data_iter,
                       DBUS_TYPE_BYTE, &(resp->data), resp->len);
        if (!dbret) {
            return false;
        }
        dbret = dbus_message_iter_close_container(&struct_iter, &data_iter);
        if (!dbret) {
            return false;
        }

        resp = resp->next;
        dbret = dbus_message_iter_close_container(&array_iter, &struct_iter);
        if (!dbret) {
            return false;
        }
    }

    /* Close the struct array */
    dbret = dbus_message_iter_close_container(&iter, &array_iter);
    if (!dbret) {
        return false;
    }

    return true;
}

bool dp_unpack_pam_response(DBusMessage *msg, struct pam_data *pd, DBusError *dbus_error)
{
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    DBusMessageIter sub_iter;
    int type;
    int len;
    const uint8_t *data;

    if (!dbus_message_iter_init(msg, &iter)) {
        DEBUG(1, ("pam response has no arguments.\n"));
        return false;
    }

    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
        DEBUG(1, ("pam response format error.\n"));
        return false;
    }
    dbus_message_iter_get_basic(&iter, &(pd->pam_status));

    if (!dbus_message_iter_next(&iter)) {
        DEBUG(1, ("pam response has too few arguments.\n"));
        return false;
    }

    /* After this point will be an array of pam data */
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
        DEBUG(1, ("pam response format error.\n"));
        DEBUG(1, ("Type was %c\n", (char)dbus_message_iter_get_arg_type(&iter)));
        return false;
    }

    if (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
        DEBUG(1, ("pam response format error.\n"));
        return false;
    }

    dbus_message_iter_recurse(&iter, &array_iter);
    while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID) {
        /* Read in a pam data struct */
        if (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_STRUCT) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }

        dbus_message_iter_recurse(&array_iter,  &struct_iter);

        /* PAM data struct contains a type and a byte-array of data */

        /* Get the pam data type */
        if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_UINT32) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }
        dbus_message_iter_get_basic(&struct_iter, &type);

        if (!dbus_message_iter_next(&struct_iter)) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }

        /* Get the byte array */
        if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&struct_iter) != DBUS_TYPE_BYTE) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }

        dbus_message_iter_recurse(&struct_iter, &sub_iter);
        dbus_message_iter_get_fixed_array(&sub_iter, &data, &len);

        if (pam_add_response(pd, type, len, data) != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
            return false;
        }
        dbus_message_iter_next(&array_iter);
    }

    return true;
}

void dp_id_callback(DBusPendingCall *pending, void *ptr)
{
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t ret;
    dbus_uint16_t dp_ver;
    int type;

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Severe error. A reply callback was called but no"
                  " reply was received and no timeout occurred\n"));

        /* FIXME: Destroy this connection ? */
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, &dp_ver,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1, ("Failed to parse message\n"));
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            /* FIXME: Destroy this connection ? */
            goto done;
        }

        DEBUG(4, ("Got id ack and version (%d) from DP\n", dp_ver));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("The Monitor returned an error [%s]\n",
                 dbus_message_get_error_name(reply)));
        /* Falling through to default intentionally*/
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */

        /* FIXME: Destroy this connection ? */
        break;
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

int dp_common_send_id(struct sbus_connection *conn, uint16_t version,
                      const char *name)
{
    DBusMessage *msg;
    dbus_bool_t ret;
    int retval;

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_REGISTER);
    if (msg == NULL) {
        DEBUG(0, ("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending ID to DP: (%d,%s)\n",
              version, name));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1, ("Failed to build message\n"));
        return EIO;
    }

    retval = sbus_conn_send(conn, msg, 30000, dp_id_callback, NULL, NULL);

    dbus_message_unref(msg);
    return retval;
}

