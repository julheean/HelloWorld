LXR linux/net/ceph/auth.c Print Save<< 
v6.0.9
 >> 
 Search Prefs
   1// SPDX-License-Identifier: GPL-2.0
   2#include <linux/ceph/ceph_debug.h>
   3
   4#include <linux/module.h>
   5#include <linux/err.h>
   6#include <linux/slab.h>
   7
   8#include <linux/ceph/types.h>
   9#include <linux/ceph/decode.h>
  10#include <linux/ceph/libceph.h>
  11#include <linux/ceph/messenger.h>
  12#include "auth_none.h"
  13#include "auth_x.h"

   5#include <linux/err.h>
   6#include <linux/slab.h>
   7
   8#include <linux/ceph/types.h>
   9#include <linux/ceph/decode.h>
  10#include <linux/ceph/libceph.h>
  11#include <linux/ceph/messenger.h>
  12#include "auth_none.h"
  13#include "auth_x.h"



   2#include <linux/ceph/ceph_debug.h>
   3
   4#include <linux/module.h>
   5#include <linux/err.h>
   6#include <linux/slab.h>
   7
   8#include <linux/ceph/types.h>
   9#include <linux/ceph/decode.h>
  10#include <linux/ceph/libceph.h>
  11#include <linux/ceph/messenger.h>
  12#include "auth_none.h"
  13#include "auth_x.h"
 
include <linux/ceph/types.h>
   9#include <linux/ceph/decode.h>
  10#include <linux/ceph/libceph.h>
  11#include <linux/ceph/messenger.h>





  14
  15
  16/*
  17 * get protocol handler
  18 */
  19static u32 supported_protocols[] = {
  20        CEPH_AUTH_NONE,
  21        CEPH_AUTH_CEPHX
  22};
  23
  24static int init_protocol(struct ceph_auth_client *ac, int proto)
  25{
  26        dout("%s proto %d\n", __func__, proto);
  27
  28        switch (proto) {
  29        case CEPH_AUTH_NONE:
  30                return ceph_auth_none_init(ac);
  31        case CEPH_AUTH_CEPHX:
  32                return ceph_x_init(ac);
  33        default:
  34                pr_err("bad auth protocol %d\n", proto);
  35                return -EINVAL;
  36        }
  37}
  38
  39void ceph_auth_set_global_id(struct ceph_auth_client *ac, u64 global_id)
  40{
  41        dout("%s global_id %llu\n", __func__, global_id);
  42
  43        if (!global_id)
  44                pr_err("got zero global_id\n");
  45
  46        if (ac->global_id && global_id != ac->global_id)
  47                pr_err("global_id changed from %llu to %llu\n", ac->global_id,
  48                       global_id);
  49
  50        ac->global_id = global_id;
  51}
  52
  53/*
  54 * setup, teardown.
  55 */
  56struct ceph_auth_client *ceph_auth_init(const char *name,
  57                                        const struct ceph_crypto_key *key,
  58                                        const int *con_modes)
  59{
  60        struct ceph_auth_client *ac;
  61
  62        ac = kzalloc(sizeof(*ac), GFP_NOFS);
  63        if (!ac)
  64                return ERR_PTR(-ENOMEM);
  65
  66        mutex_init(&ac->mutex);
  67        ac->negotiating = true;
  68        if (name)
  69                ac->name = name;
  70        else
  71                ac->name = CEPH_AUTH_NAME_DEFAULT;
  72        ac->key = key;
  73        ac->preferred_mode = con_modes[0];
  74        ac->fallback_mode = con_modes[1];
  75
  76        dout("%s name '%s' preferred_mode %d fallback_mode %d\n", __func__,
  77             ac->name, ac->preferred_mode, ac->fallback_mode);
  78        return ac;
  79}
  80
  81void ceph_auth_destroy(struct ceph_auth_client *ac)
  82{
  83        dout("auth_destroy %p\n", ac);
  84        if (ac->ops)
  85                ac->ops->destroy(ac);
  86        kfree(ac);
  87}
  88
  89/*
  90 * Reset occurs when reconnecting to the monitor.
  91 */
  92void ceph_auth_reset(struct ceph_auth_client *ac)
  93{
  94        mutex_lock(&ac->mutex);
  95        dout("auth_reset %p\n", ac);
  96        if (ac->ops && !ac->negotiating)
  97                ac->ops->reset(ac);
  98        ac->negotiating = true;
  99        mutex_unlock(&ac->mutex);
 100}
 101
 102/*
 103 * EntityName, not to be confused with entity_name_t
 104 */
 105int ceph_auth_entity_name_encode(const char *name, void **p, void *end)
 106{
 107        int len = strlen(name);
 108
 109        if (*p + 2*sizeof(u32) + len > end)
 110                return -ERANGE;
 111        ceph_encode_32(p, CEPH_ENTITY_TYPE_CLIENT);
 112        ceph_encode_32(p, len);
 113        ceph_encode_copy(p, name, len);
 114        return 0;
 115}
 116
 117/*
 118 * Initiate protocol negotiation with monitor.  Include entity name
 119 * and list supported protocols.
 120 */
 121int ceph_auth_build_hello(struct ceph_auth_client *ac, void *buf, size_t len)
 122{
 123        struct ceph_mon_request_header *monhdr = buf;
 124        void *p = monhdr + 1, *end = buf + len, *lenp;
 125        int i, num;
 126        int ret;
 127
 128        mutex_lock(&ac->mutex);
 129        dout("auth_build_hello\n");
 130        monhdr->have_version = 0;
 131        monhdr->session_mon = cpu_to_le16(-1);
 132        monhdr->session_mon_tid = 0;
 133
 134        ceph_encode_32(&p, CEPH_AUTH_UNKNOWN);  /* no protocol, yet */
 135
 136        lenp = p;
 137        p += sizeof(u32);
 138
 139        ceph_decode_need(&p, end, 1 + sizeof(u32), bad);
 140        ceph_encode_8(&p, 1);
 141        num = ARRAY_SIZE(supported_protocols);
 142        ceph_encode_32(&p, num);
 143        ceph_decode_need(&p, end, num * sizeof(u32), bad);
 144        for (i = 0; i < num; i++)
 145                ceph_encode_32(&p, supported_protocols[i]);
 146
 147        ret = ceph_auth_entity_name_encode(ac->name, &p, end);
 148        if (ret < 0)
 149                goto out;
 150        ceph_decode_need(&p, end, sizeof(u64), bad);
 151        ceph_encode_64(&p, ac->global_id);
 152
 153        ceph_encode_32(&lenp, p - lenp - sizeof(u32));
 154        ret = p - buf;
 155out:
 156        mutex_unlock(&ac->mutex);
 157        return ret;
 158
 159bad:
 160        ret = -ERANGE;
 161        goto out;
 162}
 163
 164static int build_request(struct ceph_auth_client *ac, bool add_header,
 165                         void *buf, int buf_len)
 166{
 167        void *end = buf + buf_len;
 168        void *p;
 169        int ret;
 170
 171        p = buf;
 172        if (add_header) {
 173                /* struct ceph_mon_request_header + protocol */
 174                ceph_encode_64_safe(&p, end, 0, e_range);
 175                ceph_encode_16_safe(&p, end, -1, e_range);
 176                ceph_encode_64_safe(&p, end, 0, e_range);
 177                ceph_encode_32_safe(&p, end, ac->protocol, e_range);
 178        }
 179
 180        ceph_encode_need(&p, end, sizeof(u32), e_range);
 181        ret = ac->ops->build_request(ac, p + sizeof(u32), end);
 182        if (ret < 0) {
 183                pr_err("auth protocol '%s' building request failed: %d\n",
 184                       ceph_auth_proto_name(ac->protocol), ret);
 185                return ret;
 186        }
 187        dout(" built request %d bytes\n", ret);
 188        ceph_encode_32(&p, ret);
 189        return p + ret - buf;
 190
 191e_range:
 192        return -ERANGE;
 193}
 194
 195/*
 196 * Handle auth message from monitor.
 197 */
 198int ceph_handle_auth_reply(struct ceph_auth_client *ac,
    99
 199                           void *buf, size_t len,
 200                           void *reply_buf, size_t reply_len)
 201{
 202        void *p = buf;
 203        void *end = buf + len;
 204        int protocol;
 205        s32 result;
 206        u64 global_id;
 207        void *payload, *payload_end;
 208        int payload_len;
 209        char *result_msg;
 210        int result_msg_len;
 211        int ret = -EINVAL;
 212
void 
	 
	 9
 199                           void *buf, size_t len,
 200                           void *reply_buf, size_t reply_len)
 201{
 202        void *p = buf;
 203        void *end = buf + len;
 204        int protocol;
 205        s32 result;
 206        u64 global_id;
 207        void *payload, *payload_end;
 208        int payload_len;
 209        char *result_msg;
 210        int result_msg_len;
 211        int ret = -EINVAL;
 212


void 
	 
 213        u64 mutex_lock(&ac->mutex);
 214        dout("handle_auth_reply %p %p\n", p, end);
 215        ceph_decode_need(&p, end, sizeof(u32) * 3 + sizeof(u64), bad);
 216        protocol = ceph_decode_32(&p);
 217        result = ceph_decode_32(&p);
 218        global_id = ceph_decode_64(&p);
 219        payload_len = ceph_decode_32(&p);
 220        payload = p;
 221        p += payload_len;
 222        ceph_decode_need(&p, end, sizeof(u32), bad);
 223        result_msg_len = ceph_decode_32(&p);
 224        result_msg = p;
 225        p += result_msg_len;
 226        if (p != end)
 227                goto bad;
 228
 229        dout(" result %d '%.*s' gid %llu len %d\n", result, result_msg_len,
 230             result_msg, global_id, payload_len);
 231
 232        payload_end = payload + payload_len;
 233
 234        if (ac->negotiating) {
 235                /* server does not support our protocols? */
 236                if (!protocol && result < 0) {
 237                        ret = result;
 238                        goto out;
 239                }
 240                /* set up (new) protocol handler? */
 241                if (ac->protocol && ac->protocol != protocol) {
 242                        ac->ops->destroy(ac);
 243                        ac->protocol = 0;
 244                        ac->ops = NULL;
 245                }
 246                if (ac->protocol != protocol) {
 247                        ret = init_protocol(ac, protocol);
 248                        if (ret) {
 249                                pr_err("auth protocol '%s' init failed: %d\n",
 250                                       ceph_auth_proto_name(protocol), ret);
 251                                goto out;
 252                        }
 253                }
 254
 255                ac->negotiating = false;
 256        }
 257
 258        if (result) {
 259                pr_err("auth protocol '%s' mauth authentication failed: %d\n",
 260                       ceph_auth_proto_name(ac->protocol), result);
 261                ret = result;
 262                goto out;
 263        }
 264
 265        ret = ac->ops->handle_reply(ac, global_id, payload, payload_end,
 266                                    NULL, NULL, NULL, NULL);
 267        if (ret == -EAGAIN) {
 268                ret = build_request(ac, true, reply_buf, reply_len);
 269                goto out;
 270        } else if (ret) {
 271                goto out;
 272        }
 273
 274out:
 275        mutex_unlock(&ac->mutex);
 276        return ret;
 277
 278bad:
 279        pr_err("failed to decode auth msg\n");
 280        ret = -EINVAL;
 281        goto out;
 282}
 283
 284int ceph_build_auth(struct ceph_auth_client *ac,
 285                    void *msg_buf, size_t msg_len)
 286{
 287        int ret = 0;
 288
 289        mutex_lock(&ac->mutex);
 290        if (ac->ops->should_authenticate(ac))
 291                ret = build_request(ac, true, msg_buf, msg_len);
 292        mutex_unlock(&ac->mutex);
 293        return ret;
 294}
 295
 296int ceph_auth_is_authenticated(struct ceph_auth_client *ac)
 297{
 298        int ret = 0;
 299
 300        mutex_lock(&ac->mutex);
 301        if (ac->ops)
 302                ret = ac->ops->is_authenticated(ac);
 303        mutex_unlock(&ac->mutex);
 304        return ret;
 305}
 306EXPORT_SYMBOL(ceph_auth_is_authenticated);
 307
 308int __ceph_auth_get_authorizer(struct ceph_auth_client *ac,
 309                               struct ceph_auth_handshake *auth,
 310                               int peer_type, bool force_new,
 311                               int *proto, int *pref_mode, int *fallb_mode)
 312{
 313        int ret;
 314
 315        mutex_lock(&ac->mutex);
 316        if (force_new && auth->authorizer) {
 317                ceph_auth_destroy_authorizer(auth->authorizer);
 318                auth->authorizer = NULL;
 319        }
 320        if (!auth->authorizer)
 321                ret = ac->ops->create_authorizer(ac, peer_type, auth);
 322        else if (ac->ops->update_authorizer)
 323                ret = ac->ops->update_authorizer(ac, peer_type, auth);
 324        else
 325                ret = 0;
 326        if (ret)
 327                goto out;
 328
 329        *proto = ac->protocol;
 330        if (pref_mode && fallb_mode) {
 331                *pref_mode = ac->preferred_mode;
 332                *fallb_mode = ac->fallback_mode;
 333        }
 334
 335out:
 336        mutex_unlock(&ac->mutex);
 337        return ret;
 338}
 339EXPORT_SYMBOL(__ceph_auth_get_authorizer);
 340
 341void ceph_auth_destroy_authorizer(struct ceph_authorizer *a)
 342{
 343        a->destroy(a);
 344}
 345EXPORT_SYMBOL(ceph_auth_destroy_authorizer);
 346
 347int ceph_auth_add_authorizer_challenge(struct ceph_auth_client *ac,
 348                                       struct ceph_authorizer *a,
 349                                       void *challenge_buf,
 350                                       int challenge_buf_len)
 351{
 352        int ret = 0;
 353
 354        mutex_lock(&ac->mutex);
 355        if (ac->ops && ac->ops->add_authorizer_challenge)
 356                ret = ac->ops->add_authorizer_challenge(ac, a, challenge_buf,
 357                                                        challenge_buf_len);
 358        mutex_unlock(&ac->mutex);
 359        return ret;
 360}
 361EXPORT_SYMBOL(ceph_auth_add_authorizer_challenge);
 362
 363int ceph_auth_verify_authorizer_reply(struct ceph_auth_client *ac,
 364                                      struct ceph_authorizer *a,
 365                                      void *reply, int reply_len,
 366                                      u8 *session_key, int *session_key_len,
 367                                      u8 *con_secret, int *con_secret_len)
 368{
 369        int ret = 0;
 370
 371        mutex_lock(&ac->mutex);
 372        if (ac->ops && ac->ops->verify_authorizer_reply)
 373                ret = ac->ops->verify_authorizer_reply(ac, a,
 374                        reply, reply_len, session_key, session_key_len,
 375                        con_secret, con_secret_len);
 376        mutex_unlock(&ac->mutex);
 377        return ret;
 378}
 379EXPORT_SYMBOL(ceph_auth_verify_authorizer_reply);
 380
 381void ceph_auth_invalidate_authorizer(struct ceph_auth_client *ac, int peer_type)
 382{
 383        mutex_lock(&ac->mutex);
 384        if (ac->ops && ac->ops->invalidate_authorizer)
 385                ac->ops->invalidate_authorizer(ac, peer_type);
 386        mutex_unlock(&ac->mutex);
 387}
 388EXPORT_SYMBOL(ceph_auth_invalidate_authorizer);
 389
 390/*
 391 * msgr2 authentication
 392 */
 393
 394static bool contains(const int *arr, int cnt, int val)
 395{
 396        int i;
 397
 398        for (i = 0; i < cnt; i++) {
 399                if (arr[i] == val)
 400                        return true;
 401        }
 402
 403        return false;
 404}
 405
 406static int encode_con_modes(void **p, void *end, int pref_mode, int fallb_mode)
 407{
 408        WARN_ON(pref_mode == CEPH_CON_MODE_UNKNOWN);
 409        if (fallb_mode != CEPH_CON_MODE_UNKNOWN) {
 410                ceph_encode_32_safe(p, end, 2, e_range);
 411                ceph_encode_32_safe(p, end, pref_mode, e_range);
 412                ceph_encode_32_safe(p, end, fallb_mode, e_range);
 413        } else {
 414                ceph_encode_32_safe(p, end, 1, e_range);
 415                ceph_encode_32_safe(p, end, pref_mode, e_range);
 416        }
 417
 418        return 0;
 419
 420e_range:
 421        return -ERANGE;
 422}
 423
 424/*
 425 * Similar to ceph_auth_build_hello().
 426 */
 427int ceph_auth_get_request(struct ceph_auth_client *ac, void *buf, int buf_len)
 428{
 429        int proto = ac->key ? CEPH_AUTH_CEPHX : CEPH_AUTH_NONE;
 430        void *end = buf + buf_len;
 431        void *lenp;
 432        void *p;
 433        int ret;
 434
 435        mutex_lock(&ac->mutex);
 436        if (ac->protocol == CEPH_AUTH_UNKNOWN) {
 437                ret = init_protocol(ac, proto);
 438                if (ret) {
 439                        pr_err("auth protocol '%s' init failed: %d\n",
 440                               ceph_auth_proto_name(proto), ret);
 441                        goto out;
 442                }
 443        } else {
 444                WARN_ON(ac->protocol != proto);
 445                ac->ops->reset(ac);
 446        }
 447
 448        p = buf;
 449        ceph_encode_32_safe(&p, end, ac->protocol, e_range);
 450        ret = encode_con_modes(&p, end, ac->preferred_mode, ac->fallback_mode);
 451        if (ret)
 452                goto out;
 453
 454        lenp = p;
 455        p += 4;  /* space for len */
 456
 457        ceph_encode_8_safe(&p, end, CEPH_AUTH_MODE_MON, e_range);
 458        ret = ceph_auth_entity_name_encode(ac->name, &p, end);
 459        if (ret)
 460                goto out;
 461
 462        ceph_encode_64_safe(&p, end, ac->global_id, e_range);
 463        ceph_encode_32(&lenp, p - lenp - 4);
 464        ret = p - buf;
 465
 466out:
 467        mutex_unlock(&ac->mutex);
 468        return ret;
 469
 470e_range:
 471        ret = -ERANGE;
 472        goto out;
 473}
 474
 475int ceph_auth_handle_reply_more(struct ceph_auth_client *ac, void *reply,
 476                                int reply_len, void *buf, int buf_len)
 477{
 478        int ret;
 479
 480        mutex_lock(&ac->mutex);
 481        ret = ac->ops->handle_reply(ac, 0, reply, reply + reply_len,
 482                                    NULL, NULL, NULL, NULL);
 483        if (ret == -EAGAIN)
 484                ret = build_request(ac, false, buf, buf_len);
 485        else
 486                WARN_ON(ret >= 0);
 487        mutex_unlock(&ac->mutex);
 488        return ret;
 489}
 490
 491int ceph_auth_handle_reply_done(struct ceph_auth_client *ac,
 492                                u64 global_id, void *reply, int reply_len,
 493                                u8 *session_key, int *session_key_len,
 494                                u8 *con_secret, int *con_secret_len)
 495{
 496        int ret;
 497
 498        mutex_lock(&ac->mutex);
 499        ret = ac->ops->handle_reply(ac, global_id, reply, reply + reply_len,
 500                                    session_key, session_key_len,
 501                                    con_secret, con_secret_len);
 502        WARN_ON(ret == -EAGAIN || ret > 0);
 503        mutex_unlock(&ac->mutex);
 504        return ret;
 505}
 506
 507bool ceph_auth_handle_bad_method(struct ceph_auth_client *ac,
 508                                 int used_proto, int result,
 509                                 const int *allowed_protos, int proto_cnt,
 510                                 const int *allowed_modes, int mode_cnt)
 511{
 512        mutex_lock(&ac->mutex);
 513        WARN_ON(used_proto != ac->protocol);
 514
 515        if (result == -EOPNOTSUPP) {
 516                if (!contains(allowed_protos, proto_cnt, ac->protocol)) {
 517                        pr_err("auth protocol '%s' not allowed\n",
 518                               ceph_auth_proto_name(ac->protocol));
 519                        goto not_allowed;
 520                }
 521                if (!contains(allowed_modes, mode_cnt, ac->preferred_mode) &&
 522                    (ac->fallback_mode == CEPH_CON_MODE_UNKNOWN ||
 523                     !contains(allowed_modes, mode_cnt, ac->fallback_mode))) {
 524                        pr_err("preferred mode '%s' not allowed\n",
 525                               ceph_con_mode_name(ac->preferred_mode));
 526                        if (ac->fallback_mode == CEPH_CON_MODE_UNKNOWN)
 527                                pr_err("no fallback mode\n");
 528                        else
 529                                pr_err("fallback mode '%s' not allowed\n",
 530                                       ceph_con_mode_name(ac->fallback_mode));
 531                        goto not_allowed;
 532                }
 533        }
 534
 535        WARN_ON(result == -EOPNOTSUPP || result >= 0);
 536        pr_err("auth protocol '%s' msgr authentication failed: %d\n",
 537               ceph_auth_proto_name(ac->protocol), result);
 538
 539        mutex_unlock(&ac->mutex);
 540        return true;
 541
 542not_allowed:
 543        mutex_unlock(&ac->mutex);
 544        return false;
 545}
 546
 547int ceph_auth_get_authorizer(struct ceph_auth_client *ac,
 548                             struct ceph_auth_handshake *auth,
 549                             int peer_type, void *buf, int *buf_len)
 550{
 551        void *end = buf + *buf_len;
 552        int pref_mode, fallb_mode;
 553        int proto;
 554        void *p;
 555        int ret;
 556
 557        ret = __ceph_auth_get_authorizer(ac, auth, peer_type, true, &proto,
 558                                         &pref_mode, &fallb_mode);
 559        if (ret)
 560                return ret;
 561
 562        p = buf;
 563        ceph_encode_32_safe(&p, end, proto, e_range);
 564        ret = encode_con_modes(&p, end, pref_mode, fallb_mode);
 565        if (ret)
 566                return ret;
 567
 568        ceph_encode_32_safe(&p, end, auth->authorizer_buf_len, e_range);
 569        *buf_len = p - buf;
 570        return 0;
 571
 572e_range:
 573        return -ERANGE;
 574}
 575EXPORT_SYMBOL(ceph_auth_get_authorizer);
 576
 577int ceph_auth_handle_svc_reply_more(struct ceph_auth_client *ac,
 578                                    struct ceph_auth_handshake *auth,
 579                                    void *reply, int reply_len,
 580                                    void *buf, int *buf_len)
 581{
 582        void *end = buf + *buf_len;
 583        void *p;
 584        int ret;
 585
 586        ret = ceph_auth_add_authorizer_challenge(ac, auth->authorizer,
 587                                                 reply, reply_len);
 588        if (ret)
 589                return ret;
 590
 591        p = buf;
 592        ceph_encode_32_safe(&p, end, auth->authorizer_buf_len, e_range);
 593        *buf_len = p - buf;
 594        return 0;
 595
 596e_range:
 597        return -ERANGE;
 598}
 599EXPORT_SYMBOL(ceph_auth_handle_svc_reply_more);
 600
 601int ceph_auth_handle_svc_reply_done(struct ceph_auth_client *ac,
 602                                    struct ceph_auth_handshake *auth,
 603                                    void *reply, int reply_len,
 604                                    u8 *session_key, int *session_key_len,
 605                                    u8 *con_secret, int *con_secret_len)
 606{
 607        return ceph_auth_verify_authorizer_reply(ac, auth->authorizer,
 608                reply, reply_len, session_key, session_key_len,
 609                con_secret, con_secret_len);
 610}
 611EXPORT_SYMBOL(ceph_auth_handle_svc_reply_done);
 612
 613bool ceph_auth_handle_bad_authorizer(struct ceph_auth_client *ac,
 614                                     int peer_type, int used_proto, int result,
 615                                     const int *allowed_protos, int proto_cnt,
 616                                     const int *allowed_modes, int mode_cnt)
 617{
 618        mutex_lock(&ac->mutex);
 619        WARN_ON(used_proto != ac->protocol);
 620
 621        if (result == -EOPNOTSUPP) {
 622                if (!contains(allowed_protos, proto_cnt, ac->protocol)) {
 623                        pr_err("auth protocol '%s' not allowed by %s\n",
 624                               ceph_auth_proto_name(ac->protocol),
 625                               ceph_entity_type_name(peer_type));
 626                        goto not_allowed;
 627                }
 628                if (!contains(allowed_modes, mode_cnt, ac->preferred_mode) &&
 629                    (ac->fallback_mode == CEPH_CON_MODE_UNKNOWN ||
 630                     !contains(allowed_modes, mode_cnt, ac->fallback_mode))) {
 631                        pr_err("preferred mode '%s' not allowed by %s\n",
 632                               ceph_con_mode_name(ac->preferred_mode),
 633                               ceph_entity_type_name(peer_type));
 634                        if (ac->fallback_mode == CEPH_CON_MODE_UNKNOWN)
 635                                pr_err("no fallback mode\n");
 636                        else
 637                                pr_err("fallback mode '%s' not allowed by %s\n",
 638                                       ceph_con_mode_name(ac->fallback_mode),
 639                                       ceph_entity_type_name(peer_type));
 640                        goto not_allowed;
 641                }
 642        }
 643
 644        WARN_ON(result == -EOPNOTSUPP || result >= 0);
 645        pr_err("auth protocol '%s' authorization to %s failed: %d\n",
 646               ceph_auth_proto_name(ac->protocol),
 647               ceph_entity_type_name(peer_type), result);
 648
 649        if (ac->ops->invalidate_authorizer)
 650                ac->ops->invalidate_authorizer(ac, peer_type);
 651
 652        mutex_unlock(&ac->mutex);
 653        return true;
 654
 655not_allowed:
 656        mutex_unlock(&ac->mutex);
 657        return false;

 658}
 659EXPORT_SYMBOL(ceph_auth_handle_bad_authorizer);
 660
The original LXR software by the LXR community, this experimental version by lxr@linux.no.
