/*
 * SSH backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>

#include "putty.h"
#include "pageant.h" /* for AGENT_MAX_MSGLEN */
#include "tree234.h"
#include "storage.h"
#include "marshal.h"
#include "ssh.h"
#include "sshcr.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshchan.h"
#ifndef NO_GSSAPI
#include "sshgssc.h"
#include "sshgss.h"
#define MIN_CTXT_LIFETIME 5     /* Avoid rekey with short lifetime (seconds) */
#define GSS_KEX_CAPABLE (1<<0)  /* Can do GSS KEX */
#define GSS_CRED_UPDATED (1<<1) /* Cred updated since previous delegation */
#define GSS_CTXT_EXPIRES (1<<2) /* Context expires before next timer */
#define GSS_CTXT_MAYFAIL (1<<3) /* Context may expire during handshake */
#endif

struct Ssh {
    Socket *s;
    Seat *seat;
    Conf *conf;

    struct ssh_version_receiver version_receiver;
    int remote_bugs;

    Plug plug;
    Backend backend;

    Ldisc *ldisc;
    LogContext *logctx;

    /* The last list returned from get_specials. */
    SessionSpecial *specials;

    bool bare_connection;
    ssh_sharing_state *connshare;
    bool attempting_connshare;

#ifndef NO_GSSAPI
    struct ssh_connection_shared_gss_state gss_state;
#endif

    char *savedhost;
    int savedport;
    char *fullhostname;

    bool fallback_cmd;
    int exitcode;

    int version;
    int conn_throttle_count;
    int overall_bufsize;
    int throttled_all;
    int v1_stdout_throttling;
    unsigned long v2_outgoing_sequence;

    int ssh1_rdpkt_crstate;
    int ssh2_rdpkt_crstate;
    int ssh2_bare_rdpkt_crstate;
    int ssh_gotdata_crstate;
    int do_ssh1_connection_crstate;

    void *do_ssh_init_state;
    void *do_ssh1_login_state;
    void *do_ssh2_transport_state;
    void *do_ssh2_authconn_state;
    void *do_ssh_connection_init_state;

    struct rdpkt1_state_tag rdpkt1_state;
    struct rdpkt2_state_tag rdpkt2_state;
    struct rdpkt2_bare_state_tag rdpkt2_bare_state;

    /* SSH-1 and SSH-2 use this for different things, but both use it */
    int protocol_initial_phase_done;

    void (*protocol) (Ssh ssh, const void *vin, int inlen,
		      struct Packet *pkt);
    struct Packet *(*s_rdpkt) (Ssh ssh, const unsigned char **data,
                               int *datalen);
    int (*do_ssh_init)(Ssh ssh, unsigned char c);

    /*
     * We maintain our own copy of a Conf structure here. That way,
     * when we're passed a new one for reconfiguration, we can check
     * the differences and potentially reconfigure port forwardings
     * etc in mid-session.
     */
    Conf *conf;

    /*
     * Values cached out of conf so as to avoid the tree234 lookup
     * cost every time they're used.
     */
    int logomitdata;

    /*
     * Dynamically allocated username string created during SSH
     * login. Stored in here rather than in the coroutine state so
     * that it'll be reliably freed if we shut down the SSH session
     * at some unexpected moment.
     */
    char *username;

    /*
     * Used to transfer data back from async callbacks.
     */
    void *agent_response;
    int agent_response_len;
    int user_response;

    /*
     * The SSH connection can be set as `frozen', meaning we are
     * not currently accepting incoming data from the network. This
     * is slightly more serious than setting the _socket_ as
     * frozen, because we may already have had data passed to us
     * from the network which we need to delay processing until
     * after the freeze is lifted, so we also need a bufchain to
     * store that data.
     */
    int frozen;
    bufchain queued_incoming_data;

    /*
     * Dispatch table for packet types that we may have to deal
     * with at any time.
     */
    handler_fn_t packet_dispatch[256];

    /*
     * Queues of one-off handler functions for success/failure
     * indications from a request.
     */
    struct queued_handler *qhead, *qtail;
    handler_fn_t q_saved_handler1, q_saved_handler2;

    /*
     * This module deals with sending keepalives.
     */
    Pinger pinger;

    /*
     * Track incoming and outgoing data sizes and time, for
     * size-based rekeys.
     */
    unsigned long incoming_data_size, outgoing_data_size, deferred_data_size;
    unsigned long max_data_size;
    int kex_in_progress;
    unsigned long next_rekey, last_rekey;
    const char *deferred_rekey_reason;

    /*
     * Fully qualified host name, which we need if doing GSSAPI.
     */
    char *fullhostname;

#ifndef NO_GSSAPI
    /*
     * GSSAPI libraries for this session.
     */
    struct ssh_gss_liblist *gsslibs;
#endif

    /*
     * The last list returned from get_specials.
     */
    struct telnet_special *specials;

    /*
     * List of host key algorithms for which we _don't_ have a stored
     * host key. These are indices into the main hostkey_algs[] array
     */
    int uncert_hostkeys[lenof(hostkey_algs)];
    int n_uncert_hostkeys;

    /*
     * Flag indicating that the current rekey is intended to finish
     * with a newly cross-certified host key.
     */
    int cross_certifying;

    /*
     * Any asynchronous query to our SSH agent that we might have in
     * flight from the main authentication loop. (Queries from
     * agent-forwarding channels live in their channel structure.)
     */
    agent_pending_query *auth_agent_query;

    /* Handle for signaling IP Loopback manager that it can umap the addresses. */
    struct iploop ipl;
};

static const char *ssh_pkt_type(Ssh ssh, int type)
{
    if (ssh->version == 1)
	return ssh1_pkt_type(type);
    else
	return ssh2_pkt_type(ssh->pkt_kctx, ssh->pkt_actx, type);
}

#define logevent(s) logevent(ssh->frontend, s)

/* logevent, only printf-formatted. */
static void logeventf(Ssh ssh, const char *fmt, ...)
{
    va_list ap;
    char *buf;

    va_start(ap, fmt);
    buf = dupvprintf(fmt, ap);
    va_end(ap);
    logevent(buf);
    sfree(buf);
}

static void bomb_out(Ssh ssh, char *text)
{
    ssh_do_close(ssh, FALSE);
    logevent(text);
    connection_fatal(ssh->frontend, "%s", text);
    sfree(text);
}

#define bombout(msg) bomb_out(ssh, dupprintf msg)

/* Helper function for common bits of parsing ttymodes. */
static void parse_ttymodes(Ssh ssh,
                           void (*do_mode)(void *data,
                                           const struct ssh_ttymode *mode,
                                           char *val),
			   void *data)
{
    int i;
    const struct ssh_ttymode *mode;
    char *val;

    for (i = 0; i < lenof(ssh_ttymodes); i++) {
        mode = ssh_ttymodes + i;
	/* Every mode known to the current version of the code should be
	 * mentioned; this was ensured when settings were loaded. */
        val = conf_get_str_str(ssh->conf, CONF_ttymodes, mode->mode);

	/*
	 * val[0] can be
	 *  - 'V', indicating that an explicit value follows it;
	 *  - 'A', indicating that we should pass the value through from
	 *    the local environment via get_ttymode; or
	 *  - 'N', indicating that we should explicitly not send this
	 *    mode.
	 */
	if (val[0] == 'A') {
	    val = get_ttymode(ssh->frontend, mode->mode);
	    if (val) {
		do_mode(data, mode, val);
		sfree(val);
	    }
	} else if (val[0] == 'V') {
            do_mode(data, mode, val + 1);              /* skip the 'V' */
	} /* else 'N', or something from the future we don't understand */
    }
}

static int ssh_channelcmp(void *av, void *bv)
{
    struct ssh_channel *a = (struct ssh_channel *) av;
    struct ssh_channel *b = (struct ssh_channel *) bv;
    if (a->localid < b->localid)
	return -1;
    if (a->localid > b->localid)
	return +1;
    return 0;
}
static int ssh_channelfind(void *av, void *bv)
{
    unsigned *a = (unsigned *) av;
    struct ssh_channel *b = (struct ssh_channel *) bv;
    if (*a < b->localid)
	return -1;
    if (*a > b->localid)
	return +1;
    return 0;
}

static int ssh_rportcmp_ssh1(void *av, void *bv)
{
    struct ssh_rportfwd *a = (struct ssh_rportfwd *) av;
    struct ssh_rportfwd *b = (struct ssh_rportfwd *) bv;
    int i;
    if ( (i = strcmp(a->dhost, b->dhost)) != 0)
	return i < 0 ? -1 : +1;
    if (a->dport > b->dport)
	return +1;
    if (a->dport < b->dport)
	return -1;
    return 0;
}

static int ssh_rportcmp_ssh2(void *av, void *bv)
{
    struct ssh_rportfwd *a = (struct ssh_rportfwd *) av;
    struct ssh_rportfwd *b = (struct ssh_rportfwd *) bv;
    int i;
    if ( (i = strcmp(a->shost, b->shost)) != 0)
	return i < 0 ? -1 : +1;
    if (a->sport > b->sport)
	return +1;
    if (a->sport < b->sport)
	return -1;
    return 0;
}

/*
 * Special form of strcmp which can cope with NULL inputs. NULL is
 * defined to sort before even the empty string.
 */
static int nullstrcmp(const char *a, const char *b)
{
    if (a == NULL && b == NULL)
	return 0;
    if (a == NULL)
	return -1;
    if (b == NULL)
	return +1;
    return strcmp(a, b);
}

static int ssh_portcmp(void *av, void *bv)
{
    struct ssh_portfwd *a = (struct ssh_portfwd *) av;
    struct ssh_portfwd *b = (struct ssh_portfwd *) bv;
    int i;
    if (a->type > b->type)
	return +1;
    if (a->type < b->type)
	return -1;
    if (a->addressfamily > b->addressfamily)
	return +1;
    if (a->addressfamily < b->addressfamily)
	return -1;
    if ( (i = nullstrcmp(a->saddr, b->saddr)) != 0)
	return i < 0 ? -1 : +1;
    if (a->sport > b->sport)
	return +1;
    if (a->sport < b->sport)
	return -1;
    if (a->type != 'D') {
	if ( (i = nullstrcmp(a->daddr, b->daddr)) != 0)
	    return i < 0 ? -1 : +1;
	if (a->dport > b->dport)
	    return +1;
	if (a->dport < b->dport)
	    return -1;
    }
    return 0;
}

static int alloc_channel_id(Ssh ssh)
{
    const unsigned CHANNEL_NUMBER_OFFSET = 256;
    unsigned low, high, mid;
    int tsize;
    struct ssh_channel *c;

    /*
     * logically_frozen is true if we're not currently _processing_
     * data from the SSH socket (e.g. because a higher layer has asked
     * us not to due to ssh_throttle_conn). socket_frozen is true if
     * we're not even _reading_ data from the socket (i.e. it should
     * always match the value we last passed to sk_set_frozen).
     *
     * The two differ in that socket_frozen can also become
     * temporarily true because of a large backlog in the in_raw
     * bufchain, to force no further plug_receive events until the BPP
     * input function has had a chance to run. (Some front ends, like
     * GTK, can persistently call the network and never get round to
     * the toplevel callbacks.) If we've stopped reading from the
     * socket for that reason, we absolutely _do_ want to carry on
     * processing our input bufchain, because that's the only way
     * it'll ever get cleared!
     *
     * ssh_check_frozen() resets socket_frozen, and should be called
     * whenever either of logically_frozen and the bufchain size
     * changes.
     */
    bool logically_frozen, socket_frozen;

    /* in case we find these out before we have a ConnectionLayer to tell */
    int term_width, term_height;

    bufchain in_raw, out_raw, user_input;
    bool pending_close;
    IdempotentCallback ic_out_raw;

    PacketLogSettings pls;
    struct DataTransferStats stats;

    /*
     * For outgoing packets, pkt->length represents the length of the
     * whole packet starting at pkt->data (including some header), and
     * pkt->body refers to the point within that where the log-worthy
     * payload begins. However, incoming packets expect pkt->length to
     * represent only the payload length (that is, it's measured from
     * pkt->body not from pkt->data). Temporarily adjust our outgoing
     * packet to conform to the incoming-packet semantics, so that we
     * can analyse it with the ssh_pkt_get functions.
     */
    pkt->length -= (pkt->body - pkt->data);
    pkt->savedpos = 0;

    if (ssh->logomitdata &&
        (pkt->type == SSH1_CMSG_STDIN_DATA ||
         pkt->type == SSH1_MSG_CHANNEL_DATA)) {
        /* "Session data" packets - omit the data string. */
        if (pkt->type == SSH1_MSG_CHANNEL_DATA)
            ssh_pkt_getuint32(pkt);    /* skip channel id */
        blanks[nblanks].offset = pkt->savedpos + 4;
        blanks[nblanks].type = PKTLOG_OMIT;
        ssh_pkt_getstring(pkt, &str, &slen);
        if (str) {
            blanks[nblanks].len = slen;
            nblanks++;
        }
    }

    if ((pkt->type == SSH1_CMSG_AUTH_PASSWORD ||
         pkt->type == SSH1_CMSG_AUTH_TIS_RESPONSE ||
         pkt->type == SSH1_CMSG_AUTH_CCARD_RESPONSE) &&
        conf_get_int(ssh->conf, CONF_logomitpass)) {
        /* If this is a password or similar packet, blank the password(s). */
        blanks[nblanks].offset = 0;
        blanks[nblanks].len = pkt->length;
        blanks[nblanks].type = PKTLOG_BLANK;
        nblanks++;
    } else if (pkt->type == SSH1_CMSG_X11_REQUEST_FORWARDING &&
               conf_get_int(ssh->conf, CONF_logomitpass)) {
        /*
         * If this is an X forwarding request packet, blank the fake
         * auth data.
         *
         * Note that while we blank the X authentication data here, we
         * don't take any special action to blank the start of an X11
         * channel, so using MIT-MAGIC-COOKIE-1 and actually opening
         * an X connection without having session blanking enabled is
         * likely to leak your cookie into the log.
         */
        pkt->savedpos = 0;
        ssh_pkt_getstring(pkt, &str, &slen);
        blanks[nblanks].offset = pkt->savedpos;
        blanks[nblanks].type = PKTLOG_BLANK;
        ssh_pkt_getstring(pkt, &str, &slen);
        if (str) {
            blanks[nblanks].len = pkt->savedpos - blanks[nblanks].offset;
            nblanks++;
        }
    }

    log_packet(ssh->logctx, PKT_OUTGOING, pkt->data[12],
               ssh1_pkt_type(pkt->data[12]),
               pkt->body, pkt->length,
               nblanks, blanks, NULL, 0, NULL);

    /*
     * Undo the above adjustment of pkt->length, to put the packet
     * back in the state we found it.
     */
    pkt->length += (pkt->body - pkt->data);
}

/*
 * Collect incoming data in the incoming packet buffer.
 * Decipher and verify the packet when it is completely read.
 * Drop SSH1_MSG_DEBUG and SSH1_MSG_IGNORE packets.
 * Update the *data and *datalen variables.
 * Return a Packet structure when a packet is completed.
 */
static struct Packet *ssh1_rdpkt(Ssh ssh, const unsigned char **data,
                                 int *datalen)
{
    struct rdpkt1_state_tag *st = &ssh->rdpkt1_state;

    crBegin(ssh->ssh1_rdpkt_crstate);

    st->pktin = ssh_new_packet();

    st->pktin->type = 0;
    st->pktin->length = 0;

    for (st->i = st->len = 0; st->i < 4; st->i++) {
	while ((*datalen) == 0)
	    crReturn(NULL);
	st->len = (st->len << 8) + **data;
	(*data)++, (*datalen)--;
    }

    st->pad = 8 - (st->len % 8);
    st->biglen = st->len + st->pad;
    st->pktin->length = st->len - 5;

    if (st->biglen < 0) {
        bombout(("Extremely large packet length from server suggests"
		 " data stream corruption"));
	ssh_free_packet(st->pktin);
        crStop(NULL);
    }

    st->pktin->maxlen = st->biglen;
    st->pktin->data = snewn(st->biglen + APIEXTRA, unsigned char);

    st->to_read = st->biglen;
    st->p = st->pktin->data;
    while (st->to_read > 0) {
	st->chunk = st->to_read;
	while ((*datalen) == 0)
	    crReturn(NULL);
	if (st->chunk > (*datalen))
	    st->chunk = (*datalen);
	memcpy(st->p, *data, st->chunk);
	*data += st->chunk;
	*datalen -= st->chunk;
	st->p += st->chunk;
	st->to_read -= st->chunk;
    }

    if (ssh->cipher && detect_attack(ssh->crcda_ctx, st->pktin->data,
				     st->biglen, NULL)) {
        bombout(("Network attack (CRC compensation) detected!"));
	ssh_free_packet(st->pktin);
        crStop(NULL);
    }

    if (ssh->cipher)
	ssh->cipher->decrypt(ssh->v1_cipher_ctx, st->pktin->data, st->biglen);

    st->realcrc = crc32_compute(st->pktin->data, st->biglen - 4);
    st->gotcrc = GET_32BIT(st->pktin->data + st->biglen - 4);
    if (st->gotcrc != st->realcrc) {
	bombout(("Incorrect CRC received on packet"));
	ssh_free_packet(st->pktin);
	crStop(NULL);
    }

    st->pktin->body = st->pktin->data + st->pad + 1;

    if (ssh->v1_compressing) {
	unsigned char *decompblk;
	int decomplen;
	if (!zlib_decompress_block(ssh->sc_comp_ctx,
				   st->pktin->body - 1, st->pktin->length + 1,
				   &decompblk, &decomplen)) {
	    bombout(("Zlib decompression encountered invalid data"));
	    ssh_free_packet(st->pktin);
	    crStop(NULL);
	}

	if (st->pktin->maxlen < st->pad + decomplen) {
	    st->pktin->maxlen = st->pad + decomplen;
	    st->pktin->data = sresize(st->pktin->data,
				      st->pktin->maxlen + APIEXTRA,
				      unsigned char);
	    st->pktin->body = st->pktin->data + st->pad + 1;
	}

	memcpy(st->pktin->body - 1, decompblk, decomplen);
	sfree(decompblk);
	st->pktin->length = decomplen - 1;
    }

    st->pktin->type = st->pktin->body[-1];

    /*
     * Now pktin->body and pktin->length identify the semantic content
     * of the packet, excluding the initial type byte.
     */

    if (ssh->logctx)
        ssh1_log_incoming_packet(ssh, st->pktin);

    st->pktin->savedpos = 0;

    crFinish(st->pktin);
}

static void ssh2_log_incoming_packet(Ssh ssh, struct Packet *pkt)
{
    int nblanks = 0;
    struct logblank_t blanks[4];
    char *str;
    int slen;

    pkt->savedpos = 0;

    if (ssh->logomitdata &&
        (pkt->type == SSH2_MSG_CHANNEL_DATA ||
         pkt->type == SSH2_MSG_CHANNEL_EXTENDED_DATA)) {
        /* "Session data" packets - omit the data string. */
        ssh_pkt_getuint32(pkt);    /* skip channel id */
        if (pkt->type == SSH2_MSG_CHANNEL_EXTENDED_DATA)
            ssh_pkt_getuint32(pkt);    /* skip extended data type */
        blanks[nblanks].offset = pkt->savedpos + 4;
        blanks[nblanks].type = PKTLOG_OMIT;
        ssh_pkt_getstring(pkt, &str, &slen);
        if (str) {
            blanks[nblanks].len = slen;
            nblanks++;
        }
    }

    log_packet(ssh->logctx, PKT_INCOMING, pkt->type,
               ssh2_pkt_type(ssh->pkt_kctx, ssh->pkt_actx, pkt->type),
               pkt->body, pkt->length, nblanks, blanks, &pkt->sequence,
               0, NULL);
}

static void ssh2_log_outgoing_packet(Ssh ssh, struct Packet *pkt)
{
    int nblanks = 0;
    struct logblank_t blanks[4];
    char *str;
    int slen;

    /*
     * For outgoing packets, pkt->length represents the length of the
     * whole packet starting at pkt->data (including some header), and
     * pkt->body refers to the point within that where the log-worthy
     * payload begins. However, incoming packets expect pkt->length to
     * represent only the payload length (that is, it's measured from
     * pkt->body not from pkt->data). Temporarily adjust our outgoing
     * packet to conform to the incoming-packet semantics, so that we
     * can analyse it with the ssh_pkt_get functions.
     */
    pkt->length -= (pkt->body - pkt->data);
    pkt->savedpos = 0;

    if (ssh->logomitdata &&
        (pkt->type == SSH2_MSG_CHANNEL_DATA ||
         pkt->type == SSH2_MSG_CHANNEL_EXTENDED_DATA)) {
        /* "Session data" packets - omit the data string. */
        ssh_pkt_getuint32(pkt);    /* skip channel id */
        if (pkt->type == SSH2_MSG_CHANNEL_EXTENDED_DATA)
            ssh_pkt_getuint32(pkt);    /* skip extended data type */
        blanks[nblanks].offset = pkt->savedpos + 4;
        blanks[nblanks].type = PKTLOG_OMIT;
        ssh_pkt_getstring(pkt, &str, &slen);
        if (str) {
            blanks[nblanks].len = slen;
            nblanks++;
        }
    }

    if (pkt->type == SSH2_MSG_USERAUTH_REQUEST &&
        conf_get_int(ssh->conf, CONF_logomitpass)) {
        /* If this is a password packet, blank the password(s). */
        pkt->savedpos = 0;
        ssh_pkt_getstring(pkt, &str, &slen);
        ssh_pkt_getstring(pkt, &str, &slen);
        ssh_pkt_getstring(pkt, &str, &slen);
        if (slen == 8 && !memcmp(str, "password", 8)) {
            ssh2_pkt_getbool(pkt);
            /* Blank the password field. */
            blanks[nblanks].offset = pkt->savedpos;
            blanks[nblanks].type = PKTLOG_BLANK;
            ssh_pkt_getstring(pkt, &str, &slen);
            if (str) {
                blanks[nblanks].len = pkt->savedpos - blanks[nblanks].offset;
                nblanks++;
                /* If there's another password field beyond it (change of
                 * password), blank that too. */
                ssh_pkt_getstring(pkt, &str, &slen);
                if (str)
                    blanks[nblanks-1].len =
                        pkt->savedpos - blanks[nblanks].offset;
            }
        }
    } else if (ssh->pkt_actx == SSH2_PKTCTX_KBDINTER &&
               pkt->type == SSH2_MSG_USERAUTH_INFO_RESPONSE &&
               conf_get_int(ssh->conf, CONF_logomitpass)) {
        /* If this is a keyboard-interactive response packet, blank
         * the responses. */
        pkt->savedpos = 0;
        ssh_pkt_getuint32(pkt);
        blanks[nblanks].offset = pkt->savedpos;
        blanks[nblanks].type = PKTLOG_BLANK;
        while (1) {
            ssh_pkt_getstring(pkt, &str, &slen);
            if (!str)
                break;
        }
        blanks[nblanks].len = pkt->savedpos - blanks[nblanks].offset;
        nblanks++;
    } else if (pkt->type == SSH2_MSG_CHANNEL_REQUEST &&
               conf_get_int(ssh->conf, CONF_logomitpass)) {
        /*
         * If this is an X forwarding request packet, blank the fake
         * auth data.
         *
         * Note that while we blank the X authentication data here, we
         * don't take any special action to blank the start of an X11
         * channel, so using MIT-MAGIC-COOKIE-1 and actually opening
         * an X connection without having session blanking enabled is
         * likely to leak your cookie into the log.
         */
        pkt->savedpos = 0;
        ssh_pkt_getuint32(pkt);
        ssh_pkt_getstring(pkt, &str, &slen);
        if (slen == 7 && !memcmp(str, "x11-req", 0)) {
            ssh2_pkt_getbool(pkt);
            ssh2_pkt_getbool(pkt);
            ssh_pkt_getstring(pkt, &str, &slen);
            blanks[nblanks].offset = pkt->savedpos;
            blanks[nblanks].type = PKTLOG_BLANK;
            ssh_pkt_getstring(pkt, &str, &slen);
            if (str) {
                blanks[nblanks].len = pkt->savedpos - blanks[nblanks].offset;
                nblanks++;
            }
        }
    }

    log_packet(ssh->logctx, PKT_OUTGOING, pkt->data[5],
               ssh2_pkt_type(ssh->pkt_kctx, ssh->pkt_actx, pkt->data[5]),
               pkt->body, pkt->length, nblanks, blanks,
               &ssh->v2_outgoing_sequence,
               pkt->downstream_id, pkt->additional_log_text);

    /*
     * Undo the above adjustment of pkt->length, to put the packet
     * back in the state we found it.
     */
    pkt->length += (pkt->body - pkt->data);
}

static struct Packet *ssh2_rdpkt(Ssh ssh, const unsigned char **data,
                                 int *datalen)
{
    struct rdpkt2_state_tag *st = &ssh->rdpkt2_state;

    crBegin(ssh->ssh2_rdpkt_crstate);

    st->pktin = ssh_new_packet();

    st->pktin->type = 0;
    st->pktin->length = 0;
    if (ssh->sccipher)
	st->cipherblk = ssh->sccipher->blksize;
    else
	st->cipherblk = 8;
    if (st->cipherblk < 8)
	st->cipherblk = 8;
    st->maclen = ssh->scmac ? ssh->scmac->len : 0;

    if (ssh->sccipher && (ssh->sccipher->flags & SSH_CIPHER_IS_CBC) &&
	ssh->scmac && !ssh->scmac_etm) {
	/*
	 * When dealing with a CBC-mode cipher, we want to avoid the
	 * possibility of an attacker's tweaking the ciphertext stream
	 * so as to cause us to feed the same block to the block
	 * cipher more than once and thus leak information
	 * (VU#958563).  The way we do this is not to take any
	 * decisions on the basis of anything we've decrypted until
	 * we've verified it with a MAC.  That includes the packet
	 * length, so we just read data and check the MAC repeatedly,
	 * and when the MAC passes, see if the length we've got is
	 * plausible.
         *
         * This defence is unnecessary in OpenSSH ETM mode, because
         * the whole point of ETM mode is that the attacker can't
         * tweak the ciphertext stream at all without the MAC
         * detecting it before we decrypt anything.
	 */

	/* May as well allocate the whole lot now. */
	st->pktin->data = snewn(OUR_V2_PACKETLIMIT + st->maclen + APIEXTRA,
				unsigned char);

	/* Read an amount corresponding to the MAC. */
	for (st->i = 0; st->i < st->maclen; st->i++) {
	    while ((*datalen) == 0)
		crReturn(NULL);
	    st->pktin->data[st->i] = *(*data)++;
	    (*datalen)--;
	}

	st->packetlen = 0;
	{
	    unsigned char seq[4];
	    ssh->scmac->start(ssh->sc_mac_ctx);
	    PUT_32BIT(seq, st->incoming_sequence);
	    ssh->scmac->bytes(ssh->sc_mac_ctx, seq, 4);
	}

	for (;;) { /* Once around this loop per cipher block. */
	    /* Read another cipher-block's worth, and tack it onto the end. */
	    for (st->i = 0; st->i < st->cipherblk; st->i++) {
		while ((*datalen) == 0)
		    crReturn(NULL);
		st->pktin->data[st->packetlen+st->maclen+st->i] = *(*data)++;
		(*datalen)--;
	    }
	    /* Decrypt one more block (a little further back in the stream). */
	    ssh->sccipher->decrypt(ssh->sc_cipher_ctx,
				   st->pktin->data + st->packetlen,
				   st->cipherblk);
	    /* Feed that block to the MAC. */
	    ssh->scmac->bytes(ssh->sc_mac_ctx,
			      st->pktin->data + st->packetlen, st->cipherblk);
	    st->packetlen += st->cipherblk;
	    /* See if that gives us a valid packet. */
	    if (ssh->scmac->verresult(ssh->sc_mac_ctx,
				      st->pktin->data + st->packetlen) &&
		((st->len = toint(GET_32BIT(st->pktin->data))) ==
                 st->packetlen-4))
		    break;
	    if (st->packetlen >= OUR_V2_PACKETLIMIT) {
		bombout(("No valid incoming packet found"));
		ssh_free_packet(st->pktin);
		crStop(NULL);
	    }	    
	}
	st->pktin->maxlen = st->packetlen + st->maclen;
	st->pktin->data = sresize(st->pktin->data,
				  st->pktin->maxlen + APIEXTRA,
				  unsigned char);
    } else if (ssh->scmac && ssh->scmac_etm) {
	st->pktin->data = snewn(4 + APIEXTRA, unsigned char);

        /*
         * OpenSSH encrypt-then-MAC mode: the packet length is
         * unencrypted, unless the cipher supports length encryption.
         */
	for (st->i = st->len = 0; st->i < 4; st->i++) {
	    while ((*datalen) == 0)
		crReturn(NULL);
	    st->pktin->data[st->i] = *(*data)++;
	    (*datalen)--;
	}
        /* Cipher supports length decryption, so do it */
        if (ssh->sccipher && (ssh->sccipher->flags & SSH_CIPHER_SEPARATE_LENGTH)) {
            /* Keep the packet the same though, so the MAC passes */
            unsigned char len[4];
            memcpy(len, st->pktin->data, 4);
            ssh->sccipher->decrypt_length(ssh->sc_cipher_ctx, len, 4, st->incoming_sequence);
            st->len = toint(GET_32BIT(len));
        } else {
            st->len = toint(GET_32BIT(st->pktin->data));
        }

	/*
	 * _Completely_ silly lengths should be stomped on before they
	 * do us any more damage.
	 */
	if (st->len < 0 || st->len > OUR_V2_PACKETLIMIT ||
	    st->len % st->cipherblk != 0) {
	    bombout(("Incoming packet length field was garbled"));
	    ssh_free_packet(st->pktin);
	    crStop(NULL);
	}

	/*
	 * So now we can work out the total packet length.
	 */
	st->packetlen = st->len + 4;

	/*
	 * Allocate memory for the rest of the packet.
	 */
	st->pktin->maxlen = st->packetlen + st->maclen;
	st->pktin->data = sresize(st->pktin->data,
				  st->pktin->maxlen + APIEXTRA,
				  unsigned char);

	/*
	 * Read the remainder of the packet.
	 */
	for (st->i = 4; st->i < st->packetlen + st->maclen; st->i++) {
	    while ((*datalen) == 0)
		crReturn(NULL);
	    st->pktin->data[st->i] = *(*data)++;
	    (*datalen)--;
	}

	/*
	 * Check the MAC.
	 */
	if (ssh->scmac
	    && !ssh->scmac->verify(ssh->sc_mac_ctx, st->pktin->data,
				   st->len + 4, st->incoming_sequence)) {
	    bombout(("Incorrect MAC received on packet"));
	    ssh_free_packet(st->pktin);
	    crStop(NULL);
	}

	/* Decrypt everything between the length field and the MAC. */
	if (ssh->sccipher)
	    ssh->sccipher->decrypt(ssh->sc_cipher_ctx,
				   st->pktin->data + 4,
				   st->packetlen - 4);
    } else {
	st->pktin->data = snewn(st->cipherblk + APIEXTRA, unsigned char);

	/*
	 * Acquire and decrypt the first block of the packet. This will
	 * contain the length and padding details.
	 */
	for (st->i = st->len = 0; st->i < st->cipherblk; st->i++) {
	    while ((*datalen) == 0)
		crReturn(NULL);
	    st->pktin->data[st->i] = *(*data)++;
	    (*datalen)--;
	}

	if (ssh->sccipher)
	    ssh->sccipher->decrypt(ssh->sc_cipher_ctx,
				   st->pktin->data, st->cipherblk);

	/*
	 * Now get the length figure.
	 */
	st->len = toint(GET_32BIT(st->pktin->data));

	/*
	 * _Completely_ silly lengths should be stomped on before they
	 * do us any more damage.
	 */
	if (st->len < 0 || st->len > OUR_V2_PACKETLIMIT ||
	    (st->len + 4) % st->cipherblk != 0) {
	    bombout(("Incoming packet was garbled on decryption"));
	    ssh_free_packet(st->pktin);
	    crStop(NULL);
	}

	/*
	 * So now we can work out the total packet length.
	 */
	st->packetlen = st->len + 4;

	/*
	 * Allocate memory for the rest of the packet.
	 */
	st->pktin->maxlen = st->packetlen + st->maclen;
	st->pktin->data = sresize(st->pktin->data,
				  st->pktin->maxlen + APIEXTRA,
				  unsigned char);

	/*
	 * Read and decrypt the remainder of the packet.
	 */
	for (st->i = st->cipherblk; st->i < st->packetlen + st->maclen;
	     st->i++) {
	    while ((*datalen) == 0)
		crReturn(NULL);
	    st->pktin->data[st->i] = *(*data)++;
	    (*datalen)--;
	}
	/* Decrypt everything _except_ the MAC. */
	if (ssh->sccipher)
	    ssh->sccipher->decrypt(ssh->sc_cipher_ctx,
				   st->pktin->data + st->cipherblk,
				   st->packetlen - st->cipherblk);

	/*
	 * Check the MAC.
	 */
	if (ssh->scmac
	    && !ssh->scmac->verify(ssh->sc_mac_ctx, st->pktin->data,
				   st->len + 4, st->incoming_sequence)) {
	    bombout(("Incorrect MAC received on packet"));
	    ssh_free_packet(st->pktin);
	    crStop(NULL);
	}
    }
    /* Get and sanity-check the amount of random padding. */
    st->pad = st->pktin->data[4];
    if (st->pad < 4 || st->len - st->pad < 1) {
	bombout(("Invalid padding length on received packet"));
	ssh_free_packet(st->pktin);
	crStop(NULL);
    }
    /*
     * This enables us to deduce the payload length.
     */
    st->payload = st->len - st->pad - 1;

    st->pktin->length = st->payload + 5;
    st->pktin->encrypted_len = st->packetlen;

    st->pktin->sequence = st->incoming_sequence++;

    st->pktin->length = st->packetlen - st->pad;
    assert(st->pktin->length >= 0);

    /*
     * Decompress packet payload.
     */
    {
	unsigned char *newpayload;
	int newlen;
	if (ssh->sccomp &&
	    ssh->sccomp->decompress(ssh->sc_comp_ctx,
				    st->pktin->data + 5, st->pktin->length - 5,
				    &newpayload, &newlen)) {
	    if (st->pktin->maxlen < newlen + 5) {
		st->pktin->maxlen = newlen + 5;
		st->pktin->data = sresize(st->pktin->data,
					  st->pktin->maxlen + APIEXTRA,
					  unsigned char);
	    }
	    st->pktin->length = 5 + newlen;
	    memcpy(st->pktin->data + 5, newpayload, newlen);
	    sfree(newpayload);
	}
    }

    /*
     * RFC 4253 doesn't explicitly say that completely empty packets
     * with no type byte are forbidden, so treat them as deserving
     * an SSH_MSG_UNIMPLEMENTED.
     */
    if (st->pktin->length <= 5) { /* == 5 we hope, but robustness */
        ssh2_msg_something_unimplemented(ssh, st->pktin);
        crStop(NULL);
    }
    /*
     * pktin->body and pktin->length should identify the semantic
     * content of the packet, excluding the initial type byte.
     */
    st->pktin->type = st->pktin->data[5];
    st->pktin->body = st->pktin->data + 6;
    st->pktin->length -= 6;
    assert(st->pktin->length >= 0);    /* one last double-check */

    if (ssh->logctx)
        ssh2_log_incoming_packet(ssh, st->pktin);

    st->pktin->savedpos = 0;

    crFinish(st->pktin);
}

static struct Packet *ssh2_bare_connection_rdpkt(Ssh ssh,
                                                 const unsigned char **data,
                                                 int *datalen)
{
    struct rdpkt2_bare_state_tag *st = &ssh->rdpkt2_bare_state;

    crBegin(ssh->ssh2_bare_rdpkt_crstate);

    /*
     * Read the packet length field.
     */
    for (st->i = 0; st->i < 4; st->i++) {
        while ((*datalen) == 0)
            crReturn(NULL);
        st->length[st->i] = *(*data)++;
        (*datalen)--;
    }

    st->packetlen = toint(GET_32BIT_MSB_FIRST(st->length));
    if (st->packetlen <= 0 || st->packetlen >= OUR_V2_PACKETLIMIT) {
        bombout(("Invalid packet length received"));
        crStop(NULL);
    }

    st->pktin = ssh_new_packet();
    st->pktin->data = snewn(st->packetlen, unsigned char);

    st->pktin->encrypted_len = st->packetlen;

    st->pktin->sequence = st->incoming_sequence++;

    /*
     * Read the remainder of the packet.
     */
    for (st->i = 0; st->i < st->packetlen; st->i++) {
        while ((*datalen) == 0)
            crReturn(NULL);
        st->pktin->data[st->i] = *(*data)++;
        (*datalen)--;
    }

    /*
     * pktin->body and pktin->length should identify the semantic
     * content of the packet, excluding the initial type byte.
     */
    st->pktin->type = st->pktin->data[0];
    st->pktin->body = st->pktin->data + 1;
    st->pktin->length = st->packetlen - 1;

    /*
     * Log incoming packet, possibly omitting sensitive fields.
     */
    if (ssh->logctx)
        ssh2_log_incoming_packet(ssh, st->pktin);

    st->pktin->savedpos = 0;

    crFinish(st->pktin);
}

static int s_wrpkt_prepare(Ssh ssh, struct Packet *pkt, int *offset_p)
{
    int pad, biglen, i, pktoffs;
    unsigned long crc;
#ifdef __SC__
    /*
     * XXX various versions of SC (including 8.8.4) screw up the
     * register allocation in this function and use the same register
     * (D6) for len and as a temporary, with predictable results.  The
     * following sledgehammer prevents this.
     */
    volatile
#endif
    int len;

    if (ssh->logctx)
        ssh1_log_outgoing_packet(ssh, pkt);

    if (ssh->v1_compressing) {
	unsigned char *compblk;
	int complen;
	zlib_compress_block(ssh->cs_comp_ctx,
			    pkt->data + 12, pkt->length - 12,
			    &compblk, &complen);
	ssh_pkt_ensure(pkt, complen + 2);   /* just in case it's got bigger */
	memcpy(pkt->data + 12, compblk, complen);
	sfree(compblk);
	pkt->length = complen + 12;
    }

    ssh_pkt_ensure(pkt, pkt->length + 4); /* space for CRC */
    pkt->length += 4;
    len = pkt->length - 4 - 8;	/* len(type+data+CRC) */
    pad = 8 - (len % 8);
    pktoffs = 8 - pad;
    biglen = len + pad;		/* len(padding+type+data+CRC) */

    for (i = pktoffs; i < 4+8; i++)
	pkt->data[i] = random_byte();
    crc = crc32_compute(pkt->data + pktoffs + 4, biglen - 4); /* all ex len */
    PUT_32BIT(pkt->data + pktoffs + 4 + biglen - 4, crc);
    PUT_32BIT(pkt->data + pktoffs, len);

    if (ssh->cipher)
	ssh->cipher->encrypt(ssh->v1_cipher_ctx,
			     pkt->data + pktoffs + 4, biglen);

    if (offset_p) *offset_p = pktoffs;
    return biglen + 4;		/* len(length+padding+type+data+CRC) */
}

static int s_write(Ssh ssh, void *data, int len)
{
    if (ssh->logctx)
	log_packet(ssh->logctx, PKT_OUTGOING, -1, NULL, data, len,
		   0, NULL, NULL, 0, NULL);
    if (!ssh->s)
        return 0;
    return sk_write(ssh->s, (char *)data, len);
}

static void s_wrpkt(Ssh ssh, struct Packet *pkt)
{
    int len, backlog, offset;
    len = s_wrpkt_prepare(ssh, pkt, &offset);
    backlog = s_write(ssh, pkt->data + offset, len);
    if (backlog > SSH_MAX_BACKLOG)
	ssh_throttle_all(ssh, 1, backlog);
    ssh_free_packet(pkt);
}

static void s_wrpkt_defer(Ssh ssh, struct Packet *pkt)
{
    int len, offset;
    len = s_wrpkt_prepare(ssh, pkt, &offset);
    if (ssh->deferred_len + len > ssh->deferred_size) {
	ssh->deferred_size = ssh->deferred_len + len + 128;
	ssh->deferred_send_data = sresize(ssh->deferred_send_data,
					  ssh->deferred_size,
					  unsigned char);
    }
    memcpy(ssh->deferred_send_data + ssh->deferred_len,
	   pkt->data + offset, len);
    ssh->deferred_len += len;
    ssh_free_packet(pkt);
}

/*
 * Construct a SSH-1 packet with the specified contents.
 * (This all-at-once interface used to be the only one, but now SSH-1
 * packets can also be constructed incrementally.)
 */
static struct Packet *construct_packet(Ssh ssh, int pkttype, va_list ap)
{
    int argtype;
    Bignum bn;
    struct Packet *pkt;

    pkt = ssh1_pkt_init(pkttype);

    while ((argtype = va_arg(ap, int)) != PKT_END) {
	unsigned char *argp, argchar;
	char *sargp;
	unsigned long argint;
	int arglen;
	switch (argtype) {
	  /* Actual fields in the packet */
	  case PKT_INT:
	    argint = va_arg(ap, int);
	    ssh_pkt_adduint32(pkt, argint);
	    break;
	  case PKT_CHAR:
	    argchar = (unsigned char) va_arg(ap, int);
	    ssh_pkt_addbyte(pkt, argchar);
	    break;
	  case PKT_DATA:
	    argp = va_arg(ap, unsigned char *);
	    arglen = va_arg(ap, int);
	    ssh_pkt_adddata(pkt, argp, arglen);
	    break;
	  case PKT_STR:
	    sargp = va_arg(ap, char *);
	    ssh_pkt_addstring(pkt, sargp);
	    break;
	  case PKT_BIGNUM:
	    bn = va_arg(ap, Bignum);
	    ssh1_pkt_addmp(pkt, bn);
	    break;
	}
    }

    return pkt;
}

static void send_packet(Ssh ssh, int pkttype, ...)
{
    struct Packet *pkt;
    va_list ap;
    va_start(ap, pkttype);
    pkt = construct_packet(ssh, pkttype, ap);
    va_end(ap);
    s_wrpkt(ssh, pkt);
}

static void defer_packet(Ssh ssh, int pkttype, ...)
{
    struct Packet *pkt;
    va_list ap;
    va_start(ap, pkttype);
    pkt = construct_packet(ssh, pkttype, ap);
    va_end(ap);
    s_wrpkt_defer(ssh, pkt);
}

static int ssh_versioncmp(const char *a, const char *b)
{
    char *ae, *be;
    unsigned long av, bv;

    av = strtoul(a, &ae, 10);
    bv = strtoul(b, &be, 10);
    if (av != bv)
	return (av < bv ? -1 : +1);
    if (*ae == '.')
	ae++;
    if (*be == '.')
	be++;
    av = strtoul(ae, &ae, 10);
    bv = strtoul(be, &be, 10);
    if (av != bv)
	return (av < bv ? -1 : +1);
    return 0;
}

/*
 * Utility routines for putting an SSH-protocol `string' and
 * `uint32' into a hash state.
 */
static void hash_string(const struct ssh_hash *h, void *s, void *str, int len)
{
    unsigned char lenblk[4];
    PUT_32BIT(lenblk, len);
    h->bytes(s, lenblk, 4);
    h->bytes(s, str, len);
}

static void hash_uint32(const struct ssh_hash *h, void *s, unsigned i)
{
    unsigned char intblk[4];
    PUT_32BIT(intblk, i);
    h->bytes(s, intblk, 4);
}

/*
 * Packet construction functions. Mostly shared between SSH-1 and SSH-2.
 */
static void ssh_pkt_ensure(struct Packet *pkt, int length)
{
    if (pkt->maxlen < length) {
	unsigned char *body = pkt->body;
	int offset = body ? body - pkt->data : 0;
	pkt->maxlen = length + 256;
	pkt->data = sresize(pkt->data, pkt->maxlen + APIEXTRA, unsigned char);
	if (body) pkt->body = pkt->data + offset;
    }
}
static void ssh_pkt_adddata(struct Packet *pkt, const void *data, int len)
{
    pkt->length += len;
    ssh_pkt_ensure(pkt, pkt->length);
    memcpy(pkt->data + pkt->length - len, data, len);
}
static void ssh_pkt_addbyte(struct Packet *pkt, unsigned char byte)
{
    ssh_pkt_adddata(pkt, &byte, 1);
}
static void ssh2_pkt_addbool(struct Packet *pkt, unsigned char value)
{
    ssh_pkt_adddata(pkt, &value, 1);
}
static void ssh_pkt_adduint32(struct Packet *pkt, unsigned long value)
{
    unsigned char x[4];
    PUT_32BIT(x, value);
    ssh_pkt_adddata(pkt, x, 4);
}
static void ssh_pkt_addstring_start(struct Packet *pkt)
{
    ssh_pkt_adduint32(pkt, 0);
    pkt->savedpos = pkt->length;
}
static void ssh_pkt_addstring_data(struct Packet *pkt, const char *data,
                                   int len)
{
    ssh_pkt_adddata(pkt, data, len);
    PUT_32BIT(pkt->data + pkt->savedpos - 4, pkt->length - pkt->savedpos);
}
static void ssh_pkt_addstring_str(struct Packet *pkt, const char *data)
{
  ssh_pkt_addstring_data(pkt, data, strlen(data));
}
static void ssh_pkt_addstring(struct Packet *pkt, const char *data)
{
    ssh_pkt_addstring_start(pkt);
    ssh_pkt_addstring_str(pkt, data);
}
static void ssh1_pkt_addmp(struct Packet *pkt, Bignum b)
{
    int len = ssh1_bignum_length(b);
    unsigned char *data = snewn(len, unsigned char);
    (void) ssh1_write_bignum(data, b);
    ssh_pkt_adddata(pkt, data, len);
    sfree(data);
}
static unsigned char *ssh2_mpint_fmt(Bignum b, int *len)
{
    unsigned char *p;
    int i, n = (bignum_bitcount(b) + 7) / 8;
    p = snewn(n + 1, unsigned char);
    p[0] = 0;
    for (i = 1; i <= n; i++)
	p[i] = bignum_byte(b, n - i);
    i = 0;
    while (i <= n && p[i] == 0 && (p[i + 1] & 0x80) == 0)
	i++;
    memmove(p, p + i, n + 1 - i);
    *len = n + 1 - i;
    return p;
}
static void ssh2_pkt_addmp(struct Packet *pkt, Bignum b)
{
    unsigned char *p;
    int len;
    p = ssh2_mpint_fmt(b, &len);
    ssh_pkt_addstring_start(pkt);
    ssh_pkt_addstring_data(pkt, (char *)p, len);
    sfree(p);
}

static struct Packet *ssh1_pkt_init(int pkt_type)
{
    struct Packet *pkt = ssh_new_packet();
    pkt->length = 4 + 8;	    /* space for length + max padding */
    ssh_pkt_addbyte(pkt, pkt_type);
    pkt->body = pkt->data + pkt->length;
    pkt->type = pkt_type;
    pkt->downstream_id = 0;
    pkt->additional_log_text = NULL;
    return pkt;
}

/* For legacy code (SSH-1 and -2 packet construction used to be separate) */
#define ssh2_pkt_ensure(pkt, length) ssh_pkt_ensure(pkt, length)
#define ssh2_pkt_adddata(pkt, data, len) ssh_pkt_adddata(pkt, data, len)
#define ssh2_pkt_addbyte(pkt, byte) ssh_pkt_addbyte(pkt, byte)
#define ssh2_pkt_adduint32(pkt, value) ssh_pkt_adduint32(pkt, value)
#define ssh2_pkt_addstring_start(pkt) ssh_pkt_addstring_start(pkt)
#define ssh2_pkt_addstring_str(pkt, data) ssh_pkt_addstring_str(pkt, data)
#define ssh2_pkt_addstring_data(pkt, data, len) ssh_pkt_addstring_data(pkt, data, len)
#define ssh2_pkt_addstring(pkt, data) ssh_pkt_addstring(pkt, data)

static struct Packet *ssh2_pkt_init(int pkt_type)
{
    struct Packet *pkt = ssh_new_packet();
    pkt->length = 5; /* space for packet length + padding length */
    pkt->forcepad = 0;
    pkt->type = pkt_type;
    ssh_pkt_addbyte(pkt, (unsigned char) pkt_type);
    pkt->body = pkt->data + pkt->length; /* after packet type */
    pkt->downstream_id = 0;
    pkt->additional_log_text = NULL;
    return pkt;
}

/*
 * Construct an SSH-2 final-form packet: compress it, encrypt it,
 * put the MAC on it. Final packet, ready to be sent, is stored in
 * pkt->data. Total length is returned.
 */
static int ssh2_pkt_construct(Ssh ssh, struct Packet *pkt)
{
    int cipherblk, maclen, padding, unencrypted_prefix, i;

    if (ssh->logctx)
        ssh2_log_outgoing_packet(ssh, pkt);

    if (ssh->bare_connection) {
        /*
         * Trivial packet construction for the bare connection
         * protocol.
         */
        PUT_32BIT(pkt->data + 1, pkt->length - 5);
        pkt->body = pkt->data + 1;
        ssh->v2_outgoing_sequence++;   /* only for diagnostics, really */
        return pkt->length - 1;
    }

    /*
     * Compress packet payload.
     */
    {
	unsigned char *newpayload;
	int newlen;
	if (ssh->cscomp &&
	    ssh->cscomp->compress(ssh->cs_comp_ctx, pkt->data + 5,
				  pkt->length - 5,
				  &newpayload, &newlen)) {
	    pkt->length = 5;
	    ssh2_pkt_adddata(pkt, newpayload, newlen);
	    sfree(newpayload);
	}
    }

    /*
     * Add padding. At least four bytes, and must also bring total
     * length (minus MAC) up to a multiple of the block size.
     * If pkt->forcepad is set, make sure the packet is at least that size
     * after padding.
     */
    cipherblk = ssh->cscipher ? ssh->cscipher->blksize : 8;  /* block size */
    cipherblk = cipherblk < 8 ? 8 : cipherblk;	/* or 8 if blksize < 8 */
    padding = 4;
    unencrypted_prefix = (ssh->csmac && ssh->csmac_etm) ? 4 : 0;
    if (pkt->length + padding < pkt->forcepad)
	padding = pkt->forcepad - pkt->length;
    padding +=
	(cipherblk - (pkt->length - unencrypted_prefix + padding) % cipherblk)
        % cipherblk;
    assert(padding <= 255);
    maclen = ssh->csmac ? ssh->csmac->len : 0;
    ssh2_pkt_ensure(pkt, pkt->length + padding + maclen);
    pkt->data[4] = padding;
    for (i = 0; i < padding; i++)
	pkt->data[pkt->length + i] = random_byte();
    PUT_32BIT(pkt->data, pkt->length + padding - 4);

    /* Encrypt length if the scheme requires it */
    if (ssh->cscipher && (ssh->cscipher->flags & SSH_CIPHER_SEPARATE_LENGTH)) {
        ssh->cscipher->encrypt_length(ssh->cs_cipher_ctx, pkt->data, 4,
                                      ssh->v2_outgoing_sequence);
    }

    if (ssh->csmac && ssh->csmac_etm) {
        /*
         * OpenSSH-defined encrypt-then-MAC protocol.
         */
        if (ssh->cscipher)
            ssh->cscipher->encrypt(ssh->cs_cipher_ctx,
                                   pkt->data + 4, pkt->length + padding - 4);
        ssh->csmac->generate(ssh->cs_mac_ctx, pkt->data,
                             pkt->length + padding,
                             ssh->v2_outgoing_sequence);
    } else {
        /*
         * SSH-2 standard protocol.
         */
        if (ssh->csmac)
            ssh->csmac->generate(ssh->cs_mac_ctx, pkt->data,
                                 pkt->length + padding,
                                 ssh->v2_outgoing_sequence);
        if (ssh->cscipher)
            ssh->cscipher->encrypt(ssh->cs_cipher_ctx,
                                   pkt->data, pkt->length + padding);
    }

    ssh->v2_outgoing_sequence++;       /* whether or not we MACed */
    pkt->encrypted_len = pkt->length + padding;

    /* Ready-to-send packet starts at pkt->data. We return length. */
    pkt->body = pkt->data;
    return pkt->length + padding + maclen;
}

/*
 * Routines called from the main SSH code to send packets. There
 * are quite a few of these, because we have two separate
 * mechanisms for delaying the sending of packets:
 * 
 *  - In order to send an IGNORE message and a password message in
 *    a single fixed-length blob, we require the ability to
 *    concatenate the encrypted forms of those two packets _into_ a
 *    single blob and then pass it to our <network.h> transport
 *    layer in one go. Hence, there's a deferment mechanism which
 *    works after packet encryption.
 * 
 *  - In order to avoid sending any connection-layer messages
 *    during repeat key exchange, we have to queue up any such
 *    outgoing messages _before_ they are encrypted (and in
 *    particular before they're allocated sequence numbers), and
 *    then send them once we've finished.
 * 
 * I call these mechanisms `defer' and `queue' respectively, so as
 * to distinguish them reasonably easily.
 * 
 * The functions send_noqueue() and defer_noqueue() free the packet
 * structure they are passed. Every outgoing packet goes through
 * precisely one of these functions in its life; packets passed to
 * ssh2_pkt_send() or ssh2_pkt_defer() either go straight to one of
 * these or get queued, and then when the queue is later emptied
 * the packets are all passed to defer_noqueue().
 *
 * When using a CBC-mode cipher, it's necessary to ensure that an
 * attacker can't provide data to be encrypted using an IV that they
 * know.  We ensure this by prefixing each packet that might contain
 * user data with an SSH_MSG_IGNORE.  This is done using the deferral
 * mechanism, so in this case send_noqueue() ends up redirecting to
 * defer_noqueue().  If you don't like this inefficiency, don't use
 * CBC.
 */

static void ssh2_pkt_defer_noqueue(Ssh, struct Packet *, int);
static void ssh_pkt_defersend(Ssh);

/*
 * Send an SSH-2 packet immediately, without queuing or deferring.
 */
static void ssh2_pkt_send_noqueue(Ssh ssh, struct Packet *pkt)
{
    int len;
    int backlog;
    if (ssh->cscipher != NULL && (ssh->cscipher->flags & SSH_CIPHER_IS_CBC)) {
	/* We need to send two packets, so use the deferral mechanism. */
	ssh2_pkt_defer_noqueue(ssh, pkt, FALSE);
	ssh_pkt_defersend(ssh);
	return;
    }
    len = ssh2_pkt_construct(ssh, pkt);
    backlog = s_write(ssh, pkt->body, len);
    if (backlog > SSH_MAX_BACKLOG)
	ssh_throttle_all(ssh, 1, backlog);

    ssh->outgoing_data_size += pkt->encrypted_len;
    if (!ssh->kex_in_progress &&
        !ssh->bare_connection &&
	ssh->max_data_size != 0 &&
	ssh->outgoing_data_size > ssh->max_data_size)
	do_ssh2_transport(ssh, "too much data sent", -1, NULL);

    ssh_free_packet(pkt);
}

/*
 * Defer an SSH-2 packet.
 */
static void ssh2_pkt_defer_noqueue(Ssh ssh, struct Packet *pkt, int noignore)
{
    int len;
    if (ssh->cscipher != NULL && (ssh->cscipher->flags & SSH_CIPHER_IS_CBC) &&
	ssh->deferred_len == 0 && !noignore &&
	!(ssh->remote_bugs & BUG_CHOKES_ON_SSH2_IGNORE)) {
	/*
	 * Interpose an SSH_MSG_IGNORE to ensure that user data don't
	 * get encrypted with a known IV.
	 */
	struct Packet *ipkt = ssh2_pkt_init(SSH2_MSG_IGNORE);
	ssh2_pkt_addstring_start(ipkt);
	ssh2_pkt_defer_noqueue(ssh, ipkt, TRUE);
    }
    len = ssh2_pkt_construct(ssh, pkt);
    if (ssh->deferred_len + len > ssh->deferred_size) {
	ssh->deferred_size = ssh->deferred_len + len + 128;
	ssh->deferred_send_data = sresize(ssh->deferred_send_data,
					  ssh->deferred_size,
					  unsigned char);
    }
    memcpy(ssh->deferred_send_data + ssh->deferred_len, pkt->body, len);
    ssh->deferred_len += len;
    ssh->deferred_data_size += pkt->encrypted_len;
    ssh_free_packet(pkt);
}

/*
 * Queue an SSH-2 packet.
 */
static void ssh2_pkt_queue(Ssh ssh, struct Packet *pkt)
{
    assert(ssh->queueing);

    if (ssh->queuelen >= ssh->queuesize) {
	ssh->queuesize = ssh->queuelen + 32;
	ssh->queue = sresize(ssh->queue, ssh->queuesize, struct Packet *);
    }

    ssh->queue[ssh->queuelen++] = pkt;
}

/*
 * Either queue or send a packet, depending on whether queueing is
 * set.
 */
static void ssh2_pkt_send(Ssh ssh, struct Packet *pkt)
{
    if (ssh->queueing)
	ssh2_pkt_queue(ssh, pkt);
    else
	ssh2_pkt_send_noqueue(ssh, pkt);
}

/*
 * Either queue or defer a packet, depending on whether queueing is
 * set.
 */
static void ssh2_pkt_defer(Ssh ssh, struct Packet *pkt)
{
    if (ssh->queueing)
	ssh2_pkt_queue(ssh, pkt);
    else
	ssh2_pkt_defer_noqueue(ssh, pkt, FALSE);
}

/*
 * Send the whole deferred data block constructed by
 * ssh2_pkt_defer() or SSH-1's defer_packet().
 * 
 * The expected use of the defer mechanism is that you call
 * ssh2_pkt_defer() a few times, then call ssh_pkt_defersend(). If
 * not currently queueing, this simply sets up deferred_send_data
 * and then sends it. If we _are_ currently queueing, the calls to
 * ssh2_pkt_defer() put the deferred packets on to the queue
 * instead, and therefore ssh_pkt_defersend() has no deferred data
 * to send. Hence, there's no need to make it conditional on
 * ssh->queueing.
 */
static void ssh_pkt_defersend(Ssh ssh)
{
    int backlog;
    backlog = s_write(ssh, ssh->deferred_send_data, ssh->deferred_len);
    ssh->deferred_len = ssh->deferred_size = 0;
    sfree(ssh->deferred_send_data);
    ssh->deferred_send_data = NULL;
    if (backlog > SSH_MAX_BACKLOG)
	ssh_throttle_all(ssh, 1, backlog);

    if (ssh->version == 2) {
	ssh->outgoing_data_size += ssh->deferred_data_size;
	ssh->deferred_data_size = 0;
	if (!ssh->kex_in_progress &&
	    !ssh->bare_connection &&
	    ssh->max_data_size != 0 &&
	    ssh->outgoing_data_size > ssh->max_data_size)
	    do_ssh2_transport(ssh, "too much data sent", -1, NULL);
    }
}

/*
 * Send a packet whose length needs to be disguised (typically
 * passwords or keyboard-interactive responses).
 */
static void ssh2_pkt_send_with_padding(Ssh ssh, struct Packet *pkt,
				       int padsize)
{
#if 0
    if (0) {
	/*
	 * The simplest way to do this is to adjust the
	 * variable-length padding field in the outgoing packet.
	 * 
	 * Currently compiled out, because some Cisco SSH servers
	 * don't like excessively padded packets (bah, why's it
	 * always Cisco?)
	 */
	pkt->forcepad = padsize;
	ssh2_pkt_send(ssh, pkt);
    } else
#endif
    {
	/*
	 * If we can't do that, however, an alternative approach is
	 * to use the pkt_defer mechanism to bundle the packet
	 * tightly together with an SSH_MSG_IGNORE such that their
	 * combined length is a constant. So first we construct the
	 * final form of this packet and defer its sending.
	 */
	ssh2_pkt_defer(ssh, pkt);

	/*
	 * Now construct an SSH_MSG_IGNORE which includes a string
	 * that's an exact multiple of the cipher block size. (If
	 * the cipher is NULL so that the block size is
	 * unavailable, we don't do this trick at all, because we
	 * gain nothing by it.)
	 */
	if (ssh->cscipher &&
	    !(ssh->remote_bugs & BUG_CHOKES_ON_SSH2_IGNORE)) {
	    int stringlen, i;

	    stringlen = (256 - ssh->deferred_len);
	    stringlen += ssh->cscipher->blksize - 1;
	    stringlen -= (stringlen % ssh->cscipher->blksize);
	    if (ssh->cscomp) {
		/*
		 * Temporarily disable actual compression, so we
		 * can guarantee to get this string exactly the
		 * length we want it. The compression-disabling
		 * routine should return an integer indicating how
		 * many bytes we should adjust our string length
		 * by.
		 */
		stringlen -=
		    ssh->cscomp->disable_compression(ssh->cs_comp_ctx);
	    }
	    pkt = ssh2_pkt_init(SSH2_MSG_IGNORE);
	    ssh2_pkt_addstring_start(pkt);
	    for (i = 0; i < stringlen; i++) {
		char c = (char) random_byte();
		ssh2_pkt_addstring_data(pkt, &c, 1);
	    }
	    ssh2_pkt_defer(ssh, pkt);
	}
	ssh_pkt_defersend(ssh);
    }
}

/*
 * Send all queued SSH-2 packets. We send them by means of
 * ssh2_pkt_defer_noqueue(), in case they included a pair of
 * packets that needed to be lumped together.
 */
static void ssh2_pkt_queuesend(Ssh ssh)
{
    int i;

    assert(!ssh->queueing);

    for (i = 0; i < ssh->queuelen; i++)
	ssh2_pkt_defer_noqueue(ssh, ssh->queue[i], FALSE);
    ssh->queuelen = 0;

    ssh_pkt_defersend(ssh);
}

#if 0
void bndebug(char *string, Bignum b)
{
    unsigned char *p;
    int i, len;
    p = ssh2_mpint_fmt(b, &len);
    debug(("%s", string));
    for (i = 0; i < len; i++)
	debug((" %02x", p[i]));
    debug(("\n"));
    sfree(p);
}
#endif

static void hash_mpint(const struct ssh_hash *h, void *s, Bignum b)
{
    unsigned char *p;
    int len;
    p = ssh2_mpint_fmt(b, &len);
    hash_string(h, s, p, len);
    sfree(p);
}

/*
 * Packet decode functions for both SSH-1 and SSH-2.
 */
static unsigned long ssh_pkt_getuint32(struct Packet *pkt)
{
    unsigned long value;
    if (pkt->length - pkt->savedpos < 4)
	return 0;		       /* arrgh, no way to decline (FIXME?) */
    value = GET_32BIT(pkt->body + pkt->savedpos);
    pkt->savedpos += 4;
    return value;
}
static int ssh2_pkt_getbool(struct Packet *pkt)
{
    unsigned long value;
    if (pkt->length - pkt->savedpos < 1)
	return 0;		       /* arrgh, no way to decline (FIXME?) */
    value = pkt->body[pkt->savedpos] != 0;
    pkt->savedpos++;
    return value;
}
static void ssh_pkt_getstring(struct Packet *pkt, char **p, int *length)
{
    int len;
    *p = NULL;
    *length = 0;
    if (pkt->length - pkt->savedpos < 4)
	return;
    len = toint(GET_32BIT(pkt->body + pkt->savedpos));
    if (len < 0)
	return;
    *length = len;
    pkt->savedpos += 4;
    if (pkt->length - pkt->savedpos < *length)
	return;
    *p = (char *)(pkt->body + pkt->savedpos);
    pkt->savedpos += *length;
}
static void *ssh_pkt_getdata(struct Packet *pkt, int length)
{
    if (pkt->length - pkt->savedpos < length)
	return NULL;
    pkt->savedpos += length;
    return pkt->body + (pkt->savedpos - length);
}
static int ssh1_pkt_getrsakey(struct Packet *pkt, struct RSAKey *key,
			      const unsigned char **keystr)
{
    int j;

    j = makekey(pkt->body + pkt->savedpos,
		pkt->length - pkt->savedpos,
		key, keystr, 0);

    if (j < 0)
	return FALSE;
    
    pkt->savedpos += j;
    assert(pkt->savedpos < pkt->length);

    return TRUE;
}
static Bignum ssh1_pkt_getmp(struct Packet *pkt)
{
    int j;
    Bignum b;

    j = ssh1_read_bignum(pkt->body + pkt->savedpos,
			 pkt->length - pkt->savedpos, &b);

    if (j < 0)
	return NULL;

    pkt->savedpos += j;
    return b;
}
static Bignum ssh2_pkt_getmp(struct Packet *pkt)
{
    char *p;
    int length;
    Bignum b;

    ssh_pkt_getstring(pkt, &p, &length);
    if (!p)
	return NULL;
    if (p[0] & 0x80)
	return NULL;
    b = bignum_from_bytes((unsigned char *)p, length);
    return b;
}

/*
 * Helper function to add an SSH-2 signature blob to a packet.
 * Expects to be shown the public key blob as well as the signature
 * blob. Normally works just like ssh2_pkt_addstring, but will
 * fiddle with the signature packet if necessary for
 * BUG_SSH2_RSA_PADDING.
 */
static void ssh2_add_sigblob(Ssh ssh, struct Packet *pkt,
			     void *pkblob_v, int pkblob_len,
			     void *sigblob_v, int sigblob_len)
{
    unsigned char *pkblob = (unsigned char *)pkblob_v;
    unsigned char *sigblob = (unsigned char *)sigblob_v;

    /* dmemdump(pkblob, pkblob_len); */
    /* dmemdump(sigblob, sigblob_len); */

    /*
     * See if this is in fact an ssh-rsa signature and a buggy
     * server; otherwise we can just do this the easy way.
     */
    if ((ssh->remote_bugs & BUG_SSH2_RSA_PADDING) && pkblob_len > 4+7+4 &&
	(GET_32BIT(pkblob) == 7 && !memcmp(pkblob+4, "ssh-rsa", 7))) {
	int pos, len, siglen;

	/*
	 * Find the byte length of the modulus.
	 */

	pos = 4+7;		       /* skip over "ssh-rsa" */
        len = toint(GET_32BIT(pkblob+pos)); /* get length of exponent */
        if (len < 0 || len > pkblob_len - pos - 4)
            goto give_up;
	pos += 4 + len;                /* skip over exponent */
        if (pkblob_len - pos < 4)
            goto give_up;
	len = toint(GET_32BIT(pkblob+pos)); /* find length of modulus */
        if (len < 0 || len > pkblob_len - pos - 4)
            goto give_up;
	pos += 4;		       /* find modulus itself */
	while (len > 0 && pkblob[pos] == 0)
	    len--, pos++;
	/* debug(("modulus length is %d\n", len)); */

	/*
	 * Now find the signature integer.
	 */
	pos = 4+7;		       /* skip over "ssh-rsa" */
        if (sigblob_len < pos+4)
            goto give_up;
	siglen = toint(GET_32BIT(sigblob+pos));
        if (siglen != sigblob_len - pos - 4)
            goto give_up;
	/* debug(("signature length is %d\n", siglen)); */

	if (len != siglen) {
	    unsigned char newlen[4];
	    ssh2_pkt_addstring_start(pkt);
	    ssh2_pkt_addstring_data(pkt, (char *)sigblob, pos);
	    /* dmemdump(sigblob, pos); */
	    pos += 4;		       /* point to start of actual sig */
	    PUT_32BIT(newlen, len);
	    ssh2_pkt_addstring_data(pkt, (char *)newlen, 4);
	    /* dmemdump(newlen, 4); */
	    newlen[0] = 0;
	    while (len-- > siglen) {
		ssh2_pkt_addstring_data(pkt, (char *)newlen, 1);
		/* dmemdump(newlen, 1); */
	    }
	    ssh2_pkt_addstring_data(pkt, (char *)(sigblob+pos), siglen);
	    /* dmemdump(sigblob+pos, siglen); */
	    return;
	}

	/* Otherwise fall through and do it the easy way. We also come
         * here as a fallback if we discover above that the key blob
         * is misformatted in some way. */
      give_up:;
    }

    ssh2_pkt_addstring_start(pkt);
    ssh2_pkt_addstring_data(pkt, (char *)sigblob, sigblob_len);
}

/*
 * Examine the remote side's version string and compare it against
 * a list of known buggy implementations.
 */
static void ssh_detect_bugs(Ssh ssh, char *vstring)
{
    char *imp;			       /* pointer to implementation part */
    imp = vstring;
    imp += strcspn(imp, "-");
    if (*imp) imp++;
    imp += strcspn(imp, "-");
    if (*imp) imp++;

    ssh->remote_bugs = 0;

    /*
     * General notes on server version strings:
     *  - Not all servers reporting "Cisco-1.25" have all the bugs listed
     *    here -- in particular, we've heard of one that's perfectly happy
     *    with SSH1_MSG_IGNOREs -- but this string never seems to change,
     *    so we can't distinguish them.
     */
    if (conf_get_int(ssh->conf, CONF_sshbug_ignore1) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_ignore1) == AUTO &&
	 (!strcmp(imp, "1.2.18") || !strcmp(imp, "1.2.19") ||
	  !strcmp(imp, "1.2.20") || !strcmp(imp, "1.2.21") ||
	  !strcmp(imp, "1.2.22") || !strcmp(imp, "Cisco-1.25") ||
	  !strcmp(imp, "OSU_1.4alpha3") || !strcmp(imp, "OSU_1.5alpha4")))) {
	/*
	 * These versions don't support SSH1_MSG_IGNORE, so we have
	 * to use a different defence against password length
	 * sniffing.
	 */
	ssh->remote_bugs |= BUG_CHOKES_ON_SSH1_IGNORE;
	logevent("We believe remote version has SSH-1 ignore bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_plainpw1) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_plainpw1) == AUTO &&
	 (!strcmp(imp, "Cisco-1.25") || !strcmp(imp, "OSU_1.4alpha3")))) {
	/*
	 * These versions need a plain password sent; they can't
	 * handle having a null and a random length of data after
	 * the password.
	 */
	ssh->remote_bugs |= BUG_NEEDS_SSH1_PLAIN_PASSWORD;
	logevent("We believe remote version needs a plain SSH-1 password");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_rsa1) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_rsa1) == AUTO &&
	 (!strcmp(imp, "Cisco-1.25")))) {
	/*
	 * These versions apparently have no clue whatever about
	 * RSA authentication and will panic and die if they see
	 * an AUTH_RSA message.
	 */
	ssh->remote_bugs |= BUG_CHOKES_ON_RSA;
	logevent("We believe remote version can't handle SSH-1 RSA authentication");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_hmac2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_hmac2) == AUTO &&
	 !wc_match("* VShell", imp) &&
	 (wc_match("2.1.0*", imp) || wc_match("2.0.*", imp) ||
	  wc_match("2.2.0*", imp) || wc_match("2.3.0*", imp) ||
	  wc_match("2.1 *", imp)))) {
	/*
	 * These versions have the HMAC bug.
	 */
	ssh->remote_bugs |= BUG_SSH2_HMAC;
	logevent("We believe remote version has SSH-2 HMAC bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_derivekey2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_derivekey2) == AUTO &&
	 !wc_match("* VShell", imp) &&
	 (wc_match("2.0.0*", imp) || wc_match("2.0.10*", imp) ))) {
	/*
	 * These versions have the key-derivation bug (failing to
	 * include the literal shared secret in the hashes that
	 * generate the keys).
	 */
	ssh->remote_bugs |= BUG_SSH2_DERIVEKEY;
	logevent("We believe remote version has SSH-2 key-derivation bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_rsapad2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_rsapad2) == AUTO &&
	 (wc_match("OpenSSH_2.[5-9]*", imp) ||
	  wc_match("OpenSSH_3.[0-2]*", imp) ||
	  wc_match("mod_sftp/0.[0-8]*", imp) ||
	  wc_match("mod_sftp/0.9.[0-8]", imp)))) {
	/*
	 * These versions have the SSH-2 RSA padding bug.
	 */
	ssh->remote_bugs |= BUG_SSH2_RSA_PADDING;
	logevent("We believe remote version has SSH-2 RSA padding bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_pksessid2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_pksessid2) == AUTO &&
	 wc_match("OpenSSH_2.[0-2]*", imp))) {
	/*
	 * These versions have the SSH-2 session-ID bug in
	 * public-key authentication.
	 */
	ssh->remote_bugs |= BUG_SSH2_PK_SESSIONID;
	logevent("We believe remote version has SSH-2 public-key-session-ID bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_rekey2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_rekey2) == AUTO &&
	 (wc_match("DigiSSH_2.0", imp) ||
	  wc_match("OpenSSH_2.[0-4]*", imp) ||
	  wc_match("OpenSSH_2.5.[0-3]*", imp) ||
	  wc_match("Sun_SSH_1.0", imp) ||
	  wc_match("Sun_SSH_1.0.1", imp) ||
	  /* All versions <= 1.2.6 (they changed their format in 1.2.7) */
	  wc_match("WeOnlyDo-*", imp)))) {
	/*
	 * These versions have the SSH-2 rekey bug.
	 */
	ssh->remote_bugs |= BUG_SSH2_REKEY;
	logevent("We believe remote version has SSH-2 rekey bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_maxpkt2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_maxpkt2) == AUTO &&
	 (wc_match("1.36_sshlib GlobalSCAPE", imp) ||
          wc_match("1.36 sshlib: GlobalScape", imp)))) {
	/*
	 * This version ignores our makpkt and needs to be throttled.
	 */
	ssh->remote_bugs |= BUG_SSH2_MAXPKT;
	logevent("We believe remote version ignores SSH-2 maximum packet size");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_ignore2) == FORCE_ON) {
	/*
	 * Servers that don't support SSH2_MSG_IGNORE. Currently,
	 * none detected automatically.
	 */
	ssh->remote_bugs |= BUG_CHOKES_ON_SSH2_IGNORE;
	logevent("We believe remote version has SSH-2 ignore bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_oldgex2) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_oldgex2) == AUTO &&
	 (wc_match("OpenSSH_2.[235]*", imp)))) {
	/*
	 * These versions only support the original (pre-RFC4419)
	 * SSH-2 GEX request, and disconnect with a protocol error if
	 * we use the newer version.
	 */
	ssh->remote_bugs |= BUG_SSH2_OLDGEX;
	logevent("We believe remote version has outdated SSH-2 GEX");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_winadj) == FORCE_ON) {
	/*
	 * Servers that don't support our winadj request for one
	 * reason or another. Currently, none detected automatically.
	 */
	ssh->remote_bugs |= BUG_CHOKES_ON_WINADJ;
	logevent("We believe remote version has winadj bug");
    }

    if (conf_get_int(ssh->conf, CONF_sshbug_chanreq) == FORCE_ON ||
	(conf_get_int(ssh->conf, CONF_sshbug_chanreq) == AUTO &&
	 (wc_match("OpenSSH_[2-5].*", imp) ||
	  wc_match("OpenSSH_6.[0-6]*", imp) ||
	  wc_match("dropbear_0.[2-4][0-9]*", imp) ||
	  wc_match("dropbear_0.5[01]*", imp)))) {
	/*
	 * These versions have the SSH-2 channel request bug.
	 * OpenSSH 6.7 and above do not:
	 * https://bugzilla.mindrot.org/show_bug.cgi?id=1818
	 * dropbear_0.52 and above do not:
	 * https://secure.ucc.asn.au/hg/dropbear/rev/cd02449b709c
	 */
	ssh->remote_bugs |= BUG_SENDS_LATE_REQUEST_REPLY;
	logevent("We believe remote version has SSH-2 channel request bug");
    }
}

/*
 * The `software version' part of an SSH version string is required
 * to contain no spaces or minus signs.
 */
static void ssh_fix_verstring(char *str)
{
    /* Eat "<protoversion>-". */
    while (*str && *str != '-') str++;
    assert(*str == '-'); str++;

    /* Convert minus signs and spaces in the remaining string into
     * underscores. */
    while (*str) {
        if (*str == '-' || *str == ' ')
            *str = '_';
        str++;
    }
}

/*
 * Send an appropriate SSH version string.
 */
static void ssh_send_verstring(Ssh ssh, const char *protoname, char *svers)
{
    char *verstring;

    if (ssh->version == 2) {
	/*
	 * Construct a v2 version string.
	 */
	verstring = dupprintf("%s2.0-%s\015\012", protoname, sshver);
    } else {
	/*
	 * Construct a v1 version string.
	 */
        assert(!strcmp(protoname, "SSH-")); /* no v1 bare connection protocol */
	verstring = dupprintf("SSH-%s-%s\012",
			      (ssh_versioncmp(svers, "1.5") <= 0 ?
			       svers : "1.5"),
			      sshver);
    }

    ssh_fix_verstring(verstring + strlen(protoname));
#ifdef FUZZING
    /* FUZZING make PuTTY insecure, so make live use difficult. */
    verstring[0] = 'I';
#endif

    if (ssh->version == 2) {
	size_t len;
	/*
	 * Record our version string.
	 */
	len = strcspn(verstring, "\015\012");
	ssh->v_c = snewn(len + 1, char);
	memcpy(ssh->v_c, verstring, len);
	ssh->v_c[len] = 0;
    }

    logeventf(ssh, "We claim version: %.*s",
	      strcspn(verstring, "\015\012"), verstring);
    s_write(ssh, verstring, strlen(verstring));
    sfree(verstring);
}

static int do_ssh_init(Ssh ssh, unsigned char c)
{
    static const char protoname[] = "SSH-";

    struct do_ssh_init_state {
	int crLine;
	int vslen;
	char version[10];
	char *vstring;
	int vstrsize;
	int i;
	int proto1, proto2;
    };
    crState(do_ssh_init_state);
    
    crBeginState;

    /* Search for a line beginning with the protocol name prefix in
     * the input. */
    for (;;) {
        for (s->i = 0; protoname[s->i]; s->i++) {
            if ((char)c != protoname[s->i]) goto no;
            crReturn(1);
        }
	break;
      no:
	while (c != '\012')
	    crReturn(1);
	crReturn(1);
    }

    ssh->session_started = TRUE;

    s->vstrsize = sizeof(protoname) + 16;
    s->vstring = snewn(s->vstrsize, char);
    strcpy(s->vstring, protoname);
    s->vslen = strlen(protoname);
    s->i = 0;
    while (1) {
	if (s->vslen >= s->vstrsize - 1) {
	    s->vstrsize += 16;
	    s->vstring = sresize(s->vstring, s->vstrsize, char);
	}
	s->vstring[s->vslen++] = c;
	if (s->i >= 0) {
	    if (c == '-') {
		s->version[s->i] = '\0';
		s->i = -1;
	    } else if (s->i < sizeof(s->version) - 1)
		s->version[s->i++] = c;
	} else if (c == '\012')
	    break;
	crReturn(1);		       /* get another char */
    }

    ssh->agentfwd_enabled = FALSE;
    ssh->rdpkt2_state.incoming_sequence = 0;

    s->vstring[s->vslen] = 0;
    s->vstring[strcspn(s->vstring, "\015\012")] = '\0';/* remove EOL chars */
    logeventf(ssh, "Server version: %s", s->vstring);
    ssh_detect_bugs(ssh, s->vstring);

    /*
     * Decide which SSH protocol version to support.
     */

    /* Anything strictly below "2.0" means protocol 1 is supported. */
    s->proto1 = ssh_versioncmp(s->version, "2.0") < 0;
    /* Anything greater or equal to "1.99" means protocol 2 is supported. */
    s->proto2 = ssh_versioncmp(s->version, "1.99") >= 0;

    if (conf_get_int(ssh->conf, CONF_sshprot) == 0) {
	if (!s->proto1) {
	    bombout(("SSH protocol version 1 required by our configuration "
		     "but not provided by server"));
	    crStop(0);
	}
    } else if (conf_get_int(ssh->conf, CONF_sshprot) == 3) {
	if (!s->proto2) {
	    bombout(("SSH protocol version 2 required by our configuration "
		     "but server only provides (old, insecure) SSH-1"));
	    crStop(0);
	}
    } else {
	/* No longer support values 1 or 2 for CONF_sshprot */
	assert(!"Unexpected value for CONF_sshprot");
    }

    if (s->proto2 && (conf_get_int(ssh->conf, CONF_sshprot) >= 2 || !s->proto1))
	ssh->version = 2;
    else
	ssh->version = 1;

    logeventf(ssh, "Using SSH protocol version %d", ssh->version);

    /* Send the version string, if we haven't already */
    if (conf_get_int(ssh->conf, CONF_sshprot) != 3)
	ssh_send_verstring(ssh, protoname, s->version);

    if (ssh->version == 2) {
	size_t len;
	/*
	 * Record their version string.
	 */
	len = strcspn(s->vstring, "\015\012");
	ssh->v_s = snewn(len + 1, char);
	memcpy(ssh->v_s, s->vstring, len);
	ssh->v_s[len] = 0;
	    
	/*
	 * Initialise SSH-2 protocol.
	 */
	ssh->protocol = ssh2_protocol;
	ssh2_protocol_setup(ssh);
	ssh->s_rdpkt = ssh2_rdpkt;
    } else {
	/*
	 * Initialise SSH-1 protocol.
	 */
	ssh->protocol = ssh1_protocol;
	ssh1_protocol_setup(ssh);
	ssh->s_rdpkt = ssh1_rdpkt;
    }
    if (ssh->version == 2)
	do_ssh2_transport(ssh, NULL, -1, NULL);

    update_specials_menu(ssh->frontend);
    ssh->state = SSH_STATE_BEFORE_SIZE;
    ssh->pinger = pinger_new(ssh->conf, &ssh_backend, ssh);

    sfree(s->vstring);

    crFinish(0);
}

static int do_ssh_connection_init(Ssh ssh, unsigned char c)
{
    /*
     * Ordinary SSH begins with the banner "SSH-x.y-...". This is just
     * the ssh-connection part, extracted and given a trivial binary
     * packet protocol, so we replace 'SSH-' at the start with a new
     * name. In proper SSH style (though of course this part of the
     * proper SSH protocol _isn't_ subject to this kind of
     * DNS-domain-based extension), we define the new name in our
     * extension space.
     */
    static const char protoname[] =
        "SSHCONNECTION@putty.projects.tartarus.org-";

    struct do_ssh_connection_init_state {
	int crLine;
	int vslen;
	char version[10];
	char *vstring;
	int vstrsize;
	int i;
    };
    crState(do_ssh_connection_init_state);
    
    crBeginState;

    /* Search for a line beginning with the protocol name prefix in
     * the input. */
    for (;;) {
        for (s->i = 0; protoname[s->i]; s->i++) {
            if ((char)c != protoname[s->i]) goto no;
            crReturn(1);
        }
	break;
      no:
	while (c != '\012')
	    crReturn(1);
	crReturn(1);
    }

    s->vstrsize = sizeof(protoname) + 16;
    s->vstring = snewn(s->vstrsize, char);
    strcpy(s->vstring, protoname);
    s->vslen = strlen(protoname);
    s->i = 0;
    while (1) {
	if (s->vslen >= s->vstrsize - 1) {
	    s->vstrsize += 16;
	    s->vstring = sresize(s->vstring, s->vstrsize, char);
	}
	s->vstring[s->vslen++] = c;
	if (s->i >= 0) {
	    if (c == '-') {
		s->version[s->i] = '\0';
		s->i = -1;
	    } else if (s->i < sizeof(s->version) - 1)
		s->version[s->i++] = c;
	} else if (c == '\012')
	    break;
	crReturn(1);		       /* get another char */
    }

    ssh->agentfwd_enabled = FALSE;
    ssh->rdpkt2_bare_state.incoming_sequence = 0;

    s->vstring[s->vslen] = 0;
    s->vstring[strcspn(s->vstring, "\015\012")] = '\0';/* remove EOL chars */
    logeventf(ssh, "Server version: %s", s->vstring);
    ssh_detect_bugs(ssh, s->vstring);

    /*
     * Decide which SSH protocol version to support. This is easy in
     * bare ssh-connection mode: only 2.0 is legal.
     */
    if (ssh_versioncmp(s->version, "2.0") < 0) {
	bombout(("Server announces compatibility with SSH-1 in bare ssh-connection protocol"));
        crStop(0);
    }
    if (conf_get_int(ssh->conf, CONF_sshprot) == 0) {
	bombout(("Bare ssh-connection protocol cannot be run in SSH-1-only mode"));
	crStop(0);
    }

    ssh->version = 2;

    logeventf(ssh, "Using bare ssh-connection protocol");

    /* Send the version string, if we haven't already */
    ssh_send_verstring(ssh, protoname, s->version);

    /*
     * Initialise bare connection protocol.
     */
    ssh->protocol = ssh2_bare_connection_protocol;
    ssh2_bare_connection_protocol_setup(ssh);
    ssh->s_rdpkt = ssh2_bare_connection_rdpkt;

    update_specials_menu(ssh->frontend);
    ssh->state = SSH_STATE_BEFORE_SIZE;
    ssh->pinger = pinger_new(ssh->conf, &ssh_backend, ssh);

    /*
     * Get authconn (really just conn) under way.
     */
    do_ssh2_authconn(ssh, NULL, 0, NULL);

    sfree(s->vstring);

    crFinish(0);
}

static void ssh_process_incoming_data(Ssh ssh,
				      const unsigned char **data, int *datalen)
{
    struct Packet *pktin;

    pktin = ssh->s_rdpkt(ssh, data, datalen);
    if (pktin) {
	ssh->protocol(ssh, NULL, 0, pktin);
	ssh_free_packet(pktin);
    }
}

static void ssh_queue_incoming_data(Ssh ssh,
				    const unsigned char **data, int *datalen)
{
    bufchain_add(&ssh->queued_incoming_data, *data, *datalen);
    *data += *datalen;
    *datalen = 0;
}

static void ssh_process_queued_incoming_data(Ssh ssh)
{
    void *vdata;
    const unsigned char *data;
    int len, origlen;

    while (!ssh->frozen && bufchain_size(&ssh->queued_incoming_data)) {
	bufchain_prefix(&ssh->queued_incoming_data, &vdata, &len);
	data = vdata;
	origlen = len;

	while (!ssh->frozen && len > 0)
	    ssh_process_incoming_data(ssh, &data, &len);

	if (origlen > len)
	    bufchain_consume(&ssh->queued_incoming_data, origlen - len);
    }
}

static void ssh_set_frozen(Ssh ssh, int frozen)
{
    if (ssh->s)
	sk_set_frozen(ssh->s, frozen);
    ssh->frozen = frozen;
}

static void ssh_gotdata(Ssh ssh, const unsigned char *data, int datalen)
{
    /* Log raw data, if we're in that mode. */
    if (ssh->logctx)
	log_packet(ssh->logctx, PKT_INCOMING, -1, NULL, data, datalen,
		   0, NULL, NULL, 0, NULL);

    crBegin(ssh->ssh_gotdata_crstate);

    /*
     * To begin with, feed the characters one by one to the
     * protocol initialisation / selection function do_ssh_init().
     * When that returns 0, we're done with the initial greeting
     * exchange and can move on to packet discipline.
     */
    while (1) {
	int ret;		       /* need not be kept across crReturn */
	if (datalen == 0)
	    crReturnV;		       /* more data please */
	ret = ssh->do_ssh_init(ssh, *data);
	data++;
	datalen--;
	if (ret == 0)
	    break;
    }

    /*
     * We emerge from that loop when the initial negotiation is
     * over and we have selected an s_rdpkt function. Now pass
     * everything to s_rdpkt, and then pass the resulting packets
     * to the proper protocol handler.
     */

    while (1) {
	while (bufchain_size(&ssh->queued_incoming_data) > 0 || datalen > 0) {
	    if (ssh->frozen) {
		ssh_queue_incoming_data(ssh, &data, &datalen);
		/* This uses up all data and cannot cause anything interesting
		 * to happen; indeed, for anything to happen at all, we must
		 * return, so break out. */
		break;
	    } else if (bufchain_size(&ssh->queued_incoming_data) > 0) {
		/* This uses up some or all data, and may freeze the
		 * session. */
		ssh_process_queued_incoming_data(ssh);
	    } else {
		/* This uses up some or all data, and may freeze the
		 * session. */
		ssh_process_incoming_data(ssh, &data, &datalen);
	    }
	    /* FIXME this is probably EBW. */
	    if (ssh->state == SSH_STATE_CLOSED)
		return;
	}
	/* We're out of data. Go and get some more. */
	crReturnV;
    }
    crFinishV;
}

static int ssh_do_close(Ssh ssh, int notify_exit)
{
    int ret = 0;
    struct ssh_channel *c;

    ssh->state = SSH_STATE_CLOSED;
    expire_timer_context(ssh);
    if (ssh->s) {
        sk_close(ssh->s);
        ssh->s = NULL;
        if (notify_exit)
            notify_remote_exit(ssh->frontend);
        else
            ret = 1;
    }
    /*
     * Now we must shut down any port- and X-forwarded channels going
     * through this connection.
     */
    if (ssh->channels) {
	while (NULL != (c = index234(ssh->channels, 0))) {
	    ssh_channel_close_local(c, NULL);
	    del234(ssh->channels, c); /* moving next one to index 0 */
	    if (ssh->version == 2)
		bufchain_clear(&c->v.v2.outbuffer);
	    sfree(c);
	}
    }
    /*
     * Go through port-forwardings, and close any associated
     * listening sockets.
     */
    if (ssh->portfwds) {
	struct ssh_portfwd *pf;
	while (NULL != (pf = index234(ssh->portfwds, 0))) {
	    /* Dispose of any listening socket. */
	    if (pf->local)
		pfl_terminate(pf->local);
	    del234(ssh->portfwds, pf); /* moving next one to index 0 */
	    free_portfwd(pf);
	}
	freetree234(ssh->portfwds);
	ssh->portfwds = NULL;
    }

    /*
     * Also stop attempting to connection-share.
     */
    if (ssh->connshare) {
        sharestate_free(ssh->connshare);
        ssh->connshare = NULL;
    }

    if (conf_get_int(ssh->conf, CONF_lport_loopback)) {
        unmap_ip_from_loopback(&ssh->ipl);
    }

    return ret;
}

static void ssh_socket_log(Plug plug, int type, SockAddr addr, int port,
                           const char *error_msg, int error_code)
{
    Ssh ssh = (Ssh) plug;

    /*
     * While we're attempting connection sharing, don't loudly log
     * everything that happens. Real TCP connections need to be logged
     * when we _start_ trying to connect, because it might be ages
     * before they respond if something goes wrong; but connection
     * sharing is local and quick to respond, and it's sufficient to
     * simply wait and see whether it worked afterwards.
     */

    if (!ssh->attempting_connshare)
        backend_socket_log(ssh->frontend, type, addr, port,
                           error_msg, error_code, ssh->conf,
                           ssh->session_started);
}

void ssh_connshare_log(Ssh ssh, int event, const char *logtext,
                       const char *ds_err, const char *us_err)
{
    if (event == SHARE_NONE) {
        /* In this case, 'logtext' is an error message indicating a
         * reason why connection sharing couldn't be set up _at all_.
         * Failing that, ds_err and us_err indicate why we couldn't be
         * a downstream and an upstream respectively. */
        if (logtext) {
            logeventf(ssh, "Could not set up connection sharing: %s", logtext);
        } else {
            if (ds_err)
                logeventf(ssh, "Could not set up connection sharing"
                          " as downstream: %s", ds_err);
            if (us_err)
                logeventf(ssh, "Could not set up connection sharing"
                          " as upstream: %s", us_err);
        }
    } else if (event == SHARE_DOWNSTREAM) {
        /* In this case, 'logtext' is a local endpoint address */
        logeventf(ssh, "Using existing shared connection at %s", logtext);
        /* Also we should mention this in the console window to avoid
         * confusing users as to why this window doesn't behave the
         * usual way. */
        if ((flags & FLAG_VERBOSE) || (flags & FLAG_INTERACTIVE)) {
            c_write_str(ssh,"Reusing a shared connection to this server.\r\n");
        }
    } else if (event == SHARE_UPSTREAM) {
        /* In this case, 'logtext' is a local endpoint address too */
        logeventf(ssh, "Sharing this connection at %s", logtext);
    }
}

static void ssh_closing(Plug plug, const char *error_msg, int error_code,
			int calling_back)
{
    Ssh ssh = (Ssh) plug;
    int need_notify = ssh_do_close(ssh, FALSE);

    if (!error_msg) {
	if (!ssh->close_expected)
	    error_msg = "Server unexpectedly closed network connection";
	else
	    error_msg = "Server closed network connection";
    }

    if (ssh->close_expected && ssh->clean_exit && ssh->exitcode < 0)
	ssh->exitcode = 0;

    if (need_notify)
        notify_remote_exit(ssh->frontend);

    if (error_msg)
	logevent(error_msg);
    if (!ssh->close_expected || !ssh->clean_exit)
	connection_fatal(ssh->frontend, "%s", error_msg);
}

static void ssh_receive(Plug plug, int urgent, char *data, int len)
{
    Ssh ssh = (Ssh) plug;
    ssh_gotdata(ssh, (unsigned char *)data, len);
    if (ssh->state == SSH_STATE_CLOSED) {
	ssh_do_close(ssh, TRUE);
    }
}

static void ssh_sent(Plug plug, int bufsize)
{
    Ssh ssh = (Ssh) plug;
    /*
     * If the send backlog on the SSH socket itself clears, we
     * should unthrottle the whole world if it was throttled.
     */
    if (bufsize < SSH_MAX_BACKLOG)
	ssh_throttle_all(ssh, 0, bufsize);
}

static void ssh_hostport_setup(const char *host, int port, Conf *conf,
                               char **savedhost, int *savedport,
                               char **loghost_ret)
{
    char *loghost = conf_get_str(conf, CONF_loghost);
    if (loghost_ret)
        *loghost_ret = loghost;

    if (*loghost) {
	char *tmphost;
        char *colon;

        tmphost = dupstr(loghost);
	*savedport = 22;	       /* default ssh port */

	/*
	 * A colon suffix on the hostname string also lets us affect
	 * savedport. (Unless there are multiple colons, in which case
	 * we assume this is an unbracketed IPv6 literal.)
	 */
	colon = host_strrchr(tmphost, ':');
	if (colon && colon == host_strchr(tmphost, ':')) {
	    *colon++ = '\0';
	    if (*colon)
		*savedport = atoi(colon);
	}

        *savedhost = host_strduptrim(tmphost);
        sfree(tmphost);
    } else {
	*savedhost = host_strduptrim(host);
	if (port < 0)
	    port = 22;		       /* default ssh port */
	*savedport = port;
    }
}

static int ssh_test_for_upstream(const char *host, int port, Conf *conf)
{
    char *savedhost;
    int savedport;
    int ret;

    random_ref(); /* platform may need this to determine share socket name */
    ssh_hostport_setup(host, port, conf, &savedhost, &savedport, NULL);
    ret = ssh_share_test_for_upstream(savedhost, savedport, conf);
    sfree(savedhost);
    random_unref();

    return ret;
}

/*
 * Connect to specified host and port.
 * Returns an error message, or NULL on success.
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *connect_to_host(Ssh ssh, const char *host, int port,
				   char **realhost, int nodelay, int keepalive)
{
    static const struct plug_function_table fn_table = {
	ssh_socket_log,
	ssh_closing,
	ssh_receive,
	ssh_sent,
	NULL
    };

    SockAddr addr;
    const char *err;
    char *loghost;
    int addressfamily, sshprot;

    ssh_hostport_setup(host, port, ssh->conf,
                       &ssh->savedhost, &ssh->savedport, &loghost);

    ssh->fn = &fn_table;               /* make 'ssh' usable as a Plug */

    /*
     * Try connection-sharing, in case that means we don't open a
     * socket after all. ssh_connection_sharing_init will connect to a
     * previously established upstream if it can, and failing that,
     * establish a listening socket for _us_ to be the upstream. In
     * the latter case it will return NULL just as if it had done
     * nothing, because here we only need to care if we're a
     * downstream and need to do our connection setup differently.
     */
    ssh->connshare = NULL;
    ssh->attempting_connshare = TRUE;  /* affects socket logging behaviour */
    ssh->s = ssh_connection_sharing_init(ssh->savedhost, ssh->savedport,
                                         ssh->conf, ssh, &ssh->connshare);
    ssh->attempting_connshare = FALSE;
    if (ssh->s != NULL) {
        /*
         * We are a downstream.
         */
        ssh->bare_connection = TRUE;
        ssh->do_ssh_init = do_ssh_connection_init;
        ssh->fullhostname = NULL;
        *realhost = dupstr(host);      /* best we can do */
    } else {
        /*
         * We're not a downstream, so open a normal socket.
         */
        ssh->do_ssh_init = do_ssh_init;

        /*
         * Try to find host.
         */
        addressfamily = conf_get_int(ssh->conf, CONF_addressfamily);
        addr = name_lookup(host, port, realhost, ssh->conf, addressfamily,
                           ssh->frontend, "SSH connection");
        if ((err = sk_addr_error(addr)) != NULL) {
            sk_addr_free(addr);
            return err;
        }
        ssh->fullhostname = dupstr(*realhost);   /* save in case of GSSAPI */

        ssh->s = new_connection(addr, *realhost, port,
                                0, 1, nodelay, keepalive,
                                (Plug) ssh, ssh->conf);
        if ((err = sk_socket_error(ssh->s)) != NULL) {
            ssh->s = NULL;
            notify_remote_exit(ssh->frontend);
            return err;
        }
    }

    /*
     * The SSH version number is always fixed (since we no longer support
     * fallback between versions), so set it now, and if it's SSH-2,
     * send the version string now too.
     */
    sshprot = conf_get_int(ssh->conf, CONF_sshprot);
    assert(sshprot == 0 || sshprot == 3);
    if (sshprot == 0)
	/* SSH-1 only */
	ssh->version = 1;
    if (sshprot == 3 && !ssh->bare_connection) {
	/* SSH-2 only */
	ssh->version = 2;
	ssh_send_verstring(ssh, "SSH-", NULL);
    }

    /*
     * loghost, if configured, overrides realhost.
     */
    if (*loghost) {
	sfree(*realhost);
	*realhost = dupstr(loghost);
    }

    return NULL;
}

/*
 * Throttle or unthrottle the SSH connection.
 */
static void ssh_throttle_conn(Ssh ssh, int adjust)
{
    int old_count = ssh->conn_throttle_count;
    ssh->conn_throttle_count += adjust;
    assert(ssh->conn_throttle_count >= 0);
    if (ssh->conn_throttle_count && !old_count) {
	ssh_set_frozen(ssh, 1);
    } else if (!ssh->conn_throttle_count && old_count) {
	ssh_set_frozen(ssh, 0);
    }
}

static void ssh_agentf_try_forward(struct ssh_channel *c);

/*
 * Throttle or unthrottle _all_ local data streams (for when sends
 * on the SSH connection itself back up).
 */
static void ssh_throttle_all(Ssh ssh, int enable, int bufsize)
{
    int i;
    struct ssh_channel *c;

    if (enable == ssh->throttled_all)
	return;
    ssh->throttled_all = enable;
    ssh->overall_bufsize = bufsize;
    if (!ssh->channels)
	return;
    for (i = 0; NULL != (c = index234(ssh->channels, i)); i++) {
	switch (c->type) {
	  case CHAN_MAINSESSION:
	    /*
	     * This is treated separately, outside the switch.
	     */
	    break;
	  case CHAN_X11:
	    x11_override_throttle(c->u.x11.xconn, enable);
	    break;
	  case CHAN_AGENT:
	    /* Agent forwarding channels are buffer-managed by
             * checking ssh->throttled_all in ssh_agentf_try_forward.
             * So at the moment we _un_throttle again, we must make an
             * attempt to do something. */
            if (!enable)
                ssh_agentf_try_forward(c);
	    break;
	  case CHAN_SOCKDATA:
	    pfd_override_throttle(c->u.pfd.pf, enable);
	    break;
	}
    }
}

static void ssh_agent_callback(void *sshv, void *reply, int replylen)
{
    Ssh ssh = (Ssh) sshv;

    ssh->auth_agent_query = NULL;

    ssh->agent_response = reply;
    ssh->agent_response_len = replylen;

    if (ssh->version == 1)
	do_ssh1_login(ssh, NULL, -1, NULL);
    else
	do_ssh2_authconn(ssh, NULL, -1, NULL);
}

static void ssh_dialog_callback(void *sshv, int ret)
{
    Ssh ssh = (Ssh) sshv;

    ssh->user_response = ret;

    if (ssh->version == 1)
	do_ssh1_login(ssh, NULL, -1, NULL);
    else
	do_ssh2_transport(ssh, NULL, -1, NULL);

    /*
     * This may have unfrozen the SSH connection, so do a
     * queued-data run.
     */
    ssh_process_queued_incoming_data(ssh);
}

static void ssh_agentf_got_response(struct ssh_channel *c,
                                    void *reply, int replylen)
{
    c->u.a.pending = NULL;

    assert(!(c->closes & CLOSES_SENT_EOF));

    if (!reply) {
	/* The real agent didn't send any kind of reply at all for
         * some reason, so fake an SSH_AGENT_FAILURE. */
	reply = "\0\0\0\1\5";
	replylen = 5;
    }

    ssh_send_channel_data(c, reply, replylen);
}

static void ssh_agentf_callback(void *cv, void *reply, int replylen);

static void ssh_agentf_try_forward(struct ssh_channel *c)
{
    unsigned datalen, lengthfield, messagelen;
    unsigned char *message;
    unsigned char msglen[4];
    void *reply;
    int replylen;

    /*
     * Don't try to parallelise agent requests. Wait for each one to
     * return before attempting the next.
     */
    if (c->u.a.pending)
        return;

    /*
     * If the outgoing side of the channel connection is currently
     * throttled (for any reason, either that channel's window size or
     * the entire SSH connection being throttled), don't submit any
     * new forwarded requests to the real agent. This causes the input
     * side of the agent forwarding not to be emptied, exerting the
     * required back-pressure on the remote client, and encouraging it
     * to read our responses before sending too many more requests.
     */
    if (c->ssh->throttled_all ||
        (c->ssh->version == 2 && c->v.v2.remwindow == 0))
        return;

    if (c->closes & CLOSES_SENT_EOF) {
        /*
         * If we've already sent outgoing EOF, there's nothing we can
         * do with incoming data except consume it and throw it away.
         */
        bufchain_clear(&c->u.a.inbuffer);
        return;
    }

    while (1) {
        /*
         * Try to extract a complete message from the input buffer.
         */
        datalen = bufchain_size(&c->u.a.inbuffer);
        if (datalen < 4)
            break;         /* not even a length field available yet */

        bufchain_fetch(&c->u.a.inbuffer, msglen, 4);
        lengthfield = GET_32BIT(msglen);

        if (lengthfield > AGENT_MAX_MSGLEN) {
            /*
             * If the remote has sent a message that's just _too_
             * long, we should reject it in advance of seeing the rest
             * of the incoming message, and also close the connection
             * for good measure (which avoids us having to faff about
             * with carefully ignoring just the right number of bytes
             * from the overlong message).
             */
            ssh_agentf_got_response(c, NULL, 0);
            sshfwd_write_eof(c);
            return;
        }

        if (lengthfield > datalen - 4)
            break;          /* a whole message is not yet available */

        messagelen = lengthfield + 4;

        message = snewn(messagelen, unsigned char);
        bufchain_fetch(&c->u.a.inbuffer, message, messagelen);
        bufchain_consume(&c->u.a.inbuffer, messagelen);
        c->u.a.pending = agent_query(
            message, messagelen, &reply, &replylen, ssh_agentf_callback, c);
        sfree(message);

        if (c->u.a.pending)
            return;   /* agent_query promised to reply in due course */

        /*
         * If the agent gave us an answer immediately, pass it
         * straight on and go round this loop again.
         */
        ssh_agentf_got_response(c, reply, replylen);
        sfree(reply);
    }

    /*
     * If we get here (i.e. we left the above while loop via 'break'
     * rather than 'return'), that means we've determined that the
     * input buffer for the agent forwarding connection doesn't
     * contain a complete request.
     *
     * So if there's potentially more data to come, we can return now,
     * and wait for the remote client to send it. But if the remote
     * has sent EOF, it would be a mistake to do that, because we'd be
     * waiting a long time. So this is the moment to check for EOF,
     * and respond appropriately.
     */
    if (c->closes & CLOSES_RCVD_EOF)
        sshfwd_write_eof(c);
}

static void ssh_agentf_callback(void *cv, void *reply, int replylen)
{
    struct ssh_channel *c = (struct ssh_channel *)cv;

    ssh_agentf_got_response(c, reply, replylen);
    sfree(reply);

    /*
     * Now try to extract and send further messages from the channel's
     * input-side buffer.
     */
    ssh_agentf_try_forward(c);
}

/*
 * Client-initiated disconnection. Send a DISCONNECT if `wire_reason'
 * non-NULL, otherwise just close the connection. `client_reason' == NULL
 * => log `wire_reason'.
 */
static void ssh_disconnect(Ssh ssh, const char *client_reason,
                           const char *wire_reason,
			   int code, int clean_exit)
{
    char *error;
    if (!client_reason)
	client_reason = wire_reason;
    if (client_reason)
	error = dupprintf("Disconnected: %s", client_reason);
    else
	error = dupstr("Disconnected");
    if (wire_reason) {
	if (ssh->version == 1) {
	    send_packet(ssh, SSH1_MSG_DISCONNECT, PKT_STR, wire_reason,
			PKT_END);
	} else if (ssh->version == 2) {
	    struct Packet *pktout = ssh2_pkt_init(SSH2_MSG_DISCONNECT);
	    ssh2_pkt_adduint32(pktout, code);
	    ssh2_pkt_addstring(pktout, wire_reason);
	    ssh2_pkt_addstring(pktout, "en");	/* language tag */
	    ssh2_pkt_send_noqueue(ssh, pktout);
	}
    }
    ssh->close_expected = TRUE;
    ssh->clean_exit = clean_exit;
    ssh_closing((Plug)ssh, error, 0, 0);
    sfree(error);
}

int verify_ssh_manual_host_key(Ssh ssh, const char *fingerprint,
                               const struct ssh_signkey *ssh2keytype,
                               void *ssh2keydata)
{
    if (!conf_get_str_nthstrkey(ssh->conf, CONF_ssh_manual_hostkeys, 0)) {
        return -1;                     /* no manual keys configured */
    }

    if (fingerprint) {
        /*
         * The fingerprint string we've been given will have things
         * like 'ssh-rsa 2048' at the front of it. Strip those off and
         * narrow down to just the colon-separated hex block at the
         * end of the string.
         */
        const char *p = strrchr(fingerprint, ' ');
        fingerprint = p ? p+1 : fingerprint;
        /* Quick sanity checks, including making sure it's in lowercase */
        assert(strlen(fingerprint) == 16*3 - 1);
        assert(fingerprint[2] == ':');
        assert(fingerprint[strspn(fingerprint, "0123456789abcdef:")] == 0);

        if (conf_get_str_str_opt(ssh->conf, CONF_ssh_manual_hostkeys,
                                 fingerprint))
            return 1;                  /* success */
    }

    if (ssh2keydata) {
        /*
         * Construct the base64-encoded public key blob and see if
         * that's listed.
         */
        unsigned char *binblob;
        char *base64blob;
        int binlen, atoms, i;
        binblob = ssh2keytype->public_blob(ssh2keydata, &binlen);
        atoms = (binlen + 2) / 3;
        base64blob = snewn(atoms * 4 + 1, char);
        for (i = 0; i < atoms; i++)
            base64_encode_atom(binblob + 3*i, binlen - 3*i, base64blob + 4*i);
        base64blob[atoms * 4] = '\0';
        sfree(binblob);
        if (conf_get_str_str_opt(ssh->conf, CONF_ssh_manual_hostkeys,
                                 base64blob)) {
            sfree(base64blob);
            return 1;                  /* success */
        }
        sfree(base64blob);
    }

    return 0;
}

/*
 * Handle the key exchange and user authentication phases.
 */
static int do_ssh1_login(Ssh ssh, const unsigned char *in, int inlen,
			 struct Packet *pktin)
{
    int i, j, ret;
    unsigned char cookie[8], *ptr;
    struct MD5Context md5c;
    struct do_ssh1_login_state {
	int crLine;
	int len;
	unsigned char *rsabuf;
        const unsigned char *keystr1, *keystr2;
	unsigned long supported_ciphers_mask, supported_auths_mask;
	int tried_publickey, tried_agent;
	int tis_auth_refused, ccard_auth_refused;
	unsigned char session_id[16];
	int cipher_type;
	void *publickey_blob;
	int publickey_bloblen;
	char *publickey_comment;
	int privatekey_available, privatekey_encrypted;
	prompts_t *cur_prompt;
	char c;
	int pwpkt_type;
	unsigned char request[5], *response, *p;
	int responselen;
	int keyi, nkeys;
	int authed;
	struct RSAKey key;
	Bignum challenge;
	char *commentp;
	int commentlen;
        int dlgret;
	Filename *keyfile;
        struct RSAKey servkey, hostkey;
    };
    crState(do_ssh1_login_state);

    crBeginState;

    if (!pktin)
	crWaitUntil(pktin);

    if (pktin->type != SSH1_SMSG_PUBLIC_KEY) {
	bombout(("Public key packet not received"));
	crStop(0);
    }

    logevent("Received public keys");

    ptr = ssh_pkt_getdata(pktin, 8);
    if (!ptr) {
	bombout(("SSH-1 public key packet stopped before random cookie"));
	crStop(0);
    }
    memcpy(cookie, ptr, 8);

    if (!ssh1_pkt_getrsakey(pktin, &s->servkey, &s->keystr1) ||
	!ssh1_pkt_getrsakey(pktin, &s->hostkey, &s->keystr2)) {	
	bombout(("Failed to read SSH-1 public keys from public key packet"));
	crStop(0);
    }

    /*
     * Log the host key fingerprint.
     */
    {
	char logmsg[80];
	logevent("Host key fingerprint is:");
	strcpy(logmsg, "      ");
	s->hostkey.comment = NULL;
	rsa_fingerprint(logmsg + strlen(logmsg),
			sizeof(logmsg) - strlen(logmsg), &s->hostkey);
	logevent(logmsg);
    }

    ssh->v1_remote_protoflags = ssh_pkt_getuint32(pktin);
    s->supported_ciphers_mask = ssh_pkt_getuint32(pktin);
    s->supported_auths_mask = ssh_pkt_getuint32(pktin);
    if ((ssh->remote_bugs & BUG_CHOKES_ON_RSA))
	s->supported_auths_mask &= ~(1 << SSH1_AUTH_RSA);

    ssh->v1_local_protoflags =
	ssh->v1_remote_protoflags & SSH1_PROTOFLAGS_SUPPORTED;
    ssh->v1_local_protoflags |= SSH1_PROTOFLAG_SCREEN_NUMBER;

    MD5Init(&md5c);
    MD5Update(&md5c, s->keystr2, s->hostkey.bytes);
    MD5Update(&md5c, s->keystr1, s->servkey.bytes);
    MD5Update(&md5c, cookie, 8);
    MD5Final(s->session_id, &md5c);

    for (i = 0; i < 32; i++)
	ssh->session_key[i] = random_byte();

    /*
     * Verify that the `bits' and `bytes' parameters match.
     */
    if (s->hostkey.bits > s->hostkey.bytes * 8 ||
	s->servkey.bits > s->servkey.bytes * 8) {
	bombout(("SSH-1 public keys were badly formatted"));
	crStop(0);
    }

    s->len = (s->hostkey.bytes > s->servkey.bytes ?
              s->hostkey.bytes : s->servkey.bytes);

    s->rsabuf = snewn(s->len, unsigned char);

    /*
     * Verify the host key.
     */
    {
	/*
	 * First format the key into a string.
	 */
	int len = rsastr_len(&s->hostkey);
	char fingerprint[100];
	char *keystr = snewn(len, char);
	rsastr_fmt(keystr, &s->hostkey);
	rsa_fingerprint(fingerprint, sizeof(fingerprint), &s->hostkey);

        /* First check against manually configured host keys. */
        s->dlgret = verify_ssh_manual_host_key(ssh, fingerprint, NULL, NULL);
        if (s->dlgret == 0) {          /* did not match */
            bombout(("Host key did not appear in manually configured list"));
            sfree(keystr);
            crStop(0);
        } else if (s->dlgret < 0) { /* none configured; use standard handling */
            ssh_set_frozen(ssh, 1);
            s->dlgret = verify_ssh_host_key(ssh->frontend,
                                            ssh->savedhost, ssh->savedport,
                                            "rsa", keystr, fingerprint,
                                            ssh_dialog_callback, ssh);
            sfree(keystr);
#ifdef FUZZING
	    s->dlgret = 1;
#endif
            if (s->dlgret < 0) {
                do {
                    crReturn(0);
                    if (pktin) {
                        bombout(("Unexpected data from server while waiting"
                                 " for user host key response"));
                        crStop(0);
                    }
                } while (pktin || inlen > 0);
                s->dlgret = ssh->user_response;
            }
            ssh_set_frozen(ssh, 0);

            if (s->dlgret == 0) {
                ssh_disconnect(ssh, "User aborted at host key verification",
                               NULL, 0, TRUE);
                crStop(0);
            }
        } else {
            sfree(keystr);
        }
    }

    for (i = 0; i < 32; i++) {
	s->rsabuf[i] = ssh->session_key[i];
	if (i < 16)
	    s->rsabuf[i] ^= s->session_id[i];
    }

    if (s->hostkey.bytes > s->servkey.bytes) {
	ret = rsaencrypt(s->rsabuf, 32, &s->servkey);
	if (ret)
	    ret = rsaencrypt(s->rsabuf, s->servkey.bytes, &s->hostkey);
    } else {
	ret = rsaencrypt(s->rsabuf, 32, &s->hostkey);
	if (ret)
	    ret = rsaencrypt(s->rsabuf, s->hostkey.bytes, &s->servkey);
    }
    if (!ret) {
	bombout(("SSH-1 public key encryptions failed due to bad formatting"));
	crStop(0);	
    }

    logevent("Encrypted session key");

    {
	int cipher_chosen = 0, warn = 0;
	const char *cipher_string = NULL;
	int i;
	for (i = 0; !cipher_chosen && i < CIPHER_MAX; i++) {
	    int next_cipher = conf_get_int_int(ssh->conf,
					       CONF_ssh_cipherlist, i);
	    if (next_cipher == CIPHER_WARN) {
		/* If/when we choose a cipher, warn about it */
		warn = 1;
	    } else if (next_cipher == CIPHER_AES) {
		/* XXX Probably don't need to mention this. */
		logevent("AES not supported in SSH-1, skipping");
	    } else {
		switch (next_cipher) {
		  case CIPHER_3DES:     s->cipher_type = SSH_CIPHER_3DES;
					cipher_string = "3DES"; break;
		  case CIPHER_BLOWFISH: s->cipher_type = SSH_CIPHER_BLOWFISH;
					cipher_string = "Blowfish"; break;
		  case CIPHER_DES:	s->cipher_type = SSH_CIPHER_DES;
					cipher_string = "single-DES"; break;
		}
		if (s->supported_ciphers_mask & (1 << s->cipher_type))
		    cipher_chosen = 1;
	    }
	}
	if (!cipher_chosen) {
	    if ((s->supported_ciphers_mask & (1 << SSH_CIPHER_3DES)) == 0)
		bombout(("Server violates SSH-1 protocol by not "
			 "supporting 3DES encryption"));
	    else
		/* shouldn't happen */
		bombout(("No supported ciphers found"));
	    crStop(0);
	}

	/* Warn about chosen cipher if necessary. */
	if (warn) {
            ssh_set_frozen(ssh, 1);
	    s->dlgret = askalg(ssh->frontend, "cipher", cipher_string,
			       ssh_dialog_callback, ssh);
	    if (s->dlgret < 0) {
		do {
		    crReturn(0);
		    if (pktin) {
			bombout(("Unexpected data from server while waiting"
				 " for user response"));
			crStop(0);
		    }
		} while (pktin || inlen > 0);
		s->dlgret = ssh->user_response;
	    }
            ssh_set_frozen(ssh, 0);
	    if (s->dlgret == 0) {
		ssh_disconnect(ssh, "User aborted at cipher warning", NULL,
			       0, TRUE);
		crStop(0);
	    }
        }
    }

    switch (s->cipher_type) {
      case SSH_CIPHER_3DES:
	logevent("Using 3DES encryption");
	break;
      case SSH_CIPHER_DES:
	logevent("Using single-DES encryption");
	break;
      case SSH_CIPHER_BLOWFISH:
	logevent("Using Blowfish encryption");
	break;
    }

    send_packet(ssh, SSH1_CMSG_SESSION_KEY,
		PKT_CHAR, s->cipher_type,
		PKT_DATA, cookie, 8,
		PKT_CHAR, (s->len * 8) >> 8, PKT_CHAR, (s->len * 8) & 0xFF,
		PKT_DATA, s->rsabuf, s->len,
		PKT_INT, ssh->v1_local_protoflags, PKT_END);

    logevent("Trying to enable encryption...");

    sfree(s->rsabuf);

    ssh->cipher = (s->cipher_type == SSH_CIPHER_BLOWFISH ? &ssh_blowfish_ssh1 :
		   s->cipher_type == SSH_CIPHER_DES ? &ssh_des :
		   &ssh_3des);
    ssh->v1_cipher_ctx = ssh->cipher->make_context();
    ssh->cipher->sesskey(ssh->v1_cipher_ctx, ssh->session_key);
    logeventf(ssh, "Initialised %s encryption", ssh->cipher->text_name);

    ssh->crcda_ctx = crcda_make_context();
    logevent("Installing CRC compensation attack detector");

    if (s->servkey.modulus) {
	sfree(s->servkey.modulus);
	s->servkey.modulus = NULL;
    }
    if (s->servkey.exponent) {
	sfree(s->servkey.exponent);
	s->servkey.exponent = NULL;
    }
    if (s->hostkey.modulus) {
	sfree(s->hostkey.modulus);
	s->hostkey.modulus = NULL;
    }
    if (s->hostkey.exponent) {
	sfree(s->hostkey.exponent);
	s->hostkey.exponent = NULL;
    }
    crWaitUntil(pktin);

    if (pktin->type != SSH1_SMSG_SUCCESS) {
	bombout(("Encryption not successfully enabled"));
	crStop(0);
    }

    logevent("Successfully started encryption");

    fflush(stdout); /* FIXME eh? */
    {
	if ((ssh->username = get_remote_username(ssh->conf)) == NULL) {
	    int ret; /* need not be kept over crReturn */
	    s->cur_prompt = new_prompts(ssh->frontend);
	    s->cur_prompt->to_server = TRUE;
	    s->cur_prompt->name = dupstr("SSH login name");
	    add_prompt(s->cur_prompt, dupstr("login as: "), TRUE);
	    ret = get_userpass_input(s->cur_prompt, NULL, 0);
	    while (ret < 0) {
		ssh->send_ok = 1;
		crWaitUntil(!pktin);
		ret = get_userpass_input(s->cur_prompt, in, inlen);
		ssh->send_ok = 0;
	    }
	    if (!ret) {
		/*
		 * Failed to get a username. Terminate.
		 */
		free_prompts(s->cur_prompt);
		ssh_disconnect(ssh, "No username provided", NULL, 0, TRUE);
		crStop(0);
	    }
	    ssh->username = dupstr(s->cur_prompt->prompts[0]->result);
	    free_prompts(s->cur_prompt);
	}

	send_packet(ssh, SSH1_CMSG_USER, PKT_STR, ssh->username, PKT_END);
	{
	    char *userlog = dupprintf("Sent username \"%s\"", ssh->username);
	    logevent(userlog);
	    if (flags & FLAG_INTERACTIVE &&
		(!((flags & FLAG_STDERR) && (flags & FLAG_VERBOSE)))) {
		c_write_str(ssh, userlog);
		c_write_str(ssh, "\r\n");
	    }
	    sfree(userlog);
	}
    }

    crWaitUntil(pktin);

    if ((s->supported_auths_mask & (1 << SSH1_AUTH_RSA)) == 0) {
	/* We must not attempt PK auth. Pretend we've already tried it. */
	s->tried_publickey = s->tried_agent = 1;
    } else {
	s->tried_publickey = s->tried_agent = 0;
    }
    s->tis_auth_refused = s->ccard_auth_refused = 0;
    /*
     * Load the public half of any configured keyfile for later use.
     */
    s->keyfile = conf_get_filename(ssh->conf, CONF_keyfile);
    if (!filename_is_null(s->keyfile)) {
	int keytype;
	logeventf(ssh, "Reading key file \"%.150s\"",
		  filename_to_str(s->keyfile));
	keytype = key_type(s->keyfile);
	if (keytype == SSH_KEYTYPE_SSH1 ||
            keytype == SSH_KEYTYPE_SSH1_PUBLIC) {
	    const char *error;
	    if (rsakey_pubblob(s->keyfile,
			       &s->publickey_blob, &s->publickey_bloblen,
			       &s->publickey_comment, &error)) {
                s->privatekey_available = (keytype == SSH_KEYTYPE_SSH1);
                if (!s->privatekey_available)
                    logeventf(ssh, "Key file contains public key only");
		s->privatekey_encrypted = rsakey_encrypted(s->keyfile,
                                                           NULL);
	    } else {
		char *msgbuf;
		logeventf(ssh, "Unable to load key (%s)", error);
		msgbuf = dupprintf("Unable to load key file "
				   "\"%.150s\" (%s)\r\n",
				   filename_to_str(s->keyfile),
				   error);
		c_write_str(ssh, msgbuf);
		sfree(msgbuf);
		s->publickey_blob = NULL;
	    }
	} else {
	    char *msgbuf;
	    logeventf(ssh, "Unable to use this key file (%s)",
		      key_type_to_str(keytype));
	    msgbuf = dupprintf("Unable to use key file \"%.150s\""
			       " (%s)\r\n",
			       filename_to_str(s->keyfile),
			       key_type_to_str(keytype));
	    c_write_str(ssh, msgbuf);
	    sfree(msgbuf);
	    s->publickey_blob = NULL;
	}
    } else
	s->publickey_blob = NULL;

    while (pktin->type == SSH1_SMSG_FAILURE) {
	s->pwpkt_type = SSH1_CMSG_AUTH_PASSWORD;

	if (conf_get_int(ssh->conf, CONF_tryagent) && agent_exists() && !s->tried_agent) {
	    /*
	     * Attempt RSA authentication using Pageant.
	     */
	    void *r;

	    s->authed = FALSE;
	    s->tried_agent = 1;
	    logevent("Pageant is running. Requesting keys.");

	    /* Request the keys held by the agent. */
	    PUT_32BIT(s->request, 1);
	    s->request[4] = SSH1_AGENTC_REQUEST_RSA_IDENTITIES;
            ssh->auth_agent_query = agent_query(
                s->request, 5, &r, &s->responselen, ssh_agent_callback, ssh);
	    if (ssh->auth_agent_query) {
		do {
		    crReturn(0);
		    if (pktin) {
			bombout(("Unexpected data from server while waiting"
				 " for agent response"));
			crStop(0);
		    }
		} while (pktin || inlen > 0);
		r = ssh->agent_response;
		s->responselen = ssh->agent_response_len;
	    }
	    s->response = (unsigned char *) r;
	    if (s->response && s->responselen >= 5 &&
		s->response[4] == SSH1_AGENT_RSA_IDENTITIES_ANSWER) {
		s->p = s->response + 5;
		s->nkeys = toint(GET_32BIT(s->p));
                if (s->nkeys < 0) {
                    logeventf(ssh, "Pageant reported negative key count %d",
                              s->nkeys);
                    s->nkeys = 0;
                }
		s->p += 4;
		logeventf(ssh, "Pageant has %d SSH-1 keys", s->nkeys);
		for (s->keyi = 0; s->keyi < s->nkeys; s->keyi++) {
		    unsigned char *pkblob = s->p;
		    s->p += 4;
		    {
			int n, ok = FALSE;
			do {	       /* do while (0) to make breaking easy */
			    n = ssh1_read_bignum
				(s->p, toint(s->responselen-(s->p-s->response)),
				 &s->key.exponent);
			    if (n < 0)
				break;
			    s->p += n;
			    n = ssh1_read_bignum
				(s->p, toint(s->responselen-(s->p-s->response)),
				 &s->key.modulus);
			    if (n < 0)
                                break;
			    s->p += n;
			    if (s->responselen - (s->p-s->response) < 4)
				break;
			    s->commentlen = toint(GET_32BIT(s->p));
			    s->p += 4;
			    if (s->commentlen < 0 ||
                                toint(s->responselen - (s->p-s->response)) <
				s->commentlen)
				break;
			    s->commentp = (char *)s->p;
			    s->p += s->commentlen;
			    ok = TRUE;
			} while (0);
			if (!ok) {
			    logevent("Pageant key list packet was truncated");
			    break;
			}
		    }
		    if (s->publickey_blob) {
			if (!memcmp(pkblob, s->publickey_blob,
				    s->publickey_bloblen)) {
			    logeventf(ssh, "Pageant key #%d matches "
				      "configured key file", s->keyi);
			    s->tried_publickey = 1;
			} else
			    /* Skip non-configured key */
			    continue;
		    }
		    logeventf(ssh, "Trying Pageant key #%d", s->keyi);
		    send_packet(ssh, SSH1_CMSG_AUTH_RSA,
				PKT_BIGNUM, s->key.modulus, PKT_END);
		    crWaitUntil(pktin);
		    if (pktin->type != SSH1_SMSG_AUTH_RSA_CHALLENGE) {
			logevent("Key refused");
			continue;
		    }
		    logevent("Received RSA challenge");
		    if ((s->challenge = ssh1_pkt_getmp(pktin)) == NULL) {
			bombout(("Server's RSA challenge was badly formatted"));
			crStop(0);
		    }

		    {
			char *agentreq, *q, *ret;
			void *vret;
			int len, retlen;
			len = 1 + 4;   /* message type, bit count */
			len += ssh1_bignum_length(s->key.exponent);
			len += ssh1_bignum_length(s->key.modulus);
			len += ssh1_bignum_length(s->challenge);
			len += 16;     /* session id */
			len += 4;      /* response format */
			agentreq = snewn(4 + len, char);
			PUT_32BIT(agentreq, len);
			q = agentreq + 4;
			*q++ = SSH1_AGENTC_RSA_CHALLENGE;
			PUT_32BIT(q, bignum_bitcount(s->key.modulus));
			q += 4;
			q += ssh1_write_bignum(q, s->key.exponent);
			q += ssh1_write_bignum(q, s->key.modulus);
			q += ssh1_write_bignum(q, s->challenge);
			memcpy(q, s->session_id, 16);
			q += 16;
			PUT_32BIT(q, 1);	/* response format */
                        ssh->auth_agent_query = agent_query(
                            agentreq, len + 4, &vret, &retlen,
                            ssh_agent_callback, ssh);
			if (ssh->auth_agent_query) {
			    sfree(agentreq);
			    do {
				crReturn(0);
				if (pktin) {
				    bombout(("Unexpected data from server"
					     " while waiting for agent"
					     " response"));
				    crStop(0);
				}
			    } while (pktin || inlen > 0);
			    vret = ssh->agent_response;
			    retlen = ssh->agent_response_len;
			} else
			    sfree(agentreq);
			ret = vret;
			if (ret) {
			    if (ret[4] == SSH1_AGENT_RSA_RESPONSE) {
				logevent("Sending Pageant's response");
				send_packet(ssh, SSH1_CMSG_AUTH_RSA_RESPONSE,
					    PKT_DATA, ret + 5, 16,
					    PKT_END);
				sfree(ret);
				crWaitUntil(pktin);
				if (pktin->type == SSH1_SMSG_SUCCESS) {
				    logevent
					("Pageant's response accepted");
				    if (flags & FLAG_VERBOSE) {
					c_write_str(ssh, "Authenticated using"
						    " RSA key \"");
					c_write(ssh, s->commentp,
						s->commentlen);
					c_write_str(ssh, "\" from agent\r\n");
				    }
				    s->authed = TRUE;
				} else
				    logevent
					("Pageant's response not accepted");
			    } else {
				logevent
				    ("Pageant failed to answer challenge");
				sfree(ret);
			    }
			} else {
			    logevent("No reply received from Pageant");
			}
		    }
		    freebn(s->key.exponent);
		    freebn(s->key.modulus);
		    freebn(s->challenge);
		    if (s->authed)
			break;
		}
		sfree(s->response);
		if (s->publickey_blob && !s->tried_publickey)
		    logevent("Configured key file not in Pageant");
	    } else {
                logevent("Failed to get reply from Pageant");
            }
	    if (s->authed)
		break;
	}
	if (s->publickey_blob && s->privatekey_available &&
            !s->tried_publickey) {
	    /*
	     * Try public key authentication with the specified
	     * key file.
	     */
	    int got_passphrase; /* need not be kept over crReturn */
	    if (flags & FLAG_VERBOSE)
		c_write_str(ssh, "Trying public key authentication.\r\n");
	    s->keyfile = conf_get_filename(ssh->conf, CONF_keyfile);
	    logeventf(ssh, "Trying public key \"%s\"",
		      filename_to_str(s->keyfile));
	    s->tried_publickey = 1;
	    got_passphrase = FALSE;
	    while (!got_passphrase) {
		/*
		 * Get a passphrase, if necessary.
		 */
		char *passphrase = NULL;    /* only written after crReturn */
		const char *error;
		if (!s->privatekey_encrypted) {
		    if (flags & FLAG_VERBOSE)
			c_write_str(ssh, "No passphrase required.\r\n");
		    passphrase = NULL;
		} else {
		    int ret; /* need not be kept over crReturn */
		    s->cur_prompt = new_prompts(ssh->frontend);
		    s->cur_prompt->to_server = FALSE;
		    s->cur_prompt->name = dupstr("SSH key passphrase");
		    add_prompt(s->cur_prompt,
			       dupprintf("Passphrase for key \"%.100s\": ",
					 s->publickey_comment), FALSE);
		    ret = get_userpass_input(s->cur_prompt, NULL, 0);
		    while (ret < 0) {
			ssh->send_ok = 1;
			crWaitUntil(!pktin);
			ret = get_userpass_input(s->cur_prompt, in, inlen);
			ssh->send_ok = 0;
		    }
		    if (!ret) {
			/* Failed to get a passphrase. Terminate. */
			free_prompts(s->cur_prompt);
			ssh_disconnect(ssh, NULL, "Unable to authenticate",
				       0, TRUE);
			crStop(0);
		    }
		    passphrase = dupstr(s->cur_prompt->prompts[0]->result);
		    free_prompts(s->cur_prompt);
		}
		/*
		 * Try decrypting key with passphrase.
		 */
		s->keyfile = conf_get_filename(ssh->conf, CONF_keyfile);
		ret = loadrsakey(s->keyfile, &s->key, passphrase,
				 &error);
		if (passphrase) {
		    smemclr(passphrase, strlen(passphrase));
		    sfree(passphrase);
		}
		if (ret == 1) {
		    /* Correct passphrase. */
		    got_passphrase = TRUE;
		} else if (ret == 0) {
		    c_write_str(ssh, "Couldn't load private key from ");
		    c_write_str(ssh, filename_to_str(s->keyfile));
		    c_write_str(ssh, " (");
		    c_write_str(ssh, error);
		    c_write_str(ssh, ").\r\n");
		    got_passphrase = FALSE;
		    break;	       /* go and try something else */
		} else if (ret == -1) {
		    c_write_str(ssh, "Wrong passphrase.\r\n"); /* FIXME */
		    got_passphrase = FALSE;
		    /* and try again */
		} else {
		    assert(0 && "unexpected return from loadrsakey()");
		    got_passphrase = FALSE;   /* placate optimisers */
		}
	    }

	    if (got_passphrase) {

		/*
		 * Send a public key attempt.
		 */
		send_packet(ssh, SSH1_CMSG_AUTH_RSA,
			    PKT_BIGNUM, s->key.modulus, PKT_END);

		crWaitUntil(pktin);
		if (pktin->type == SSH1_SMSG_FAILURE) {
		    c_write_str(ssh, "Server refused our public key.\r\n");
		    continue;	       /* go and try something else */
		}
		if (pktin->type != SSH1_SMSG_AUTH_RSA_CHALLENGE) {
		    bombout(("Bizarre response to offer of public key"));
		    crStop(0);
		}

		{
		    int i;
		    unsigned char buffer[32];
		    Bignum challenge, response;

		    if ((challenge = ssh1_pkt_getmp(pktin)) == NULL) {
			bombout(("Server's RSA challenge was badly formatted"));
			crStop(0);
		    }
		    response = rsadecrypt(challenge, &s->key);
		    freebn(s->key.private_exponent);/* burn the evidence */

		    for (i = 0; i < 32; i++) {
			buffer[i] = bignum_byte(response, 31 - i);
		    }

		    MD5Init(&md5c);
		    MD5Update(&md5c, buffer, 32);
		    MD5Update(&md5c, s->session_id, 16);
		    MD5Final(buffer, &md5c);

		    send_packet(ssh, SSH1_CMSG_AUTH_RSA_RESPONSE,
				PKT_DATA, buffer, 16, PKT_END);

		    freebn(challenge);
		    freebn(response);
		}

		crWaitUntil(pktin);
		if (pktin->type == SSH1_SMSG_FAILURE) {
		    if (flags & FLAG_VERBOSE)
			c_write_str(ssh, "Failed to authenticate with"
				    " our public key.\r\n");
		    continue;	       /* go and try something else */
		} else if (pktin->type != SSH1_SMSG_SUCCESS) {
		    bombout(("Bizarre response to RSA authentication response"));
		    crStop(0);
		}

		break;		       /* we're through! */
	    }

	}

	/*
	 * Otherwise, try various forms of password-like authentication.
	 */
	s->cur_prompt = new_prompts(ssh->frontend);

	if (conf_get_int(ssh->conf, CONF_try_tis_auth) &&
	    (s->supported_auths_mask & (1 << SSH1_AUTH_TIS)) &&
	    !s->tis_auth_refused) {
	    s->pwpkt_type = SSH1_CMSG_AUTH_TIS_RESPONSE;
	    logevent("Requested TIS authentication");
	    send_packet(ssh, SSH1_CMSG_AUTH_TIS, PKT_END);
	    crWaitUntil(pktin);
	    if (pktin->type != SSH1_SMSG_AUTH_TIS_CHALLENGE) {
		logevent("TIS authentication declined");
		if (flags & FLAG_INTERACTIVE)
		    c_write_str(ssh, "TIS authentication refused.\r\n");
		s->tis_auth_refused = 1;
		continue;
	    } else {
		char *challenge;
		int challengelen;
		char *instr_suf, *prompt;

		ssh_pkt_getstring(pktin, &challenge, &challengelen);
		if (!challenge) {
		    bombout(("TIS challenge packet was badly formed"));
		    crStop(0);
		}
		logevent("Received TIS challenge");
		s->cur_prompt->to_server = TRUE;
		s->cur_prompt->name = dupstr("SSH TIS authentication");
		/* Prompt heuristic comes from OpenSSH */
		if (memchr(challenge, '\n', challengelen)) {
		    instr_suf = dupstr("");
		    prompt = dupprintf("%.*s", challengelen, challenge);
		} else {
		    instr_suf = dupprintf("%.*s", challengelen, challenge);
		    prompt = dupstr("Response: ");
		}
		s->cur_prompt->instruction =
		    dupprintf("Using TIS authentication.%s%s",
			      (*instr_suf) ? "\n" : "",
			      instr_suf);
		s->cur_prompt->instr_reqd = TRUE;
		add_prompt(s->cur_prompt, prompt, FALSE);
		sfree(instr_suf);
	    }
	}
	if (conf_get_int(ssh->conf, CONF_try_tis_auth) &&
	    (s->supported_auths_mask & (1 << SSH1_AUTH_CCARD)) &&
	    !s->ccard_auth_refused) {
	    s->pwpkt_type = SSH1_CMSG_AUTH_CCARD_RESPONSE;
	    logevent("Requested CryptoCard authentication");
	    send_packet(ssh, SSH1_CMSG_AUTH_CCARD, PKT_END);
	    crWaitUntil(pktin);
	    if (pktin->type != SSH1_SMSG_AUTH_CCARD_CHALLENGE) {
		logevent("CryptoCard authentication declined");
		c_write_str(ssh, "CryptoCard authentication refused.\r\n");
		s->ccard_auth_refused = 1;
		continue;
	    } else {
		char *challenge;
		int challengelen;
		char *instr_suf, *prompt;

		ssh_pkt_getstring(pktin, &challenge, &challengelen);
		if (!challenge) {
		    bombout(("CryptoCard challenge packet was badly formed"));
		    crStop(0);
		}
		logevent("Received CryptoCard challenge");
		s->cur_prompt->to_server = TRUE;
		s->cur_prompt->name = dupstr("SSH CryptoCard authentication");
		s->cur_prompt->name_reqd = FALSE;
		/* Prompt heuristic comes from OpenSSH */
		if (memchr(challenge, '\n', challengelen)) {
		    instr_suf = dupstr("");
		    prompt = dupprintf("%.*s", challengelen, challenge);
		} else {
		    instr_suf = dupprintf("%.*s", challengelen, challenge);
		    prompt = dupstr("Response: ");
		}
		s->cur_prompt->instruction =
		    dupprintf("Using CryptoCard authentication.%s%s",
			      (*instr_suf) ? "\n" : "",
			      instr_suf);
		s->cur_prompt->instr_reqd = TRUE;
		add_prompt(s->cur_prompt, prompt, FALSE);
		sfree(instr_suf);
	    }
	}
	if (s->pwpkt_type == SSH1_CMSG_AUTH_PASSWORD) {
	    if ((s->supported_auths_mask & (1 << SSH1_AUTH_PASSWORD)) == 0) {
		bombout(("No supported authentication methods available"));
		crStop(0);
	    }
	    s->cur_prompt->to_server = TRUE;
	    s->cur_prompt->name = dupstr("SSH password");
	    add_prompt(s->cur_prompt, dupprintf("%s@%s's password: ",
						ssh->username, ssh->savedhost),
		       FALSE);
	}

	/*
	 * Show password prompt, having first obtained it via a TIS
	 * or CryptoCard exchange if we're doing TIS or CryptoCard
	 * authentication.
	 */
	{
	    int ret; /* need not be kept over crReturn */
	    ret = get_userpass_input(s->cur_prompt, NULL, 0);
	    while (ret < 0) {
		ssh->send_ok = 1;
		crWaitUntil(!pktin);
		ret = get_userpass_input(s->cur_prompt, in, inlen);
		ssh->send_ok = 0;
	    }
	    if (!ret) {
		/*
		 * Failed to get a password (for example
		 * because one was supplied on the command line
		 * which has already failed to work). Terminate.
		 */
		free_prompts(s->cur_prompt);
		ssh_disconnect(ssh, NULL, "Unable to authenticate", 0, TRUE);
		crStop(0);
	    }
	}

	if (s->pwpkt_type == SSH1_CMSG_AUTH_PASSWORD) {
	    /*
	     * Defence against traffic analysis: we send a
	     * whole bunch of packets containing strings of
	     * different lengths. One of these strings is the
	     * password, in a SSH1_CMSG_AUTH_PASSWORD packet.
	     * The others are all random data in
	     * SSH1_MSG_IGNORE packets. This way a passive
	     * listener can't tell which is the password, and
	     * hence can't deduce the password length.
	     * 
	     * Anybody with a password length greater than 16
	     * bytes is going to have enough entropy in their
	     * password that a listener won't find it _that_
	     * much help to know how long it is. So what we'll
	     * do is:
	     * 
	     *  - if password length < 16, we send 15 packets
	     *    containing string lengths 1 through 15
	     * 
	     *  - otherwise, we let N be the nearest multiple
	     *    of 8 below the password length, and send 8
	     *    packets containing string lengths N through
	     *    N+7. This won't obscure the order of
	     *    magnitude of the password length, but it will
	     *    introduce a bit of extra uncertainty.
	     * 
	     * A few servers can't deal with SSH1_MSG_IGNORE, at
	     * least in this context. For these servers, we need
	     * an alternative defence. We make use of the fact
	     * that the password is interpreted as a C string:
	     * so we can append a NUL, then some random data.
	     * 
	     * A few servers can deal with neither SSH1_MSG_IGNORE
	     * here _nor_ a padded password string.
	     * For these servers we are left with no defences
	     * against password length sniffing.
	     */
	    if (!(ssh->remote_bugs & BUG_CHOKES_ON_SSH1_IGNORE) &&
	        !(ssh->remote_bugs & BUG_NEEDS_SSH1_PLAIN_PASSWORD)) {
		/*
		 * The server can deal with SSH1_MSG_IGNORE, so
		 * we can use the primary defence.
		 */
		int bottom, top, pwlen, i;
		char *randomstr;

		pwlen = strlen(s->cur_prompt->prompts[0]->result);
		if (pwlen < 16) {
		    bottom = 0;    /* zero length passwords are OK! :-) */
		    top = 15;
		} else {
		    bottom = pwlen & ~7;
		    top = bottom + 7;
		}

		assert(pwlen >= bottom && pwlen <= top);

		randomstr = snewn(top + 1, char);

		for (i = bottom; i <= top; i++) {
		    if (i == pwlen) {
			defer_packet(ssh, s->pwpkt_type,
                                     PKT_STR,s->cur_prompt->prompts[0]->result,
				     PKT_END);
		    } else {
			for (j = 0; j < i; j++) {
			    do {
				randomstr[j] = random_byte();
			    } while (randomstr[j] == '\0');
			}
			randomstr[i] = '\0';
			defer_packet(ssh, SSH1_MSG_IGNORE,
				     PKT_STR, randomstr, PKT_END);
		    }
		}
		logevent("Sending password with camouflage packets");
		ssh_pkt_defersend(ssh);
		sfree(randomstr);
	    } 
	    else if (!(ssh->remote_bugs & BUG_NEEDS_SSH1_PLAIN_PASSWORD)) {
		/*
		 * The server can't deal with SSH1_MSG_IGNORE
		 * but can deal with padded passwords, so we
		 * can use the secondary defence.
		 */
		char string[64];
		char *ss;
		int len;

		len = strlen(s->cur_prompt->prompts[0]->result);
		if (len < sizeof(string)) {
		    ss = string;
		    strcpy(string, s->cur_prompt->prompts[0]->result);
		    len++;	       /* cover the zero byte */
		    while (len < sizeof(string)) {
			string[len++] = (char) random_byte();
		    }
		} else {
		    ss = s->cur_prompt->prompts[0]->result;
		}
		logevent("Sending length-padded password");
		send_packet(ssh, s->pwpkt_type,
			    PKT_INT, len, PKT_DATA, ss, len,
			    PKT_END);
	    } else {
		/*
		 * The server is believed unable to cope with
		 * any of our password camouflage methods.
		 */
		int len;
		len = strlen(s->cur_prompt->prompts[0]->result);
		logevent("Sending unpadded password");
		send_packet(ssh, s->pwpkt_type,
                            PKT_INT, len,
			    PKT_DATA, s->cur_prompt->prompts[0]->result, len,
			    PKT_END);
	    }
	} else {
	    send_packet(ssh, s->pwpkt_type,
			PKT_STR, s->cur_prompt->prompts[0]->result,
			PKT_END);
	}
	logevent("Sent password");
	free_prompts(s->cur_prompt);
	crWaitUntil(pktin);
	if (pktin->type == SSH1_SMSG_FAILURE) {
	    if (flags & FLAG_VERBOSE)
		c_write_str(ssh, "Access denied\r\n");
	    logevent("Authentication refused");
	} else if (pktin->type != SSH1_SMSG_SUCCESS) {
	    bombout(("Strange packet received, type %d", pktin->type));
	    crStop(0);
	}
    }

    /* Clear up */
    if (s->publickey_blob) {
	sfree(s->publickey_blob);
	sfree(s->publickey_comment);
    }

    logevent("Authentication successful");

    crFinish(1);
}

static void ssh_channel_try_eof(struct ssh_channel *c)
{
    Ssh ssh = c->ssh;
    assert(c->pending_eof);          /* precondition for calling us */
    if (c->halfopen)
        return;                 /* can't close: not even opened yet */
    if (ssh->version == 2 && bufchain_size(&c->v.v2.outbuffer) > 0)
        return;              /* can't send EOF: pending outgoing data */

    c->pending_eof = FALSE;            /* we're about to send it */
    if (ssh->version == 1) {
        send_packet(ssh, SSH1_MSG_CHANNEL_CLOSE, PKT_INT, c->remoteid,
                    PKT_END);
        c->closes |= CLOSES_SENT_EOF;
    } else {
        struct Packet *pktout;
        pktout = ssh2_pkt_init(SSH2_MSG_CHANNEL_EOF);
        ssh2_pkt_adduint32(pktout, c->remoteid);
        ssh2_pkt_send(ssh, pktout);
        c->closes |= CLOSES_SENT_EOF;
	ssh2_channel_check_close(c);
    }
}

Conf *sshfwd_get_conf(struct ssh_channel *c)
{
    Ssh ssh = c->ssh;
    return ssh->conf;
}

void sshfwd_write_eof(struct ssh_channel *c)
{
    Ssh ssh = c->ssh;

    if (ssh->state == SSH_STATE_CLOSED)
	return;

    if (c->closes & CLOSES_SENT_EOF)
        return;

    c->pending_eof = TRUE;
    ssh_channel_try_eof(c);
}

void sshfwd_unclean_close(struct ssh_channel *c, const char *err)
{
    Ssh ssh = c->ssh;
    char *reason;

    if (ssh->state == SSH_STATE_CLOSED)
	return;

    reason = dupprintf("due to local error: %s", err);
    ssh_channel_close_local(c, reason);
    sfree(reason);
    c->pending_eof = FALSE;   /* this will confuse a zombie channel */

    ssh2_channel_check_close(c);
}

int sshfwd_write(struct ssh_channel *c, char *buf, int len)
{
    Ssh ssh = c->ssh;

    if (ssh->state == SSH_STATE_CLOSED)
	return 0;

    return ssh_send_channel_data(c, buf, len);
}

void sshfwd_unthrottle(struct ssh_channel *c, int bufsize)
{
    Ssh ssh = c->ssh;

    if (ssh->state == SSH_STATE_CLOSED)
	return;

    ssh_channel_unthrottle(c, bufsize);
}

static void ssh_queueing_handler(Ssh ssh, struct Packet *pktin)
{
    struct queued_handler *qh = ssh->qhead;

    assert(qh != NULL);

    assert(pktin->type == qh->msg1 || pktin->type == qh->msg2);

    if (qh->msg1 > 0) {
	assert(ssh->packet_dispatch[qh->msg1] == ssh_queueing_handler);
	ssh->packet_dispatch[qh->msg1] = ssh->q_saved_handler1;
    }
    if (qh->msg2 > 0) {
	assert(ssh->packet_dispatch[qh->msg2] == ssh_queueing_handler);
	ssh->packet_dispatch[qh->msg2] = ssh->q_saved_handler2;
    }

    if (qh->next) {
	ssh->qhead = qh->next;

	if (ssh->qhead->msg1 > 0) {
	    ssh->q_saved_handler1 = ssh->packet_dispatch[ssh->qhead->msg1];
	    ssh->packet_dispatch[ssh->qhead->msg1] = ssh_queueing_handler;
	}
	if (ssh->qhead->msg2 > 0) {
	    ssh->q_saved_handler2 = ssh->packet_dispatch[ssh->qhead->msg2];
	    ssh->packet_dispatch[ssh->qhead->msg2] = ssh_queueing_handler;
	}
    } else {
	ssh->qhead = ssh->qtail = NULL;
    }

    qh->handler(ssh, pktin, qh->ctx);

    sfree(qh);
}

static void ssh_queue_handler(Ssh ssh, int msg1, int msg2,
			      chandler_fn_t handler, void *ctx)
{
    struct queued_handler *qh;

    qh = snew(struct queued_handler);
    qh->msg1 = msg1;
    qh->msg2 = msg2;
    qh->handler = handler;
    qh->ctx = ctx;
    qh->next = NULL;

    if (ssh->qtail == NULL) {
	ssh->qhead = qh;

	if (qh->msg1 > 0) {
	    ssh->q_saved_handler1 = ssh->packet_dispatch[ssh->qhead->msg1];
	    ssh->packet_dispatch[qh->msg1] = ssh_queueing_handler;
	}
	if (qh->msg2 > 0) {
	    ssh->q_saved_handler2 = ssh->packet_dispatch[ssh->qhead->msg2];
	    ssh->packet_dispatch[qh->msg2] = ssh_queueing_handler;
	}
    } else {
	ssh->qtail->next = qh;
    }
    ssh->qtail = qh;
}

static void ssh_rportfwd_succfail(Ssh ssh, struct Packet *pktin, void *ctx)
{
    struct ssh_rportfwd *rpf, *pf = (struct ssh_rportfwd *)ctx;

    if (pktin->type == (ssh->version == 1 ? SSH1_SMSG_SUCCESS :
			SSH2_MSG_REQUEST_SUCCESS)) {
	logeventf(ssh, "Remote port forwarding from %s enabled",
		  pf->sportdesc);
    } else {
	logeventf(ssh, "Remote port forwarding from %s refused",
		  pf->sportdesc);

	rpf = del234(ssh->rportfwds, pf);
	assert(rpf == pf);
	pf->pfrec->remote = NULL;
	free_rportfwd(pf);
    }
}

int ssh_alloc_sharing_rportfwd(Ssh ssh, const char *shost, int sport,
                               void *share_ctx)
{
    struct ssh_rportfwd *pf = snew(struct ssh_rportfwd);
    pf->dhost = NULL;
    pf->dport = 0;
    pf->share_ctx = share_ctx;
    pf->shost = dupstr(shost);
    pf->sport = sport;
    pf->sportdesc = NULL;
    if (!ssh->rportfwds) {
        assert(ssh->version == 2);
        ssh->rportfwds = newtree234(ssh_rportcmp_ssh2);
    }
    if (add234(ssh->rportfwds, pf) != pf) {
        sfree(pf->shost);
        sfree(pf);
        return FALSE;
    }
    return TRUE;
}

static void ssh_sharing_global_request_response(Ssh ssh, struct Packet *pktin,
                                                void *ctx)
{
    share_got_pkt_from_server(ctx, pktin->type,
                              pktin->body, pktin->length);
}

void ssh_sharing_queue_global_request(Ssh ssh, void *share_ctx)
{
    ssh_queue_handler(ssh, SSH2_MSG_REQUEST_SUCCESS, SSH2_MSG_REQUEST_FAILURE,
                      ssh_sharing_global_request_response, share_ctx);
}

static void ssh_setup_portfwd(Ssh ssh, Conf *conf)
{
    struct ssh_portfwd *epf;
    int i;
    char *key, *val;

    if (!ssh->portfwds) {
	ssh->portfwds = newtree234(ssh_portcmp);
    } else {
	/*
	 * Go through the existing port forwardings and tag them
	 * with status==DESTROY. Any that we want to keep will be
	 * re-enabled (status==KEEP) as we go through the
	 * configuration and find out which bits are the same as
	 * they were before.
	 */
	struct ssh_portfwd *epf;
	int i;
	for (i = 0; (epf = index234(ssh->portfwds, i)) != NULL; i++)
	    epf->status = DESTROY;
    }

    for (val = conf_get_str_strs(conf, CONF_portfwd, NULL, &key);
	 val != NULL;
	 val = conf_get_str_strs(conf, CONF_portfwd, key, &key)) {
	char *kp, *kp2, *vp, *vp2;
	char address_family, type;
	int sport,dport,sserv,dserv;
	char *sports, *dports, *saddr, *host;

	kp = key;

	address_family = 'A';
	type = 'L';
	if (*kp == 'A' || *kp == '4' || *kp == '6')
	    address_family = *kp++;
	if (*kp == 'L' || *kp == 'R')
	    type = *kp++;

	if ((kp2 = host_strchr(kp, ':')) != NULL) {
	    /*
	     * There's a colon in the middle of the source port
	     * string, which means that the part before it is
	     * actually a source address.
	     */
	    char *saddr_tmp = dupprintf("%.*s", (int)(kp2 - kp), kp);
            saddr = host_strduptrim(saddr_tmp);
            sfree(saddr_tmp);
	    sports = kp2+1;
	} else {
	    saddr = NULL;
	    sports = kp;
	}
	sport = atoi(sports);
	sserv = 0;
	if (sport == 0) {
	    sserv = 1;
	    sport = net_service_lookup(sports);
	    if (!sport) {
		logeventf(ssh, "Service lookup failed for source"
			  " port \"%s\"", sports);
	    }
	}

	if (type == 'L' && !strcmp(val, "D")) {
            /* dynamic forwarding */
	    host = NULL;
	    dports = NULL;
	    dport = -1;
	    dserv = 0;
            type = 'D';
        } else {
            /* ordinary forwarding */
	    vp = val;
	    vp2 = vp + host_strcspn(vp, ":");
	    host = dupprintf("%.*s", (int)(vp2 - vp), vp);
	    if (*vp2)
		vp2++;
	    dports = vp2;
	    dport = atoi(dports);
	    dserv = 0;
	    if (dport == 0) {
		dserv = 1;
		dport = net_service_lookup(dports);
		if (!dport) {
		    logeventf(ssh, "Service lookup failed for destination"
			      " port \"%s\"", dports);
		}
	    }
	}

	if (sport && dport) {
	    /* Set up a description of the source port. */
	    struct ssh_portfwd *pfrec, *epfrec;

	    pfrec = snew(struct ssh_portfwd);
	    pfrec->type = type;
	    pfrec->saddr = saddr;
	    pfrec->sserv = sserv ? dupstr(sports) : NULL;
	    pfrec->sport = sport;
	    pfrec->daddr = host;
	    pfrec->dserv = dserv ? dupstr(dports) : NULL;
	    pfrec->dport = dport;
	    pfrec->local = NULL;
	    pfrec->remote = NULL;
	    pfrec->addressfamily = (address_family == '4' ? ADDRTYPE_IPV4 :
				    address_family == '6' ? ADDRTYPE_IPV6 :
				    ADDRTYPE_UNSPEC);

	    epfrec = add234(ssh->portfwds, pfrec);
	    if (epfrec != pfrec) {
		if (epfrec->status == DESTROY) {
		    /*
		     * We already have a port forwarding up and running
		     * with precisely these parameters. Hence, no need
		     * to do anything; simply re-tag the existing one
		     * as KEEP.
		     */
		    epfrec->status = KEEP;
		}
		/*
		 * Anything else indicates that there was a duplicate
		 * in our input, which we'll silently ignore.
		 */
		free_portfwd(pfrec);
	    } else {
		pfrec->status = CREATE;
	    }
	} else {
	    sfree(saddr);
	    sfree(host);
	}
    }

    /*
     * Now go through and destroy any port forwardings which were
     * not re-enabled.
     */
    for (i = 0; (epf = index234(ssh->portfwds, i)) != NULL; i++)
	if (epf->status == DESTROY) {
	    char *message;

	    message = dupprintf("%s port forwarding from %s%s%d",
				epf->type == 'L' ? "local" :
				epf->type == 'R' ? "remote" : "dynamic",
				epf->saddr ? epf->saddr : "",
				epf->saddr ? ":" : "",
				epf->sport);

	    if (epf->type != 'D') {
		char *msg2 = dupprintf("%s to %s:%d", message,
				       epf->daddr, epf->dport);
		sfree(message);
		message = msg2;
	    }

	    logeventf(ssh, "Cancelling %s", message);
	    sfree(message);

	    /* epf->remote or epf->local may be NULL if setting up a
	     * forwarding failed. */
	    if (epf->remote) {
		struct ssh_rportfwd *rpf = epf->remote;
		struct Packet *pktout;

		/*
		 * Cancel the port forwarding at the server
		 * end.
		 */
		if (ssh->version == 1) {
		    /*
		     * We cannot cancel listening ports on the
		     * server side in SSH-1! There's no message
		     * to support it. Instead, we simply remove
		     * the rportfwd record from the local end
		     * so that any connections the server tries
		     * to make on it are rejected.
		     */
		} else {
		    pktout = ssh2_pkt_init(SSH2_MSG_GLOBAL_REQUEST);
		    ssh2_pkt_addstring(pktout, "cancel-tcpip-forward");
		    ssh2_pkt_addbool(pktout, 0);/* _don't_ want reply */
		    if (epf->saddr) {
			ssh2_pkt_addstring(pktout, epf->saddr);
		    } else if (conf_get_int(conf, CONF_rport_acceptall)) {
			/* XXX: rport_acceptall may not represent
			 * what was used to open the original connection,
			 * since it's reconfigurable. */
			ssh2_pkt_addstring(pktout, "");
		    } else {
			ssh2_pkt_addstring(pktout, "localhost");
		    }
		    ssh2_pkt_adduint32(pktout, epf->sport);
		    ssh2_pkt_send(ssh, pktout);
		}

		del234(ssh->rportfwds, rpf);
		free_rportfwd(rpf);
	    } else if (epf->local) {
		pfl_terminate(epf->local);
	    }

	    delpos234(ssh->portfwds, i);
	    free_portfwd(epf);
	    i--;		       /* so we don't skip one in the list */
	}

    /*
     * And finally, set up any new port forwardings (status==CREATE).
     */
    for (i = 0; (epf = index234(ssh->portfwds, i)) != NULL; i++)
	if (epf->status == CREATE) {
	    char *sportdesc, *dportdesc;
	    sportdesc = dupprintf("%s%s%s%s%d%s",
				  epf->saddr ? epf->saddr : "",
				  epf->saddr ? ":" : "",
				  epf->sserv ? epf->sserv : "",
				  epf->sserv ? "(" : "",
				  epf->sport,
				  epf->sserv ? ")" : "");
	    if (epf->type == 'D') {
		dportdesc = NULL;
	    } else {
		dportdesc = dupprintf("%s:%s%s%d%s",
				      epf->daddr,
				      epf->dserv ? epf->dserv : "",
				      epf->dserv ? "(" : "",
				      epf->dport,
				      epf->dserv ? ")" : "");
	    }

	    if (epf->type == 'L') {
                char *err = pfl_listen(epf->daddr, epf->dport,
                                       epf->saddr, epf->sport,
                                       ssh, conf, &epf->local,
                                       epf->addressfamily);

		logeventf(ssh, "Local %sport %s forwarding to %s%s%s",
			  epf->addressfamily == ADDRTYPE_IPV4 ? "IPv4 " :
			  epf->addressfamily == ADDRTYPE_IPV6 ? "IPv6 " : "",
			  sportdesc, dportdesc,
			  err ? " failed: " : "", err ? err : "");
                if (err)
                    sfree(err);
	    } else if (epf->type == 'D') {
		char *err = pfl_listen(NULL, -1, epf->saddr, epf->sport,
                                       ssh, conf, &epf->local,
                                       epf->addressfamily);

		logeventf(ssh, "Local %sport %s SOCKS dynamic forwarding%s%s",
			  epf->addressfamily == ADDRTYPE_IPV4 ? "IPv4 " :
			  epf->addressfamily == ADDRTYPE_IPV6 ? "IPv6 " : "",
			  sportdesc,
			  err ? " failed: " : "", err ? err : "");

                if (err)
                    sfree(err);
	    } else {
		struct ssh_rportfwd *pf;

		/*
		 * Ensure the remote port forwardings tree exists.
		 */
		if (!ssh->rportfwds) {
		    if (ssh->version == 1)
			ssh->rportfwds = newtree234(ssh_rportcmp_ssh1);
		    else
			ssh->rportfwds = newtree234(ssh_rportcmp_ssh2);
		}

		pf = snew(struct ssh_rportfwd);
                pf->share_ctx = NULL;
                pf->dhost = dupstr(epf->daddr);
		pf->dport = epf->dport;
                if (epf->saddr) {
                    pf->shost = dupstr(epf->saddr);
                } else if (conf_get_int(conf, CONF_rport_acceptall)) {
                    pf->shost = dupstr("");
                } else {
                    pf->shost = dupstr("localhost");
                }
		pf->sport = epf->sport;
		if (add234(ssh->rportfwds, pf) != pf) {
		    logeventf(ssh, "Duplicate remote port forwarding to %s:%d",
			      epf->daddr, epf->dport);
		    sfree(pf);
		} else {
		    logeventf(ssh, "Requesting remote port %s"
			      " forward to %s", sportdesc, dportdesc);

		    pf->sportdesc = sportdesc;
		    sportdesc = NULL;
		    epf->remote = pf;
		    pf->pfrec = epf;

		    if (ssh->version == 1) {
			send_packet(ssh, SSH1_CMSG_PORT_FORWARD_REQUEST,
				    PKT_INT, epf->sport,
				    PKT_STR, epf->daddr,
				    PKT_INT, epf->dport,
				    PKT_END);
			ssh_queue_handler(ssh, SSH1_SMSG_SUCCESS,
					  SSH1_SMSG_FAILURE,
					  ssh_rportfwd_succfail, pf);
		    } else {
			struct Packet *pktout;
			pktout = ssh2_pkt_init(SSH2_MSG_GLOBAL_REQUEST);
			ssh2_pkt_addstring(pktout, "tcpip-forward");
			ssh2_pkt_addbool(pktout, 1);/* want reply */
			ssh2_pkt_addstring(pktout, pf->shost);
			ssh2_pkt_adduint32(pktout, pf->sport);
			ssh2_pkt_send(ssh, pktout);

			ssh_queue_handler(ssh, SSH2_MSG_REQUEST_SUCCESS,
					  SSH2_MSG_REQUEST_FAILURE,
					  ssh_rportfwd_succfail, pf);
		    }
		}
	    }
	    sfree(sportdesc);
	    sfree(dportdesc);
	}
}

static void ssh1_smsg_stdout_stderr_data(Ssh ssh, struct Packet *pktin)
{
    char *string;
    int stringlen, bufsize;

    ssh_pkt_getstring(pktin, &string, &stringlen);
    if (string == NULL) {
	bombout(("Incoming terminal data packet was badly formed"));
	return;
    }

    bufsize = from_backend(ssh->frontend, pktin->type == SSH1_SMSG_STDERR_DATA,
			   string, stringlen);
    if (!ssh->v1_stdout_throttling && bufsize > SSH1_BUFFER_LIMIT) {
	ssh->v1_stdout_throttling = 1;
	ssh_throttle_conn(ssh, +1);
    }
}

static void ssh1_smsg_x11_open(Ssh ssh, struct Packet *pktin)
{
    /* Remote side is trying to open a channel to talk to our
     * X-Server. Give them back a local channel number. */
    struct ssh_channel *c;
    int remoteid = ssh_pkt_getuint32(pktin);

    logevent("Received X11 connect request");
    /* Refuse if X11 forwarding is disabled. */
    if (!ssh->X11_fwd_enabled) {
	send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_FAILURE,
		    PKT_INT, remoteid, PKT_END);
	logevent("Rejected X11 connect request");
    } else {
	c = snew(struct ssh_channel);
	c->ssh = ssh;

	ssh_channel_init(c);
	c->u.x11.xconn = x11_init(ssh->x11authtree, c, NULL, -1);
        c->remoteid = remoteid;
        c->halfopen = FALSE;
        c->type = CHAN_X11;	/* identify channel type */
        send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_CONFIRMATION,
                    PKT_INT, c->remoteid, PKT_INT,
                    c->localid, PKT_END);
        logevent("Opened X11 forward channel");
    }
}

static void ssh1_smsg_agent_open(Ssh ssh, struct Packet *pktin)
{
    /* Remote side is trying to open a channel to talk to our
     * agent. Give them back a local channel number. */
    struct ssh_channel *c;
    int remoteid = ssh_pkt_getuint32(pktin);

    /* Refuse if agent forwarding is disabled. */
    if (!ssh->agentfwd_enabled) {
	send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_FAILURE,
		    PKT_INT, remoteid, PKT_END);
    } else {
	c = snew(struct ssh_channel);
	c->ssh = ssh;
	ssh_channel_init(c);
	c->remoteid = remoteid;
	c->halfopen = FALSE;
	c->type = CHAN_AGENT;	/* identify channel type */
	c->u.a.pending = NULL;
        bufchain_init(&c->u.a.inbuffer);
	send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_CONFIRMATION,
		    PKT_INT, c->remoteid, PKT_INT, c->localid,
		    PKT_END);
    }
}

static void ssh1_msg_port_open(Ssh ssh, struct Packet *pktin)
{
    /* Remote side is trying to open a channel to talk to a
     * forwarded port. Give them back a local channel number. */
    struct ssh_rportfwd pf, *pfp;
    int remoteid;
    int hostsize, port;
    char *host;
    char *err;

    remoteid = ssh_pkt_getuint32(pktin);
    ssh_pkt_getstring(pktin, &host, &hostsize);
    port = ssh_pkt_getuint32(pktin);

    pf.dhost = dupprintf("%.*s", hostsize, NULLTOEMPTY(host));
    pf.dport = port;
    pfp = find234(ssh->rportfwds, &pf, NULL);

    if (pfp == NULL) {
	logeventf(ssh, "Rejected remote port open request for %s:%d",
		  pf.dhost, port);
	send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_FAILURE,
		    PKT_INT, remoteid, PKT_END);
    } else {
        struct ssh_channel *c = snew(struct ssh_channel);
        c->ssh = ssh;

	logeventf(ssh, "Received remote port open request for %s:%d",
		  pf.dhost, port);
	err = pfd_connect(&c->u.pfd.pf, pf.dhost, port,
                          c, ssh->conf, pfp->pfrec->addressfamily);
	if (err != NULL) {
	    logeventf(ssh, "Port open failed: %s", err);
            sfree(err);
	    sfree(c);
	    send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_FAILURE,
			PKT_INT, remoteid, PKT_END);
	} else {
	    ssh_channel_init(c);
	    c->remoteid = remoteid;
	    c->halfopen = FALSE;
	    c->type = CHAN_SOCKDATA;	/* identify channel type */
	    send_packet(ssh, SSH1_MSG_CHANNEL_OPEN_CONFIRMATION,
			PKT_INT, c->remoteid, PKT_INT,
			c->localid, PKT_END);
	    logevent("Forwarded port opened successfully");
	}
    }

    sfree(pf.dhost);
}

static void ssh1_msg_channel_open_confirmation(Ssh ssh, struct Packet *pktin)
{
    struct ssh_channel *c;

    c = ssh_channel_msg(ssh, pktin);
    if (c && c->type == CHAN_SOCKDATA) {
	c->remoteid = ssh_pkt_getuint32(pktin);
	c->halfopen = FALSE;
	c->throttling_conn = 0;
	pfd_confirm(c->u.pfd.pf);
    }

    if (c && c->pending_eof) {
	/*
	 * We have a pending close on this channel,
	 * which we decided on before the server acked
	 * the channel open. So now we know the
	 * remoteid, we can close it again.
	 */
        ssh_channel_try_eof(c);
    }
}

static void ssh1_msg_channel_open_failure(Ssh ssh, struct Packet *pktin)
{
    struct ssh_channel *c;

    c = ssh_channel_msg(ssh, pktin);
    if (c && c->type == CHAN_SOCKDATA) {
	logevent("Forwarded connection refused by server");
	pfd_close(c->u.pfd.pf);
	del234(ssh->channels, c);
	sfree(c);
    }
}

static void ssh1_msg_channel_close(Ssh ssh, struct Packet *pktin)
{
    /* Remote side closes a channel. */
    struct ssh_channel *c;

    c = ssh_channel_msg(ssh, pktin);
    if (c) {

        if (pktin->type == SSH1_MSG_CHANNEL_CLOSE) {
            /*
             * Received CHANNEL_CLOSE, which we translate into
             * outgoing EOF.
             */
	    ssh_channel_got_eof(c);
        }

        if (pktin->type == SSH1_MSG_CHANNEL_CLOSE_CONFIRMATION &&
            !(c->closes & CLOSES_RCVD_CLOSE)) {

            if (!(c->closes & CLOSES_SENT_EOF)) {
                bombout(("Received CHANNEL_CLOSE_CONFIRMATION for channel %u"
                         " for which we never sent CHANNEL_CLOSE\n",
			 c->localid));
            }

            c->closes |= CLOSES_RCVD_CLOSE;
        }

        if (!((CLOSES_SENT_EOF | CLOSES_RCVD_EOF) & ~c->closes) &&
            !(c->closes & CLOSES_SENT_CLOSE)) {
            send_packet(ssh, SSH1_MSG_CHANNEL_CLOSE_CONFIRMATION,
                        PKT_INT, c->remoteid, PKT_END);
            c->closes |= CLOSES_SENT_CLOSE;
        }

	if (!((CLOSES_SENT_CLOSE | CLOSES_RCVD_CLOSE) & ~c->closes))
            ssh_channel_destroy(c);
    }
}

/*
 * Handle incoming data on an SSH-1 or SSH-2 agent-forwarding channel.
 */
static int ssh_agent_channel_data(struct ssh_channel *c, char *data,
				  int length)
{
    bufchain_add(&c->u.a.inbuffer, data, length);
    ssh_agentf_try_forward(c);

    /*
     * We exert back-pressure on an agent forwarding client if and
     * only if we're waiting for the response to an asynchronous agent
     * request. This prevents the client running out of window while
     * receiving the _first_ message, but means that if any message
     * takes time to process, the client will be discouraged from
     * sending an endless stream of further ones after it.
     */
    return (c->u.a.pending ? bufchain_size(&c->u.a.inbuffer) : 0);
}

static int ssh_channel_data(struct ssh_channel *c, int is_stderr,
			    char *data,  int length)
{
    switch (c->type) {
      case CHAN_MAINSESSION:
	return from_backend(c->ssh->frontend, is_stderr, data, length);
      case CHAN_X11:
	return x11_send(c->u.x11.xconn, data, length);
      case CHAN_SOCKDATA:
	return pfd_send(c->u.pfd.pf, data, length);
      case CHAN_AGENT:
	return ssh_agent_channel_data(c, data, length);
    }
    return 0;
}

static void ssh1_msg_channel_data(Ssh ssh, struct Packet *pktin)
{
    /* Data sent down one of our channels. */
    char *p;
    int len;
    struct ssh_channel *c;

    c = ssh_channel_msg(ssh, pktin);
    ssh_pkt_getstring(pktin, &p, &len);

    if (c) {
	int bufsize = ssh_channel_data(c, FALSE, p, len);
	if (!c->throttling_conn && bufsize > SSH1_BUFFER_LIMIT) {
	    c->throttling_conn = 1;
	    ssh_throttle_conn(ssh, +1);
	}
    }
}

static void ssh1_smsg_exit_status(Ssh ssh, struct Packet *pktin)
{
    ssh->exitcode = ssh_pkt_getuint32(pktin);
    logeventf(ssh, "Server sent command exit status %d", ssh->exitcode);
    send_packet(ssh, SSH1_CMSG_EXIT_CONFIRMATION, PKT_END);
    /*
     * In case `helpful' firewalls or proxies tack
     * extra human-readable text on the end of the
     * session which we might mistake for another
     * encrypted packet, we close the session once
     * we've sent EXIT_CONFIRMATION.
     */
    ssh_disconnect(ssh, NULL, NULL, 0, TRUE);
}

/* Helper function to deal with sending tty modes for REQUEST_PTY */
static void ssh1_send_ttymode(void *data,
                              const struct ssh_ttymode *mode, char *val)
{
    struct Packet *pktout = (struct Packet *)data;
    unsigned int arg = 0;

    switch (mode->type) {
      case TTY_OP_CHAR:
	arg = ssh_tty_parse_specchar(val);
	break;
      case TTY_OP_BOOL:
	arg = ssh_tty_parse_boolean(val);
	break;
    }
    ssh2_pkt_addbyte(pktout, mode->opcode);
    ssh2_pkt_addbyte(pktout, arg);
}

int ssh_agent_forwarding_permitted(Ssh ssh)
{
    return conf_get_int(ssh->conf, CONF_agentfwd) && agent_exists();
}

static void do_ssh1_connection(Ssh ssh, const unsigned char *in, int inlen,
			       struct Packet *pktin)
{
    crBegin(ssh->do_ssh1_connection_crstate);

    ssh->packet_dispatch[SSH1_SMSG_STDOUT_DATA] = 
	ssh->packet_dispatch[SSH1_SMSG_STDERR_DATA] =
	ssh1_smsg_stdout_stderr_data;

    ssh->packet_dispatch[SSH1_MSG_CHANNEL_OPEN_CONFIRMATION] =
	ssh1_msg_channel_open_confirmation;
    ssh->packet_dispatch[SSH1_MSG_CHANNEL_OPEN_FAILURE] =
	ssh1_msg_channel_open_failure;
    ssh->packet_dispatch[SSH1_MSG_CHANNEL_CLOSE] =
	ssh->packet_dispatch[SSH1_MSG_CHANNEL_CLOSE_CONFIRMATION] =
	ssh1_msg_channel_close;
    ssh->packet_dispatch[SSH1_MSG_CHANNEL_DATA] = ssh1_msg_channel_data;
    ssh->packet_dispatch[SSH1_SMSG_EXIT_STATUS] = ssh1_smsg_exit_status;

    if (ssh_agent_forwarding_permitted(ssh)) {
	logevent("Requesting agent forwarding");
	send_packet(ssh, SSH1_CMSG_AGENT_REQUEST_FORWARDING, PKT_END);
	do {
	    crReturnV;
	} while (!pktin);
	if (pktin->type != SSH1_SMSG_SUCCESS
	    && pktin->type != SSH1_SMSG_FAILURE) {
	    bombout(("Protocol confusion"));
	    crStopV;
	} else if (pktin->type == SSH1_SMSG_FAILURE) {
	    logevent("Agent forwarding refused");
	} else {
	    logevent("Agent forwarding enabled");
	    ssh->agentfwd_enabled = TRUE;
	    ssh->packet_dispatch[SSH1_SMSG_AGENT_OPEN] = ssh1_smsg_agent_open;
	}
    }

    if (conf_get_int(ssh->conf, CONF_x11_forward)) {
        ssh->x11disp =
            x11_setup_display(conf_get_str(ssh->conf, CONF_x11_display),
                              ssh->conf);
        if (!ssh->x11disp) {
            /* FIXME: return an error message from x11_setup_display */
            logevent("X11 forwarding not enabled: unable to"
                     " initialise X display");
        } else {
            ssh->x11auth = x11_invent_fake_auth
                (ssh->x11authtree, conf_get_int(ssh->conf, CONF_x11_auth));
            ssh->x11auth->disp = ssh->x11disp;

            logevent("Requesting X11 forwarding");
            if (ssh->v1_local_protoflags & SSH1_PROTOFLAG_SCREEN_NUMBER) {
                send_packet(ssh, SSH1_CMSG_X11_REQUEST_FORWARDING,
                            PKT_STR, ssh->x11auth->protoname,
                            PKT_STR, ssh->x11auth->datastring,
                            PKT_INT, ssh->x11disp->screennum,
                            PKT_END);
            } else {
                send_packet(ssh, SSH1_CMSG_X11_REQUEST_FORWARDING,
                            PKT_STR, ssh->x11auth->protoname,
                            PKT_STR, ssh->x11auth->datastring,
                            PKT_END);
            }
            do {
                crReturnV;
            } while (!pktin);
            if (pktin->type != SSH1_SMSG_SUCCESS
                && pktin->type != SSH1_SMSG_FAILURE) {
                bombout(("Protocol confusion"));
                crStopV;
            } else if (pktin->type == SSH1_SMSG_FAILURE) {
                logevent("X11 forwarding refused");
            } else {
                logevent("X11 forwarding enabled");
                ssh->X11_fwd_enabled = TRUE;
                ssh->packet_dispatch[SSH1_SMSG_X11_OPEN] = ssh1_smsg_x11_open;
            }
        }
    }

    ssh_setup_portfwd(ssh, ssh->conf);
    ssh->packet_dispatch[SSH1_MSG_PORT_OPEN] = ssh1_msg_port_open;

    if (!conf_get_int(ssh->conf, CONF_nopty)) {
	struct Packet *pkt;
	/* Unpick the terminal-speed string. */
	/* XXX perhaps we should allow no speeds to be sent. */
	ssh->ospeed = 38400; ssh->ispeed = 38400; /* last-resort defaults */
	sscanf(conf_get_str(ssh->conf, CONF_termspeed), "%d,%d", &ssh->ospeed, &ssh->ispeed);
	/* Send the pty request. */
	pkt = ssh1_pkt_init(SSH1_CMSG_REQUEST_PTY);
	ssh_pkt_addstring(pkt, conf_get_str(ssh->conf, CONF_termtype));
	ssh_pkt_adduint32(pkt, ssh->term_height);
	ssh_pkt_adduint32(pkt, ssh->term_width);
	ssh_pkt_adduint32(pkt, 0); /* width in pixels */
	ssh_pkt_adduint32(pkt, 0); /* height in pixels */
	parse_ttymodes(ssh, ssh1_send_ttymode, (void *)pkt);
	ssh_pkt_addbyte(pkt, SSH1_TTY_OP_ISPEED);
	ssh_pkt_adduint32(pkt, ssh->ispeed);
	ssh_pkt_addbyte(pkt, SSH1_TTY_OP_OSPEED);
	ssh_pkt_adduint32(pkt, ssh->ospeed);
	ssh_pkt_addbyte(pkt, SSH_TTY_OP_END);
	s_wrpkt(ssh, pkt);
	ssh->state = SSH_STATE_INTERMED;
	do {
	    crReturnV;
	} while (!pktin);
	if (pktin->type != SSH1_SMSG_SUCCESS
	    && pktin->type != SSH1_SMSG_FAILURE) {
	    bombout(("Protocol confusion"));
	    crStopV;
	} else if (pktin->type == SSH1_SMSG_FAILURE) {
	    c_write_str(ssh, "Server refused to allocate pty\r\n");
	    ssh->editing = ssh->echoing = 1;
	} else {
            logeventf(ssh, "Allocated pty (ospeed %dbps, ispeed %dbps)",
                      ssh->ospeed, ssh->ispeed);
            ssh->got_pty = TRUE;
        }
    } else {
	ssh->editing = ssh->echoing = 1;
    }

    if (conf_get_int(ssh->conf, CONF_compression)) {
	send_packet(ssh, SSH1_CMSG_REQUEST_COMPRESSION, PKT_INT, 6, PKT_END);
	do {
	    crReturnV;
	} while (!pktin);
	if (pktin->type != SSH1_SMSG_SUCCESS
	    && pktin->type != SSH1_SMSG_FAILURE) {
	    bombout(("Protocol confusion"));
	    crStopV;
	} else if (pktin->type == SSH1_SMSG_FAILURE) {
	    c_write_str(ssh, "Server refused to compress\r\n");
	}
	logevent("Started compression");
	ssh->v1_compressing = TRUE;
	ssh->cs_comp_ctx = zlib_compress_init();
	logevent("Initialised zlib (RFC1950) compression");
	ssh->sc_comp_ctx = zlib_decompress_init();
	logevent("Initialised zlib (RFC1950) decompression");
    }

    /*
     * Start the shell or command.
     * 
     * Special case: if the first-choice command is an SSH-2
     * subsystem (hence not usable here) and the second choice
     * exists, we fall straight back to that.
     */
    {
	char *cmd = conf_get_str(ssh->conf, CONF_remote_cmd);
	
	if (conf_get_int(ssh->conf, CONF_ssh_subsys) &&
	    conf_get_str(ssh->conf, CONF_remote_cmd2)) {
	    cmd = conf_get_str(ssh->conf, CONF_remote_cmd2);
	    ssh->fallback_cmd = TRUE;
	}
	if (*cmd)
	    send_packet(ssh, SSH1_CMSG_EXEC_CMD, PKT_STR, cmd, PKT_END);
	else
	    send_packet(ssh, SSH1_CMSG_EXEC_SHELL, PKT_END);
	logevent("Started session");
    }

    ssh->state = SSH_STATE_SESSION;
    if (ssh->size_needed)
	ssh_size(ssh, ssh->term_width, ssh->term_height);
    if (ssh->eof_needed)
	ssh_special(ssh, TS_EOF);

    if (ssh->ldisc)
	ldisc_echoedit_update(ssh->ldisc);  /* cause ldisc to notice changes */
    ssh->send_ok = 1;
    ssh->channels = newtree234(ssh_channelcmp);
    while (1) {

	/*
	 * By this point, most incoming packets are already being
	 * handled by the dispatch table, and we need only pay
	 * attention to the unusual ones.
	 */

	crReturnV;
	if (pktin) {
	    if (pktin->type == SSH1_SMSG_SUCCESS) {
		/* may be from EXEC_SHELL on some servers */
	    } else if (pktin->type == SSH1_SMSG_FAILURE) {
		/* may be from EXEC_SHELL on some servers
		 * if no pty is available or in other odd cases. Ignore */
	    } else {
		bombout(("Strange packet received: type %d", pktin->type));
		crStopV;
	    }
	} else {
	    while (inlen > 0) {
		int len = min(inlen, 512);
		send_packet(ssh, SSH1_CMSG_STDIN_DATA,
			    PKT_INT, len, PKT_DATA, in, len,
                            PKT_END);
		in += len;
		inlen -= len;
	    }
	}
    }

    crFinishV;
}

/*
 * Handle the top-level SSH-2 protocol.
 */
static void ssh1_msg_debug(Ssh ssh, struct Packet *pktin)
{
    char *msg;
    int msglen;

    ssh_pkt_getstring(pktin, &msg, &msglen);
    logeventf(ssh, "Remote debug message: %.*s", msglen, NULLTOEMPTY(msg));
}

static void ssh1_msg_disconnect(Ssh ssh, struct Packet *pktin)
{
    /* log reason code in disconnect message */
    char *msg;
    int msglen;

    ssh_pkt_getstring(pktin, &msg, &msglen);
    bombout(("Server sent disconnect message:\n\"%.*s\"",
             msglen, NULLTOEMPTY(msg)));
}

static void ssh_msg_ignore(Ssh ssh, struct Packet *pktin)
{
    /* Do nothing, because we're ignoring it! Duhh. */
}

static void ssh1_protocol_setup(Ssh ssh)
{
    int i;

    /*
     * Most messages are handled by the coroutines.
     */
    for (i = 0; i < 256; i++)
	ssh->packet_dispatch[i] = NULL;

    /*
     * These special message types we install handlers for.
     */
    ssh->packet_dispatch[SSH1_MSG_DISCONNECT] = ssh1_msg_disconnect;
    ssh->packet_dispatch[SSH1_MSG_IGNORE] = ssh_msg_ignore;
    ssh->packet_dispatch[SSH1_MSG_DEBUG] = ssh1_msg_debug;
}

static void ssh1_protocol(Ssh ssh, const void *vin, int inlen,
			  struct Packet *pktin)
{
    const unsigned char *in = (const unsigned char *)vin;
    if (ssh->state == SSH_STATE_CLOSED)
	return;

    if (pktin && ssh->packet_dispatch[pktin->type]) {
	ssh->packet_dispatch[pktin->type](ssh, pktin);
	return;
    }

    if (!ssh->protocol_initial_phase_done) {
	if (do_ssh1_login(ssh, in, inlen, pktin))
	    ssh->protocol_initial_phase_done = TRUE;
	else
	    return;
    }

    do_ssh1_connection(ssh, in, inlen, pktin);
}

/*
 * Utility routines for decoding comma-separated strings in KEXINIT.
 */
static int first_in_commasep_string(char const *needle, char const *haystack,
				    int haylen)
{
    int needlen;
    if (!needle || !haystack)	       /* protect against null pointers */
	return 0;
    needlen = strlen(needle);

    if (haylen >= needlen &&       /* haystack is long enough */
	!memcmp(needle, haystack, needlen) &&	/* initial match */
	(haylen == needlen || haystack[needlen] == ',')
	/* either , or EOS follows */
	)
	return 1;
    return 0;
}

static int in_commasep_string(char const *needle, char const *haystack,
			      int haylen)
{
    char *p;

    if (!needle || !haystack)	       /* protect against null pointers */
	return 0;
    /*
     * Is it at the start of the string?
     */
    if (first_in_commasep_string(needle, haystack, haylen))
	return 1;
    /*
     * If not, search for the next comma and resume after that.
     * If no comma found, terminate.
     */
    p = memchr(haystack, ',', haylen);
    if (!p) return 0;
    /* + 1 to skip over comma */
    return in_commasep_string(needle, p + 1, haylen - (p + 1 - haystack));
}

/*
 * Add a value to the comma-separated string at the end of the packet.
 */
static void ssh2_pkt_addstring_commasep(struct Packet *pkt, const char *data)
{
    if (pkt->length - pkt->savedpos > 0)
	ssh_pkt_addstring_str(pkt, ",");
    ssh_pkt_addstring_str(pkt, data);
}


/*
 * SSH-2 key derivation (RFC 4253 section 7.2).
 */
static unsigned char *ssh2_mkkey(Ssh ssh, Bignum K, unsigned char *H,
                                 char chr, int keylen)
{
    const struct ssh_hash *h = ssh->kex->hash;
    int keylen_padded;
    unsigned char *key;
    void *s, *s2;

    if (keylen == 0)
        return NULL;

    /* Round up to the next multiple of hash length. */
    keylen_padded = ((keylen + h->hlen - 1) / h->hlen) * h->hlen;

    key = snewn(keylen_padded, unsigned char);

    /* First hlen bytes. */
    s = h->init();
    if (!(ssh->remote_bugs & BUG_SSH2_DERIVEKEY))
	hash_mpint(h, s, K);
    h->bytes(s, H, h->hlen);
    h->bytes(s, &chr, 1);
    h->bytes(s, ssh->v2_session_id, ssh->v2_session_id_len);
    h->final(s, key);

    /* Subsequent blocks of hlen bytes. */
    if (keylen_padded > h->hlen) {
        int offset;

        s = h->init();
        if (!(ssh->remote_bugs & BUG_SSH2_DERIVEKEY))
            hash_mpint(h, s, K);
        h->bytes(s, H, h->hlen);

        for (offset = h->hlen; offset < keylen_padded; offset += h->hlen) {
            h->bytes(s, key + offset - h->hlen, h->hlen);
            s2 = h->copy(s);
            h->final(s2, key + offset);
        }

        h->free(s);
    }

    /* Now clear any extra bytes of key material beyond the length
     * we're officially returning, because the caller won't know to
     * smemclr those. */
    if (keylen_padded > keylen)
        smemclr(key + keylen, keylen_padded - keylen);

    return key;
}

/*
 * Structure for constructing KEXINIT algorithm lists.
 */
#define MAXKEXLIST 16
struct kexinit_algorithm {
    const char *name;
    union {
	struct {
	    const struct ssh_kex *kex;
	    int warn;
	} kex;
	struct {
            const struct ssh_signkey *hostkey;
            int warn;
        } hk;
	struct {
	    const struct ssh2_cipher *cipher;
	    int warn;
	} cipher;
	struct {
	    const struct ssh_mac *mac;
	    int etm;
	} mac;
	const struct ssh_compress *comp;
    } u;
};

/*
 * Find a slot in a KEXINIT algorithm list to use for a new algorithm.
 * If the algorithm is already in the list, return a pointer to its
 * entry, otherwise return an entry from the end of the list.
 * This assumes that every time a particular name is passed in, it
 * comes from the same string constant.  If this isn't true, this
 * function may need to be rewritten to use strcmp() instead.
 */
static struct kexinit_algorithm *ssh2_kexinit_addalg(struct kexinit_algorithm
						     *list, const char *name)
{
    int i;

    for (i = 0; i < MAXKEXLIST; i++)
	if (list[i].name == NULL || list[i].name == name) {
	    list[i].name = name;
	    return &list[i];
	}
    assert(!"No space in KEXINIT list");
    return NULL;
}

/*
 * Handle the SSH-2 transport layer.
 */
static void do_ssh2_transport(Ssh ssh, const void *vin, int inlen,
			     struct Packet *pktin)
{
    const unsigned char *in = (const unsigned char *)vin;
    enum kexlist {
	KEXLIST_KEX, KEXLIST_HOSTKEY, KEXLIST_CSCIPHER, KEXLIST_SCCIPHER,
	KEXLIST_CSMAC, KEXLIST_SCMAC, KEXLIST_CSCOMP, KEXLIST_SCCOMP,
	NKEXLIST
    };
    const char * kexlist_descr[NKEXLIST] = {
	"key exchange algorithm", "host key algorithm",
	"client-to-server cipher", "server-to-client cipher",
	"client-to-server MAC", "server-to-client MAC",
	"client-to-server compression method",
	"server-to-client compression method" };
    struct do_ssh2_transport_state {
	int crLine;
	int nbits, pbits, warn_kex, warn_hk, warn_cscipher, warn_sccipher;
	Bignum p, g, e, f, K;
	void *our_kexinit;
	int our_kexinitlen;
	int kex_init_value, kex_reply_value;
	const struct ssh_mac *const *maclist;
	int nmacs;
	const struct ssh2_cipher *cscipher_tobe;
	const struct ssh2_cipher *sccipher_tobe;
	const struct ssh_mac *csmac_tobe;
	const struct ssh_mac *scmac_tobe;
        int csmac_etm_tobe, scmac_etm_tobe;
	const struct ssh_compress *cscomp_tobe;
	const struct ssh_compress *sccomp_tobe;
	char *hostkeydata, *sigdata, *rsakeydata, *keystr, *fingerprint;
	int hostkeylen, siglen, rsakeylen;
	void *hkey;		       /* actual host key */
	void *rsakey;		       /* for RSA kex */
        void *eckey;                   /* for ECDH kex */
	unsigned char exchange_hash[SSH2_KEX_MAX_HASH_LEN];
	int n_preferred_kex;
	const struct ssh_kexes *preferred_kex[KEX_MAX];
	int n_preferred_hk;
	int preferred_hk[HK_MAX];
	int n_preferred_ciphers;
	const struct ssh2_ciphers *preferred_ciphers[CIPHER_MAX];
	const struct ssh_compress *preferred_comp;
	int userauth_succeeded;	    /* for delayed compression */
	int pending_compression;
	int got_session_id, activated_authconn;
	struct Packet *pktout;
        int dlgret;
	int guessok;
	int ignorepkt;
	struct kexinit_algorithm kexlists[NKEXLIST][MAXKEXLIST];
    };
    crState(do_ssh2_transport_state);

    assert(!ssh->bare_connection);
    assert(ssh->version == 2);

    crBeginState;

    s->cscipher_tobe = s->sccipher_tobe = NULL;
    s->csmac_tobe = s->scmac_tobe = NULL;
    s->cscomp_tobe = s->sccomp_tobe = NULL;

    s->got_session_id = s->activated_authconn = FALSE;
    s->userauth_succeeded = FALSE;
    s->pending_compression = FALSE;

    /*
     * Be prepared to work around the buggy MAC problem.
     */
    if (ssh->remote_bugs & BUG_SSH2_HMAC)
	s->maclist = buggymacs, s->nmacs = lenof(buggymacs);
    else
	s->maclist = macs, s->nmacs = lenof(macs);

  begin_key_exchange:
    ssh->pkt_kctx = SSH2_PKTCTX_NOKEX;
    {
	int i, j, k, warn;
	struct kexinit_algorithm *alg;

	/*
	 * Set up the preferred key exchange. (NULL => warn below here)
	 */
	s->n_preferred_kex = 0;
	for (i = 0; i < KEX_MAX; i++) {
	    switch (conf_get_int_int(ssh->conf, CONF_ssh_kexlist, i)) {
	      case KEX_DHGEX:
		s->preferred_kex[s->n_preferred_kex++] =
		    &ssh_diffiehellman_gex;
		break;
	      case KEX_DHGROUP14:
		s->preferred_kex[s->n_preferred_kex++] =
		    &ssh_diffiehellman_group14;
		break;
	      case KEX_DHGROUP1:
		s->preferred_kex[s->n_preferred_kex++] =
		    &ssh_diffiehellman_group1;
		break;
	      case KEX_RSA:
		s->preferred_kex[s->n_preferred_kex++] =
		    &ssh_rsa_kex;
		break;
              case KEX_ECDH:
                s->preferred_kex[s->n_preferred_kex++] =
                    &ssh_ecdh_kex;
                break;
	      case KEX_WARN:
		/* Flag for later. Don't bother if it's the last in
		 * the list. */
		if (i < KEX_MAX - 1) {
		    s->preferred_kex[s->n_preferred_kex++] = NULL;
		}
		break;
	    }
	}

	/*
	 * Set up the preferred host key types. These are just the ids
	 * in the enum in putty.h, so 'warn below here' is indicated
	 * by HK_WARN.
	 */
	s->n_preferred_hk = 0;
	for (i = 0; i < HK_MAX; i++) {
            int id = conf_get_int_int(ssh->conf, CONF_ssh_hklist, i);
            /* As above, don't bother with HK_WARN if it's last in the
             * list */
	    if (id != HK_WARN || i < HK_MAX - 1)
                s->preferred_hk[s->n_preferred_hk++] = id;
	}

	/*
	 * Set up the preferred ciphers. (NULL => warn below here)
	 */
	s->n_preferred_ciphers = 0;
	for (i = 0; i < CIPHER_MAX; i++) {
	    switch (conf_get_int_int(ssh->conf, CONF_ssh_cipherlist, i)) {
	      case CIPHER_BLOWFISH:
		s->preferred_ciphers[s->n_preferred_ciphers++] = &ssh2_blowfish;
		break;
	      case CIPHER_DES:
		if (conf_get_int(ssh->conf, CONF_ssh2_des_cbc)) {
		    s->preferred_ciphers[s->n_preferred_ciphers++] = &ssh2_des;
		}
		break;
	      case CIPHER_3DES:
		s->preferred_ciphers[s->n_preferred_ciphers++] = &ssh2_3des;
		break;
	      case CIPHER_AES:
		s->preferred_ciphers[s->n_preferred_ciphers++] = &ssh2_aes;
		break;
	      case CIPHER_ARCFOUR:
		s->preferred_ciphers[s->n_preferred_ciphers++] = &ssh2_arcfour;
		break;
              case CIPHER_CHACHA20:
                s->preferred_ciphers[s->n_preferred_ciphers++] = &ssh2_ccp;
                break;
	      case CIPHER_WARN:
		/* Flag for later. Don't bother if it's the last in
		 * the list. */
		if (i < CIPHER_MAX - 1) {
		    s->preferred_ciphers[s->n_preferred_ciphers++] = NULL;
		}
		break;
	    }
	}

	/*
	 * Set up preferred compression.
	 */
	if (conf_get_int(ssh->conf, CONF_compression))
	    s->preferred_comp = &ssh_zlib;
	else
	    s->preferred_comp = &ssh_comp_none;

	/*
	 * Enable queueing of outgoing auth- or connection-layer
	 * packets while we are in the middle of a key exchange.
	 */
	ssh->queueing = TRUE;

	/*
	 * Flag that KEX is in progress.
	 */
	ssh->kex_in_progress = TRUE;

	for (i = 0; i < NKEXLIST; i++)
	    for (j = 0; j < MAXKEXLIST; j++)
	        s->kexlists[i][j].name = NULL;
	/* List key exchange algorithms. */
	warn = FALSE;
	for (i = 0; i < s->n_preferred_kex; i++) {
	    const struct ssh_kexes *k = s->preferred_kex[i];
	    if (!k) warn = TRUE;
	    else for (j = 0; j < k->nkexes; j++) {
		alg = ssh2_kexinit_addalg(s->kexlists[KEXLIST_KEX],
					  k->list[j]->name);
	        alg->u.kex.kex = k->list[j];
		alg->u.kex.warn = warn;
	    }
	}
	/* List server host key algorithms. */
        if (!s->got_session_id) {
            /*
             * In the first key exchange, we list all the algorithms
             * we're prepared to cope with, but prefer those algorithms
	     * for which we have a host key for this host.
             *
             * If the host key algorithm is below the warning
             * threshold, we warn even if we did already have a key
             * for it, on the basis that if the user has just
             * reconfigured that host key type to be warned about,
             * they surely _do_ want to be alerted that a server
             * they're actually connecting to is using it.
             */
            warn = FALSE;
            for (i = 0; i < s->n_preferred_hk; i++) {
                if (s->preferred_hk[i] == HK_WARN)
                    warn = TRUE;
                for (j = 0; j < lenof(hostkey_algs); j++) {
                    if (hostkey_algs[j].id != s->preferred_hk[i])
                        continue;
                    if (have_ssh_host_key(ssh->savedhost, ssh->savedport,
                                          hostkey_algs[j].alg->keytype)) {
                        alg = ssh2_kexinit_addalg(s->kexlists[KEXLIST_HOSTKEY],
                                                  hostkey_algs[j].alg->name);
                        alg->u.hk.hostkey = hostkey_algs[j].alg;
                        alg->u.hk.warn = warn;
                    }
                }
	    }
            warn = FALSE;
            for (i = 0; i < s->n_preferred_hk; i++) {
                if (s->preferred_hk[i] == HK_WARN)
                    warn = TRUE;
                for (j = 0; j < lenof(hostkey_algs); j++) {
                    if (hostkey_algs[j].id != s->preferred_hk[i])
                        continue;
                    alg = ssh2_kexinit_addalg(s->kexlists[KEXLIST_HOSTKEY],
                                              hostkey_algs[j].alg->name);
                    alg->u.hk.hostkey = hostkey_algs[j].alg;
                    alg->u.hk.warn = warn;
                }
            }
        } else {
            /*
             * In subsequent key exchanges, we list only the kex
             * algorithm that was selected in the first key exchange,
             * so that we keep getting the same host key and hence
             * don't have to interrupt the user's session to ask for
             * reverification.
             */
            assert(ssh->kex);
	    alg = ssh2_kexinit_addalg(s->kexlists[KEXLIST_HOSTKEY],
				      ssh->hostkey->name);
	    alg->u.hk.hostkey = ssh->hostkey;
            alg->u.hk.warn = FALSE;
        }
	/* List encryption algorithms (client->server then server->client). */
	for (k = KEXLIST_CSCIPHER; k <= KEXLIST_SCCIPHER; k++) {
	    warn = FALSE;
#ifdef FUZZING
	    alg = ssh2_kexinit_addalg(s->kexlists[k], "none");
	    alg->u.cipher.cipher = NULL;
	    alg->u.cipher.warn = warn;
#endif /* FUZZING */
	    for (i = 0; i < s->n_preferred_ciphers; i++) {
		const struct ssh2_ciphers *c = s->preferred_ciphers[i];
		if (!c) warn = TRUE;
		else for (j = 0; j < c->nciphers; j++) {
		    alg = ssh2_kexinit_addalg(s->kexlists[k],
					      c->list[j]->name);
		    alg->u.cipher.cipher = c->list[j];
		    alg->u.cipher.warn = warn;
		}
	    }
	}
	/* List MAC algorithms (client->server then server->client). */
	for (j = KEXLIST_CSMAC; j <= KEXLIST_SCMAC; j++) {
#ifdef FUZZING
	    alg = ssh2_kexinit_addalg(s->kexlists[j], "none");
	    alg->u.mac.mac = NULL;
	    alg->u.mac.etm = FALSE;
#endif /* FUZZING */
	    for (i = 0; i < s->nmacs; i++) {
		alg = ssh2_kexinit_addalg(s->kexlists[j], s->maclist[i]->name);
		alg->u.mac.mac = s->maclist[i];
		alg->u.mac.etm = FALSE;
            }
	    for (i = 0; i < s->nmacs; i++)
                /* For each MAC, there may also be an ETM version,
                 * which we list second. */
                if (s->maclist[i]->etm_name) {
		    alg = ssh2_kexinit_addalg(s->kexlists[j],
					      s->maclist[i]->etm_name);
		    alg->u.mac.mac = s->maclist[i];
		    alg->u.mac.etm = TRUE;
		}
	}
	/* List client->server compression algorithms,
	 * then server->client compression algorithms. (We use the
	 * same set twice.) */
	for (j = KEXLIST_CSCOMP; j <= KEXLIST_SCCOMP; j++) {
	    assert(lenof(compressions) > 1);
	    /* Prefer non-delayed versions */
	    alg = ssh2_kexinit_addalg(s->kexlists[j], s->preferred_comp->name);
	    alg->u.comp = s->preferred_comp;
	    /* We don't even list delayed versions of algorithms until
	     * they're allowed to be used, to avoid a race. See the end of
	     * this function. */
	    if (s->userauth_succeeded && s->preferred_comp->delayed_name) {
		alg = ssh2_kexinit_addalg(s->kexlists[j],
					  s->preferred_comp->delayed_name);
		alg->u.comp = s->preferred_comp;
	    }
	    for (i = 0; i < lenof(compressions); i++) {
		const struct ssh_compress *c = compressions[i];
		alg = ssh2_kexinit_addalg(s->kexlists[j], c->name);
		alg->u.comp = c;
		if (s->userauth_succeeded && c->delayed_name) {
		    alg = ssh2_kexinit_addalg(s->kexlists[j], c->delayed_name);
		    alg->u.comp = c;
		}
	    }
	}
	/*
	 * Construct and send our key exchange packet.
	 */
	s->pktout = ssh2_pkt_init(SSH2_MSG_KEXINIT);
	for (i = 0; i < 16; i++)
	    ssh2_pkt_addbyte(s->pktout, (unsigned char) random_byte());
	for (i = 0; i < NKEXLIST; i++) {
	    ssh2_pkt_addstring_start(s->pktout);
	    for (j = 0; j < MAXKEXLIST; j++) {
		if (s->kexlists[i][j].name == NULL) break;
		ssh2_pkt_addstring_commasep(s->pktout, s->kexlists[i][j].name);
	    }
	}
	/* List client->server languages. Empty list. */
	ssh2_pkt_addstring_start(s->pktout);
	/* List server->client languages. Empty list. */
	ssh2_pkt_addstring_start(s->pktout);
	/* First KEX packet does _not_ follow, because we're not that brave. */
	ssh2_pkt_addbool(s->pktout, FALSE);
	/* Reserved. */
	ssh2_pkt_adduint32(s->pktout, 0);
    }

    s->our_kexinitlen = s->pktout->length - 5;
    s->our_kexinit = snewn(s->our_kexinitlen, unsigned char);
    memcpy(s->our_kexinit, s->pktout->data + 5, s->our_kexinitlen); 

    ssh2_pkt_send_noqueue(ssh, s->pktout);

    if (!pktin)
	crWaitUntilV(pktin);

    /*
     * Now examine the other side's KEXINIT to see what we're up
     * to.
     */
    {
	char *str;
	int i, j, len;

	if (pktin->type != SSH2_MSG_KEXINIT) {
	    bombout(("expected key exchange packet from server"));
	    crStopV;
	}
	ssh->kex = NULL;
	ssh->hostkey = NULL;
	s->cscipher_tobe = NULL;
	s->sccipher_tobe = NULL;
	s->csmac_tobe = NULL;
	s->scmac_tobe = NULL;
	s->cscomp_tobe = NULL;
	s->sccomp_tobe = NULL;
	s->warn_kex = s->warn_hk = FALSE;
        s->warn_cscipher = s->warn_sccipher = FALSE;

	pktin->savedpos += 16;	        /* skip garbage cookie */

	s->guessok = FALSE;
	for (i = 0; i < NKEXLIST; i++) {
	    ssh_pkt_getstring(pktin, &str, &len);
	    if (!str) {
		bombout(("KEXINIT packet was incomplete"));
		crStopV;
	    }

            /* If we've already selected a cipher which requires a
             * particular MAC, then just select that, and don't even
             * bother looking through the server's KEXINIT string for
             * MACs. */
            if (i == KEXLIST_CSMAC && s->cscipher_tobe &&
                s->cscipher_tobe->required_mac) {
                s->csmac_tobe = s->cscipher_tobe->required_mac;
                s->csmac_etm_tobe = !!(s->csmac_tobe->etm_name);
                goto matched;
            }
            if (i == KEXLIST_SCMAC && s->sccipher_tobe &&
                s->sccipher_tobe->required_mac) {
                s->scmac_tobe = s->sccipher_tobe->required_mac;
                s->scmac_etm_tobe = !!(s->scmac_tobe->etm_name);
                goto matched;
            }

	    for (j = 0; j < MAXKEXLIST; j++) {
		struct kexinit_algorithm *alg = &s->kexlists[i][j];
		if (alg->name == NULL) break;
		if (in_commasep_string(alg->name, str, len)) {
		    /* We've found a matching algorithm. */
		    if (i == KEXLIST_KEX || i == KEXLIST_HOSTKEY) {
			/* Check if we might need to ignore first kex pkt */
			if (j != 0 ||
			    !first_in_commasep_string(alg->name, str, len))
			    s->guessok = FALSE;
		    }
		    if (i == KEXLIST_KEX) {
			ssh->kex = alg->u.kex.kex;
			s->warn_kex = alg->u.kex.warn;
		    } else if (i == KEXLIST_HOSTKEY) {
			ssh->hostkey = alg->u.hk.hostkey;
                        s->warn_hk = alg->u.hk.warn;
		    } else if (i == KEXLIST_CSCIPHER) {
			s->cscipher_tobe = alg->u.cipher.cipher;
			s->warn_cscipher = alg->u.cipher.warn;
		    } else if (i == KEXLIST_SCCIPHER) {
			s->sccipher_tobe = alg->u.cipher.cipher;
			s->warn_sccipher = alg->u.cipher.warn;
		    } else if (i == KEXLIST_CSMAC) {
			s->csmac_tobe = alg->u.mac.mac;
			s->csmac_etm_tobe = alg->u.mac.etm;
		    } else if (i == KEXLIST_SCMAC) {
			s->scmac_tobe = alg->u.mac.mac;
			s->scmac_etm_tobe = alg->u.mac.etm;
		    } else if (i == KEXLIST_CSCOMP) {
			s->cscomp_tobe = alg->u.comp;
		    } else if (i == KEXLIST_SCCOMP) {
			s->sccomp_tobe = alg->u.comp;
		    }
		    goto matched;
		}
		if ((i == KEXLIST_CSCOMP || i == KEXLIST_SCCOMP) &&
		    in_commasep_string(alg->u.comp->delayed_name, str, len))
		    s->pending_compression = TRUE;  /* try this later */
	    }
	    bombout(("Couldn't agree a %s (available: %.*s)",
		     kexlist_descr[i], len, str));
	    crStopV;
	  matched:;

            if (i == KEXLIST_HOSTKEY) {
                int j;

                /*
                 * In addition to deciding which host key we're
                 * actually going to use, we should make a list of the
                 * host keys offered by the server which we _don't_
                 * have cached. These will be offered as cross-
                 * certification options by ssh_get_specials.
                 *
                 * We also count the key we're currently using for KEX
                 * as one we've already got, because by the time this
                 * menu becomes visible, it will be.
                 */
                ssh->n_uncert_hostkeys = 0;

                for (j = 0; j < lenof(hostkey_algs); j++) {
                    if (hostkey_algs[j].alg != ssh->hostkey &&
                        in_commasep_string(hostkey_algs[j].alg->name,
                                           str, len) &&
                        !have_ssh_host_key(ssh->savedhost, ssh->savedport,
                                           hostkey_algs[j].alg->keytype)) {
                        ssh->uncert_hostkeys[ssh->n_uncert_hostkeys++] = j;
                    }
                }
            }
	}

	if (s->pending_compression) {
	    logevent("Server supports delayed compression; "
		     "will try this later");
	}
	ssh_pkt_getstring(pktin, &str, &len);  /* client->server language */
	ssh_pkt_getstring(pktin, &str, &len);  /* server->client language */
	s->ignorepkt = ssh2_pkt_getbool(pktin) && !s->guessok;

	ssh->exhash = ssh->kex->hash->init();
	hash_string(ssh->kex->hash, ssh->exhash, ssh->v_c, strlen(ssh->v_c));
	hash_string(ssh->kex->hash, ssh->exhash, ssh->v_s, strlen(ssh->v_s));
	hash_string(ssh->kex->hash, ssh->exhash,
	    s->our_kexinit, s->our_kexinitlen);
	sfree(s->our_kexinit);
        /* Include the type byte in the hash of server's KEXINIT */
        hash_string(ssh->kex->hash, ssh->exhash,
                    pktin->body - 1, pktin->length + 1);

	if (s->warn_kex) {
	    ssh_set_frozen(ssh, 1);
	    s->dlgret = askalg(ssh->frontend, "key-exchange algorithm",
			       ssh->kex->name,
			       ssh_dialog_callback, ssh);
	    if (s->dlgret < 0) {
		do {
		    crReturnV;
		    if (pktin) {
			bombout(("Unexpected data from server while"
				 " waiting for user response"));
			crStopV;
		    }
		} while (pktin || inlen > 0);
		s->dlgret = ssh->user_response;
	    }
	    ssh_set_frozen(ssh, 0);
	    if (s->dlgret == 0) {
		ssh_disconnect(ssh, "User aborted at kex warning", NULL,
			       0, TRUE);
		crStopV;
	    }
	}

	if (s->warn_hk) {
            int j, k;
            char *betteralgs;

	    ssh_set_frozen(ssh, 1);

            /*
             * Change warning box wording depending on why we chose a
             * warning-level host key algorithm. If it's because
             * that's all we have *cached*, use the askhk mechanism,
             * and list the host keys we could usefully cross-certify.
             * Otherwise, use askalg for the standard wording.
             */
            betteralgs = NULL;
            for (j = 0; j < ssh->n_uncert_hostkeys; j++) {
                const struct ssh_signkey_with_user_pref_id *hktype =
                    &hostkey_algs[ssh->uncert_hostkeys[j]];
                int better = FALSE;
                for (k = 0; k < HK_MAX; k++) {
                    int id = conf_get_int_int(ssh->conf, CONF_ssh_hklist, k);
                    if (id == HK_WARN) {
                        break;
                    } else if (id == hktype->id) {
                        better = TRUE;
                        break;
                    }
                }
                if (better) {
                    if (betteralgs) {
                        char *old_ba = betteralgs;
                        betteralgs = dupcat(betteralgs, ",",
                                            hktype->alg->name,
                                            (const char *)NULL);
                        sfree(old_ba);
                    } else {
                        betteralgs = dupstr(hktype->alg->name);
                    }
                }
            }
            if (betteralgs) {
                s->dlgret = askhk(ssh->frontend, ssh->hostkey->name,
                                  betteralgs, ssh_dialog_callback, ssh);
                sfree(betteralgs);
            } else {
                s->dlgret = askalg(ssh->frontend, "host key type",
                                   ssh->hostkey->name,
                                   ssh_dialog_callback, ssh);
            }
	    if (s->dlgret < 0) {
		do {
		    crReturnV;
		    if (pktin) {
			bombout(("Unexpected data from server while"
				 " waiting for user response"));
			crStopV;
		    }
		} while (pktin || inlen > 0);
		s->dlgret = ssh->user_response;
	    }
	    ssh_set_frozen(ssh, 0);
	    if (s->dlgret == 0) {
		ssh_disconnect(ssh, "User aborted at host key warning", NULL,
			       0, TRUE);
		crStopV;
	    }
	}

	if (s->warn_cscipher) {
	    ssh_set_frozen(ssh, 1);
	    s->dlgret = askalg(ssh->frontend,
			       "client-to-server cipher",
			       s->cscipher_tobe->name,
			       ssh_dialog_callback, ssh);
	    if (s->dlgret < 0) {
		do {
		    crReturnV;
		    if (pktin) {
			bombout(("Unexpected data from server while"
				 " waiting for user response"));
			crStopV;
		    }
		} while (pktin || inlen > 0);
		s->dlgret = ssh->user_response;
	    }
	    ssh_set_frozen(ssh, 0);
	    if (s->dlgret == 0) {
		ssh_disconnect(ssh, "User aborted at cipher warning", NULL,
			       0, TRUE);
		crStopV;
	    }
	}

	if (s->warn_sccipher) {
	    ssh_set_frozen(ssh, 1);
	    s->dlgret = askalg(ssh->frontend,
			       "server-to-client cipher",
			       s->sccipher_tobe->name,
			       ssh_dialog_callback, ssh);
	    if (s->dlgret < 0) {
		do {
		    crReturnV;
		    if (pktin) {
			bombout(("Unexpected data from server while"
				 " waiting for user response"));
			crStopV;
		    }
		} while (pktin || inlen > 0);
		s->dlgret = ssh->user_response;
	    }
	    ssh_set_frozen(ssh, 0);
	    if (s->dlgret == 0) {
		ssh_disconnect(ssh, "User aborted at cipher warning", NULL,
			       0, TRUE);
		crStopV;
	    }
	}

	if (s->ignorepkt) /* first_kex_packet_follows */
	    crWaitUntilV(pktin);                /* Ignore packet */
    }

    if (ssh->kex->main_type == KEXTYPE_DH) {
        /*
         * Work out the number of bits of key we will need from the
         * key exchange. We start with the maximum key length of
         * either cipher...
         */
        {
            int csbits, scbits;

            csbits = s->cscipher_tobe ? s->cscipher_tobe->real_keybits : 0;
            scbits = s->sccipher_tobe ? s->sccipher_tobe->real_keybits : 0;
            s->nbits = (csbits > scbits ? csbits : scbits);
        }
        /* The keys only have hlen-bit entropy, since they're based on
         * a hash. So cap the key size at hlen bits. */
        if (s->nbits > ssh->kex->hash->hlen * 8)
            s->nbits = ssh->kex->hash->hlen * 8;

        /*
         * If we're doing Diffie-Hellman group exchange, start by
         * requesting a group.
         */
        if (dh_is_gex(ssh->kex)) {
            logevent("Doing Diffie-Hellman group exchange");
            ssh->pkt_kctx = SSH2_PKTCTX_DHGEX;
            /*
             * Work out how big a DH group we will need to allow that
             * much data.
             */
            s->pbits = 512 << ((s->nbits - 1) / 64);
            if (s->pbits < DH_MIN_SIZE)
                s->pbits = DH_MIN_SIZE;
            if (s->pbits > DH_MAX_SIZE)
                s->pbits = DH_MAX_SIZE;
            if ((ssh->remote_bugs & BUG_SSH2_OLDGEX)) {
                s->pktout = ssh2_pkt_init(SSH2_MSG_KEX_DH_GEX_REQUEST_OLD);
                ssh2_pkt_adduint32(s->pktout, s->pbits);
            } else {
                s->pktout = ssh2_pkt_init(SSH2_MSG_KEX_DH_GEX_REQUEST);
                ssh2_pkt_adduint32(s->pktout, DH_MIN_SIZE);
                ssh2_pkt_adduint32(s->pktout, s->pbits);
                ssh2_pkt_adduint32(s->pktout, DH_MAX_SIZE);
            }
            ssh2_pkt_send_noqueue(ssh, s->pktout);

            crWaitUntilV(pktin);
            if (pktin->type != SSH2_MSG_KEX_DH_GEX_GROUP) {
                bombout(("expected key exchange group packet from server"));
                crStopV;
            }
            s->p = ssh2_pkt_getmp(pktin);
            s->g = ssh2_pkt_getmp(pktin);
            if (!s->p || !s->g) {
                bombout(("unable to read mp-ints from incoming group packet"));
                crStopV;
            }
            ssh->kex_ctx = dh_setup_gex(s->p, s->g);
            s->kex_init_value = SSH2_MSG_KEX_DH_GEX_INIT;
            s->kex_reply_value = SSH2_MSG_KEX_DH_GEX_REPLY;
        } else {
            ssh->pkt_kctx = SSH2_PKTCTX_DHGROUP;
            ssh->kex_ctx = dh_setup_group(ssh->kex);
            s->kex_init_value = SSH2_MSG_KEXDH_INIT;
            s->kex_reply_value = SSH2_MSG_KEXDH_REPLY;
            logeventf(ssh, "Using Diffie-Hellman with standard group \"%s\"",
                      ssh->kex->groupname);
        }

        logeventf(ssh, "Doing Diffie-Hellman key exchange with hash %s",
                  ssh->kex->hash->text_name);
        /*
         * Now generate and send e for Diffie-Hellman.
         */
        set_busy_status(ssh->frontend, BUSY_CPU); /* this can take a while */
        s->e = dh_create_e(ssh->kex_ctx, s->nbits * 2);
        s->pktout = ssh2_pkt_init(s->kex_init_value);
        ssh2_pkt_addmp(s->pktout, s->e);
        ssh2_pkt_send_noqueue(ssh, s->pktout);

        set_busy_status(ssh->frontend, BUSY_WAITING); /* wait for server */
        crWaitUntilV(pktin);
        if (pktin->type != s->kex_reply_value) {
            bombout(("expected key exchange reply packet from server"));
            crStopV;
        }
        set_busy_status(ssh->frontend, BUSY_CPU); /* cogitate */
        ssh_pkt_getstring(pktin, &s->hostkeydata, &s->hostkeylen);
        if (!s->hostkeydata) {
            bombout(("unable to parse key exchange reply packet"));
            crStopV;
        }
        s->hkey = ssh->hostkey->newkey(ssh->hostkey,
                                       s->hostkeydata, s->hostkeylen);
        s->f = ssh2_pkt_getmp(pktin);
        if (!s->f) {
            bombout(("unable to parse key exchange reply packet"));
            crStopV;
        }
        ssh_pkt_getstring(pktin, &s->sigdata, &s->siglen);
        if (!s->sigdata) {
            bombout(("unable to parse key exchange reply packet"));
            crStopV;
        }

        {
            const char *err = dh_validate_f(ssh->kex_ctx, s->f);
            if (err) {
                bombout(("key exchange reply failed validation: %s", err));
                crStopV;
            }
        }
        s->K = dh_find_K(ssh->kex_ctx, s->f);

        /* We assume everything from now on will be quick, and it might
         * involve user interaction. */
        set_busy_status(ssh->frontend, BUSY_NOT);

        hash_string(ssh->kex->hash, ssh->exhash, s->hostkeydata, s->hostkeylen);
        if (dh_is_gex(ssh->kex)) {
            if (!(ssh->remote_bugs & BUG_SSH2_OLDGEX))
                hash_uint32(ssh->kex->hash, ssh->exhash, DH_MIN_SIZE);
            hash_uint32(ssh->kex->hash, ssh->exhash, s->pbits);
            if (!(ssh->remote_bugs & BUG_SSH2_OLDGEX))
                hash_uint32(ssh->kex->hash, ssh->exhash, DH_MAX_SIZE);
            hash_mpint(ssh->kex->hash, ssh->exhash, s->p);
            hash_mpint(ssh->kex->hash, ssh->exhash, s->g);
        }
        hash_mpint(ssh->kex->hash, ssh->exhash, s->e);
        hash_mpint(ssh->kex->hash, ssh->exhash, s->f);

        dh_cleanup(ssh->kex_ctx);
        freebn(s->f);
        if (dh_is_gex(ssh->kex)) {
            freebn(s->g);
            freebn(s->p);
        }
    } else if (ssh->kex->main_type == KEXTYPE_ECDH) {

        logeventf(ssh, "Doing ECDH key exchange with curve %s and hash %s",
                  ssh_ecdhkex_curve_textname(ssh->kex),
                  ssh->kex->hash->text_name);
        ssh->pkt_kctx = SSH2_PKTCTX_ECDHKEX;

        s->eckey = ssh_ecdhkex_newkey(ssh->kex);
        if (!s->eckey) {
            bombout(("Unable to generate key for ECDH"));
            crStopV;
        }

        {
            char *publicPoint;
            int publicPointLength;
            publicPoint = ssh_ecdhkex_getpublic(s->eckey, &publicPointLength);
            if (!publicPoint) {
                ssh_ecdhkex_freekey(s->eckey);
                bombout(("Unable to encode public key for ECDH"));
                crStopV;
            }
            s->pktout = ssh2_pkt_init(SSH2_MSG_KEX_ECDH_INIT);
            ssh2_pkt_addstring_start(s->pktout);
            ssh2_pkt_addstring_data(s->pktout, publicPoint, publicPointLength);
            sfree(publicPoint);
        }

        ssh2_pkt_send_noqueue(ssh, s->pktout);

        crWaitUntilV(pktin);
        if (pktin->type != SSH2_MSG_KEX_ECDH_REPLY) {
            ssh_ecdhkex_freekey(s->eckey);
            bombout(("expected ECDH reply packet from server"));
            crStopV;
        }

        ssh_pkt_getstring(pktin, &s->hostkeydata, &s->hostkeylen);
        if (!s->hostkeydata) {
            bombout(("unable to parse ECDH reply packet"));
            crStopV;
        }
        hash_string(ssh->kex->hash, ssh->exhash, s->hostkeydata, s->hostkeylen);
        s->hkey = ssh->hostkey->newkey(ssh->hostkey,
                                       s->hostkeydata, s->hostkeylen);

        {
            char *publicPoint;
            int publicPointLength;
            publicPoint = ssh_ecdhkex_getpublic(s->eckey, &publicPointLength);
            if (!publicPoint) {
                ssh_ecdhkex_freekey(s->eckey);
                bombout(("Unable to encode public key for ECDH hash"));
                crStopV;
            }
            hash_string(ssh->kex->hash, ssh->exhash,
                        publicPoint, publicPointLength);
            sfree(publicPoint);
        }

        {
            char *keydata;
            int keylen;
            ssh_pkt_getstring(pktin, &keydata, &keylen);
            if (!keydata) {
                bombout(("unable to parse ECDH reply packet"));
                crStopV;
            }
            hash_string(ssh->kex->hash, ssh->exhash, keydata, keylen);
            s->K = ssh_ecdhkex_getkey(s->eckey, keydata, keylen);
            if (!s->K) {
                ssh_ecdhkex_freekey(s->eckey);
                bombout(("point received in ECDH was not valid"));
                crStopV;
            }
        }

        ssh_pkt_getstring(pktin, &s->sigdata, &s->siglen);
        if (!s->sigdata) {
            bombout(("unable to parse key exchange reply packet"));
            crStopV;
        }

        ssh_ecdhkex_freekey(s->eckey);
    } else {
	logeventf(ssh, "Doing RSA key exchange with hash %s",
		  ssh->kex->hash->text_name);
	ssh->pkt_kctx = SSH2_PKTCTX_RSAKEX;
        /*
         * RSA key exchange. First expect a KEXRSA_PUBKEY packet
         * from the server.
         */
        crWaitUntilV(pktin);
        if (pktin->type != SSH2_MSG_KEXRSA_PUBKEY) {
            bombout(("expected RSA public key packet from server"));
            crStopV;
        }

        ssh_pkt_getstring(pktin, &s->hostkeydata, &s->hostkeylen);
        if (!s->hostkeydata) {
            bombout(("unable to parse RSA public key packet"));
            crStopV;
        }
        hash_string(ssh->kex->hash, ssh->exhash,
		    s->hostkeydata, s->hostkeylen);
	s->hkey = ssh->hostkey->newkey(ssh->hostkey,
                                       s->hostkeydata, s->hostkeylen);

        {
            char *keydata;
            ssh_pkt_getstring(pktin, &keydata, &s->rsakeylen);
            if (!keydata) {
                bombout(("unable to parse RSA public key packet"));
                crStopV;
            }
            s->rsakeydata = snewn(s->rsakeylen, char);
            memcpy(s->rsakeydata, keydata, s->rsakeylen);
        }

        s->rsakey = ssh_rsakex_newkey(s->rsakeydata, s->rsakeylen);
        if (!s->rsakey) {
            sfree(s->rsakeydata);
            bombout(("unable to parse RSA public key from server"));
            crStopV;
        }

        hash_string(ssh->kex->hash, ssh->exhash, s->rsakeydata, s->rsakeylen);

        /*
         * Next, set up a shared secret K, of precisely KLEN -
         * 2*HLEN - 49 bits, where KLEN is the bit length of the
         * RSA key modulus and HLEN is the bit length of the hash
         * we're using.
         */
        {
            int klen = ssh_rsakex_klen(s->rsakey);
            int nbits = klen - (2*ssh->kex->hash->hlen*8 + 49);
            int i, byte = 0;
            unsigned char *kstr1, *kstr2, *outstr;
            int kstr1len, kstr2len, outstrlen;

            s->K = bn_power_2(nbits - 1);

            for (i = 0; i < nbits; i++) {
                if ((i & 7) == 0) {
                    byte = random_byte();
                }
                bignum_set_bit(s->K, i, (byte >> (i & 7)) & 1);
            }

            /*
             * Encode this as an mpint.
             */
            kstr1 = ssh2_mpint_fmt(s->K, &kstr1len);
            kstr2 = snewn(kstr2len = 4 + kstr1len, unsigned char);
            PUT_32BIT(kstr2, kstr1len);
            memcpy(kstr2 + 4, kstr1, kstr1len);

            /*
             * Encrypt it with the given RSA key.
             */
            outstrlen = (klen + 7) / 8;
            outstr = snewn(outstrlen, unsigned char);
            ssh_rsakex_encrypt(ssh->kex->hash, kstr2, kstr2len,
			       outstr, outstrlen, s->rsakey);

            /*
             * And send it off in a return packet.
             */
            s->pktout = ssh2_pkt_init(SSH2_MSG_KEXRSA_SECRET);
            ssh2_pkt_addstring_start(s->pktout);
            ssh2_pkt_addstring_data(s->pktout, (char *)outstr, outstrlen);
            ssh2_pkt_send_noqueue(ssh, s->pktout);

	    hash_string(ssh->kex->hash, ssh->exhash, outstr, outstrlen);

            sfree(kstr2);
            sfree(kstr1);
            sfree(outstr);
        }

        ssh_rsakex_freekey(s->rsakey);

        crWaitUntilV(pktin);
        if (pktin->type != SSH2_MSG_KEXRSA_DONE) {
            sfree(s->rsakeydata);
            bombout(("expected signature packet from server"));
            crStopV;
        }

        ssh_pkt_getstring(pktin, &s->sigdata, &s->siglen);
        if (!s->sigdata) {
            bombout(("unable to parse signature packet"));
            crStopV;
        }

        sfree(s->rsakeydata);
    }

    hash_mpint(ssh->kex->hash, ssh->exhash, s->K);
    assert(ssh->kex->hash->hlen <= sizeof(s->exchange_hash));
    ssh->kex->hash->final(ssh->exhash, s->exchange_hash);

    ssh->kex_ctx = NULL;

#if 0
    debug(("Exchange hash is:\n"));
    dmemdump(s->exchange_hash, ssh->kex->hash->hlen);
#endif

    if (!s->hkey) {
	bombout(("Server's host key is invalid"));
	crStopV;
    }

    if (!ssh->hostkey->verifysig(s->hkey, s->sigdata, s->siglen,
				 (char *)s->exchange_hash,
				 ssh->kex->hash->hlen)) {
#ifndef FUZZING
	bombout(("Server's host key did not match the signature supplied"));
	crStopV;
#endif
    }

    s->keystr = ssh->hostkey->fmtkey(s->hkey);
    if (!s->got_session_id) {
	/*
	 * Make a note of any other host key formats that are available.
	 */
	{
	    int i, j, nkeys = 0;
	    char *list = NULL;
	    for (i = 0; i < lenof(hostkey_algs); i++) {
		if (hostkey_algs[i].alg == ssh->hostkey)
		    continue;

                for (j = 0; j < ssh->n_uncert_hostkeys; j++)
                    if (ssh->uncert_hostkeys[j] == i)
                        break;

                if (j < ssh->n_uncert_hostkeys) {
		    char *newlist;
		    if (list)
			newlist = dupprintf("%s/%s", list,
					    hostkey_algs[i].alg->name);
		    else
			newlist = dupprintf("%s", hostkey_algs[i].alg->name);
		    sfree(list);
		    list = newlist;
		    nkeys++;
		}
	    }
	    if (list) {
		logeventf(ssh,
			  "Server also has %s host key%s, but we "
			  "don't know %s", list,
			  nkeys > 1 ? "s" : "",
			  nkeys > 1 ? "any of them" : "it");
		sfree(list);
	    }
	}

        /*
         * Authenticate remote host: verify host key. (We've already
         * checked the signature of the exchange hash.)
         */
        s->fingerprint = ssh2_fingerprint(ssh->hostkey, s->hkey);
        logevent("Host key fingerprint is:");
        logevent(s->fingerprint);
        /* First check against manually configured host keys. */
        s->dlgret = verify_ssh_manual_host_key(ssh, s->fingerprint,
                                               ssh->hostkey, s->hkey);
        if (s->dlgret == 0) {          /* did not match */
            bombout(("Host key did not appear in manually configured list"));
            crStopV;
        } else if (s->dlgret < 0) { /* none configured; use standard handling */
            ssh_set_frozen(ssh, 1);
            s->dlgret = verify_ssh_host_key(ssh->frontend,
                                            ssh->savedhost, ssh->savedport,
                                            ssh->hostkey->keytype, s->keystr,
                                            s->fingerprint,
                                            ssh_dialog_callback, ssh);
#ifdef FUZZING
	    s->dlgret = 1;
#endif
            if (s->dlgret < 0) {
                do {
                    crReturnV;
                    if (pktin) {
                        bombout(("Unexpected data from server while waiting"
                                 " for user host key response"));
                        crStopV;
                    }
                } while (pktin || inlen > 0);
                s->dlgret = ssh->user_response;
            }
            ssh_set_frozen(ssh, 0);
            if (s->dlgret == 0) {
                ssh_disconnect(ssh, "Aborted at host key verification", NULL,
                               0, TRUE);
                crStopV;
            }
        }
        sfree(s->fingerprint);
        /*
         * Save this host key, to check against the one presented in
         * subsequent rekeys.
         */
        ssh->hostkey_str = s->keystr;
    } else if (ssh->cross_certifying) {
        s->fingerprint = ssh2_fingerprint(ssh->hostkey, s->hkey);
        logevent("Storing additional host key for this host:");
        logevent(s->fingerprint);
        sfree(s->fingerprint);
        store_host_key(ssh->savedhost, ssh->savedport,
                       ssh->hostkey->keytype, s->keystr);
        ssh->cross_certifying = FALSE;
        /*
         * Don't forget to store the new key as the one we'll be
         * re-checking in future normal rekeys.
         */
        ssh->hostkey_str = s->keystr;
    } else {
        /*
         * In a rekey, we never present an interactive host key
         * verification request to the user. Instead, we simply
         * enforce that the key we're seeing this time is identical to
         * the one we saw before.
         */
        if (strcmp(ssh->hostkey_str, s->keystr)) {
#ifndef FUZZING
            bombout(("Host key was different in repeat key exchange"));
            crStopV;
#endif
        }
        sfree(s->keystr);
    }
    ssh->hostkey->freekey(s->hkey);

    /*
     * The exchange hash from the very first key exchange is also
     * the session id, used in session key construction and
     * authentication.
     */
    if (!s->got_session_id) {
	assert(sizeof(s->exchange_hash) <= sizeof(ssh->v2_session_id));
	memcpy(ssh->v2_session_id, s->exchange_hash,
	       sizeof(s->exchange_hash));
	ssh->v2_session_id_len = ssh->kex->hash->hlen;
	assert(ssh->v2_session_id_len <= sizeof(ssh->v2_session_id));
	s->got_session_id = TRUE;
    }

    /*
     * Send SSH2_MSG_NEWKEYS.
     */
    s->pktout = ssh2_pkt_init(SSH2_MSG_NEWKEYS);
    ssh2_pkt_send_noqueue(ssh, s->pktout);
    ssh->outgoing_data_size = 0;       /* start counting from here */

    /*
     * We've sent client NEWKEYS, so create and initialise
     * client-to-server session keys.
     */
    if (ssh->cs_cipher_ctx)
	ssh->cscipher->free_context(ssh->cs_cipher_ctx);
    ssh->cscipher = s->cscipher_tobe;
    if (ssh->cscipher) ssh->cs_cipher_ctx = ssh->cscipher->make_context();

    if (ssh->cs_mac_ctx)
	ssh->csmac->free_context(ssh->cs_mac_ctx);
    ssh->csmac = s->csmac_tobe;
    ssh->csmac_etm = s->csmac_etm_tobe;
    if (ssh->csmac)
        ssh->cs_mac_ctx = ssh->csmac->make_context(ssh->cs_cipher_ctx);

    if (ssh->cs_comp_ctx)
	ssh->cscomp->compress_cleanup(ssh->cs_comp_ctx);
    ssh->cscomp = s->cscomp_tobe;
    ssh->cs_comp_ctx = ssh->cscomp->compress_init();

    /*
     * Set IVs on client-to-server keys. Here we use the exchange
     * hash from the _first_ key exchange.
     */
    if (ssh->cscipher) {
	unsigned char *key;

	key = ssh2_mkkey(ssh, s->K, s->exchange_hash, 'C',
                         ssh->cscipher->padded_keybytes);
	ssh->cscipher->setkey(ssh->cs_cipher_ctx, key);
        smemclr(key, ssh->cscipher->padded_keybytes);
        sfree(key);

	key = ssh2_mkkey(ssh, s->K, s->exchange_hash, 'A',
                         ssh->cscipher->blksize);
	ssh->cscipher->setiv(ssh->cs_cipher_ctx, key);
        smemclr(key, ssh->cscipher->blksize);
        sfree(key);
    }
    if (ssh->csmac) {
	unsigned char *key;

	key = ssh2_mkkey(ssh, s->K, s->exchange_hash, 'E',
                         ssh->csmac->keylen);
	ssh->csmac->setkey(ssh->cs_mac_ctx, key);
        smemclr(key, ssh->csmac->keylen);
        sfree(key);
    }

    if (ssh->cscipher)
	logeventf(ssh, "Initialised %.200s client->server encryption",
		  ssh->cscipher->text_name);
    if (ssh->csmac)
	logeventf(ssh, "Initialised %.200s client->server MAC algorithm%s%s",
		  ssh->csmac->text_name,
		  ssh->csmac_etm ? " (in ETM mode)" : "",
		  ssh->cscipher->required_mac ? " (required by cipher)" : "");
    if (ssh->cscomp->text_name)
	logeventf(ssh, "Initialised %s compression",
		  ssh->cscomp->text_name);

    /*
     * Now our end of the key exchange is complete, we can send all
     * our queued higher-layer packets.
     */
    ssh->queueing = FALSE;
    ssh2_pkt_queuesend(ssh);

    /*
     * Expect SSH2_MSG_NEWKEYS from server.
     */
    crWaitUntilV(pktin);
    if (pktin->type != SSH2_MSG_NEWKEYS) {
	bombout(("expected new-keys packet from server"));
	crStopV;
    }
    ssh->incoming_data_size = 0;       /* start counting from here */

    /*
     * We've seen server NEWKEYS, so create and initialise
     * server-to-client session keys.
     */
    if (ssh->sc_cipher_ctx)
	ssh->sccipher->free_context(ssh->sc_cipher_ctx);
    if (s->sccipher_tobe) {
	ssh->sccipher = s->sccipher_tobe;
	ssh->sc_cipher_ctx = ssh->sccipher->make_context();
    }

    if (ssh->sc_mac_ctx)
	ssh->scmac->free_context(ssh->sc_mac_ctx);
    if (s->scmac_tobe) {
	ssh->scmac = s->scmac_tobe;
	ssh->scmac_etm = s->scmac_etm_tobe;
	ssh->sc_mac_ctx = ssh->scmac->make_context(ssh->sc_cipher_ctx);
    }

    if (ssh->sc_comp_ctx)
	ssh->sccomp->decompress_cleanup(ssh->sc_comp_ctx);
    ssh->sccomp = s->sccomp_tobe;
    ssh->sc_comp_ctx = ssh->sccomp->decompress_init();

    /*
     * Set IVs on server-to-client keys. Here we use the exchange
     * hash from the _first_ key exchange.
     */
    if (ssh->sccipher) {
	unsigned char *key;

	key = ssh2_mkkey(ssh, s->K, s->exchange_hash, 'D',
                         ssh->sccipher->padded_keybytes);
	ssh->sccipher->setkey(ssh->sc_cipher_ctx, key);
        smemclr(key, ssh->sccipher->padded_keybytes);
        sfree(key);

	key = ssh2_mkkey(ssh, s->K, s->exchange_hash, 'B',
                         ssh->sccipher->blksize);
	ssh->sccipher->setiv(ssh->sc_cipher_ctx, key);
        smemclr(key, ssh->sccipher->blksize);
        sfree(key);
    }
    if (ssh->scmac) {
	unsigned char *key;

	key = ssh2_mkkey(ssh, s->K, s->exchange_hash, 'F',
                         ssh->scmac->keylen);
	ssh->scmac->setkey(ssh->sc_mac_ctx, key);
        smemclr(key, ssh->scmac->keylen);
        sfree(key);
    }
    if (ssh->sccipher)
	logeventf(ssh, "Initialised %.200s server->client encryption",
		  ssh->sccipher->text_name);
    if (ssh->scmac)
	logeventf(ssh, "Initialised %.200s server->client MAC algorithm%s%s",
		  ssh->scmac->text_name,
		  ssh->scmac_etm ? " (in ETM mode)" : "",
		  ssh->sccipher->required_mac ? " (required by cipher)" : "");
    if (ssh->sccomp->text_name)
	logeventf(ssh, "Initialised %s decompression",
		  ssh->sccomp->text_name);

    /*
     * Free shared secret.
     */
    freebn(s->K);

    /*
     * Update the specials menu to list the remaining uncertified host
     * keys.
     */
    update_specials_menu(ssh->frontend);

    /*
     * Key exchange is over. Loop straight back round if we have a
     * deferred rekey reason.
     */
    if (ssh->deferred_rekey_reason) {
	logevent(ssh->deferred_rekey_reason);
	pktin = NULL;
	ssh->deferred_rekey_reason = NULL;
	goto begin_key_exchange;
    }

    /*
     * Otherwise, schedule a timer for our next rekey.
     */
    ssh->kex_in_progress = FALSE;
    ssh->last_rekey = GETTICKCOUNT();
    if (conf_get_int(ssh->conf, CONF_ssh_rekey_time) != 0)
	ssh->next_rekey = schedule_timer(conf_get_int(ssh->conf, CONF_ssh_rekey_time)*60*TICKSPERSEC,
					 ssh2_timer, ssh);

    /*
     * Now we're encrypting. Begin returning 1 to the protocol main
     * function so that other things can run on top of the
     * transport. If we ever see a KEXINIT, we must go back to the
     * start.
     * 
     * We _also_ go back to the start if we see pktin==NULL and
     * inlen negative, because this is a special signal meaning
     * `initiate client-driven rekey', and `in' contains a message
     * giving the reason for the rekey.
     *
     * inlen==-1 means always initiate a rekey;
     * inlen==-2 means that userauth has completed successfully and
     *   we should consider rekeying (for delayed compression).
     */
    while (!((pktin && pktin->type == SSH2_MSG_KEXINIT) ||
	     (!pktin && inlen < 0))) {
        wait_for_rekey:
	if (!ssh->protocol_initial_phase_done) {
	    ssh->protocol_initial_phase_done = TRUE;
	    /*
	     * Allow authconn to initialise itself.
	     */
	    do_ssh2_authconn(ssh, NULL, 0, NULL);
	}
	crReturnV;
    }
    if (pktin) {
	logevent("Server initiated key re-exchange");
    } else {
	if (inlen == -2) {
	    /* 
	     * authconn has seen a USERAUTH_SUCCEEDED. Time to enable
	     * delayed compression, if it's available.
	     *
	     * draft-miller-secsh-compression-delayed-00 says that you
	     * negotiate delayed compression in the first key exchange, and
	     * both sides start compressing when the server has sent
	     * USERAUTH_SUCCESS. This has a race condition -- the server
	     * can't know when the client has seen it, and thus which incoming
	     * packets it should treat as compressed.
	     *
	     * Instead, we do the initial key exchange without offering the
	     * delayed methods, but note if the server offers them; when we
	     * get here, if a delayed method was available that was higher
	     * on our list than what we got, we initiate a rekey in which we
	     * _do_ list the delayed methods (and hopefully get it as a
	     * result). Subsequent rekeys will do the same.
	     */
	    assert(!s->userauth_succeeded); /* should only happen once */
	    s->userauth_succeeded = TRUE;
	    if (!s->pending_compression)
		/* Can't see any point rekeying. */
		goto wait_for_rekey;       /* this is utterly horrid */
	    /* else fall through to rekey... */
	    s->pending_compression = FALSE;
	}
        /*
	 * Now we've decided to rekey.
	 *
         * Special case: if the server bug is set that doesn't
         * allow rekeying, we give a different log message and
         * continue waiting. (If such a server _initiates_ a rekey,
         * we process it anyway!)
         */
        if ((ssh->remote_bugs & BUG_SSH2_REKEY)) {
            logeventf(ssh, "Server bug prevents key re-exchange (%s)",
                      (char *)in);
            /* Reset the counters, so that at least this message doesn't
             * hit the event log _too_ often. */
            ssh->outgoing_data_size = 0;
            ssh->incoming_data_size = 0;
            if (conf_get_int(ssh->conf, CONF_ssh_rekey_time) != 0) {
                ssh->next_rekey =
                    schedule_timer(conf_get_int(ssh->conf, CONF_ssh_rekey_time)*60*TICKSPERSEC,
                                   ssh2_timer, ssh);
            }
            goto wait_for_rekey;       /* this is still utterly horrid */
        } else {
            logeventf(ssh, "Initiating key re-exchange (%s)", (char *)in);
        }
    }
    goto begin_key_exchange;

    crFinishV;
}

/*
 * Send data on an SSH channel.  In SSH-2, this involves buffering it
 * first.
 */
static int ssh_send_channel_data(struct ssh_channel *c, const char *buf,
				   int len)
{
    if (c->ssh->version == 2) {
	bufchain_add(&c->v.v2.outbuffer, buf, len);
	return ssh2_try_send(c);
    } else {
	send_packet(c->ssh, SSH1_MSG_CHANNEL_DATA,
		    PKT_INT, c->remoteid,
		    PKT_INT, len,
		    PKT_DATA, buf, len,
		    PKT_END);
	/*
	 * In SSH-1 we can return 0 here - implying that channels are
	 * never individually throttled - because the only
	 * circumstance that can cause throttling will be the whole
	 * SSH connection backing up, in which case _everything_ will
	 * be throttled as a whole.
	 */
	return 0;
    }
}

/*
 * Attempt to send data on an SSH-2 channel.
 */
static int ssh2_try_send(struct ssh_channel *c)
{
    Ssh ssh = c->ssh;
    struct Packet *pktout;
    int ret;

    while (c->v.v2.remwindow > 0 && bufchain_size(&c->v.v2.outbuffer) > 0) {
	int len;
	void *data;
	bufchain_prefix(&c->v.v2.outbuffer, &data, &len);
	if ((unsigned)len > c->v.v2.remwindow)
	    len = c->v.v2.remwindow;
	if ((unsigned)len > c->v.v2.remmaxpkt)
	    len = c->v.v2.remmaxpkt;
	pktout = ssh2_pkt_init(SSH2_MSG_CHANNEL_DATA);
	ssh2_pkt_adduint32(pktout, c->remoteid);
	ssh2_pkt_addstring_start(pktout);
	ssh2_pkt_addstring_data(pktout, data, len);
	ssh2_pkt_send(ssh, pktout);
	bufchain_consume(&c->v.v2.outbuffer, len);
	c->v.v2.remwindow -= len;
    }

    /*
     * After having sent as much data as we can, return the amount
     * still buffered.
     */
    ret = bufchain_size(&c->v.v2.outbuffer);

    /*
     * And if there's no data pending but we need to send an EOF, send
     * it.
     */
    if (!ret && c->pending_eof)
        ssh_channel_try_eof(c);

    return ret;
}

static void ssh2_try_send_and_unthrottle(Ssh ssh, struct ssh_channel *c)
{
    int bufsize;
    if (c->closes & CLOSES_SENT_EOF)
	return;                   /* don't send on channels we've EOFed */
    bufsize = ssh2_try_send(c);
    if (bufsize == 0) {
	switch (c->type) {
	  case CHAN_MAINSESSION:
	    /* stdin need not receive an unthrottle
	     * notification since it will be polled */
	    break;
	  case CHAN_X11:
	    x11_unthrottle(c->u.x11.xconn);
	    break;
	  case CHAN_AGENT:
            /* Now that we've successfully sent all the outgoing
             * replies we had, try to process more incoming data. */
            ssh_agentf_try_forward(c);
	    break;
	  case CHAN_SOCKDATA:
	    pfd_unthrottle(c->u.pfd.pf);
	    break;
	}
    }
}

static int ssh_is_simple(Ssh ssh)
{
    /*
     * We use the 'simple' variant of the SSH protocol if we're asked
     * to, except not if we're also doing connection-sharing (either
     * tunnelling our packets over an upstream or expecting to be
     * tunnelled over ourselves), since then the assumption that we
     * have only one channel to worry about is not true after all.
     */
    return (conf_get_int(ssh->conf, CONF_ssh_simple) &&
            !ssh->bare_connection && !ssh->connshare);
}

/*
 * Set up most of a new ssh_channel.
 */
static void ssh_channel_init(struct ssh_channel *c)
{
    Ssh ssh = c->ssh;
    c->localid = alloc_channel_id(ssh);
    c->closes = 0;
    c->pending_eof = FALSE;
    c->throttling_conn = FALSE;
    if (ssh->version == 2) {
	c->v.v2.locwindow = c->v.v2.locmaxwin = c->v.v2.remlocwin =
	    ssh_is_simple(ssh) ? OUR_V2_BIGWIN : OUR_V2_WINSIZE;
	c->v.v2.chanreq_head = NULL;
	c->v.v2.throttle_state = UNTHROTTLED;
	bufchain_init(&c->v.v2.outbuffer);
    }
    add234(ssh->channels, c);
}

/*
 * Construct the common parts of a CHANNEL_OPEN.
 */
static struct Packet *ssh2_chanopen_init(struct ssh_channel *c,
                                         const char *type)
{
    struct Packet *pktout;

    pktout = ssh2_pkt_init(SSH2_MSG_CHANNEL_OPEN);
    ssh2_pkt_addstring(pktout, type);
    ssh2_pkt_adduint32(pktout, c->localid);
    ssh2_pkt_adduint32(pktout, c->v.v2.locwindow);/* our window size */
    ssh2_pkt_adduint32(pktout, OUR_V2_MAXPKT);      /* our max pkt size */
    return pktout;
}

/*
 * CHANNEL_FAILURE doesn't come with any indication of what message
 * caused it, so we have to keep track of the outstanding
 * CHANNEL_REQUESTs ourselves.
 */
static void ssh2_queue_chanreq_handler(struct ssh_channel *c,
				       cchandler_fn_t handler, void *ctx)
{
    struct outstanding_channel_request *ocr =
	snew(struct outstanding_channel_request);

    assert(!(c->closes & (CLOSES_SENT_CLOSE | CLOSES_RCVD_CLOSE)));
    ocr->handler = handler;
    ocr->ctx = ctx;
    ocr->next = NULL;
    if (!c->v.v2.chanreq_head)
	c->v.v2.chanreq_head = ocr;
    else
	c->v.v2.chanreq_tail->next = ocr;
    c->v.v2.chanreq_tail = ocr;
}

/*
 * Construct the common parts of a CHANNEL_REQUEST.  If handler is not
 * NULL then a reply will be requested and the handler will be called
 * when it arrives.  The returned packet is ready to have any
 * request-specific data added and be sent.  Note that if a handler is
 * provided, it's essential that the request actually be sent.
 *
 * The handler will usually be passed the response packet in pktin. If
 * pktin is NULL, this means that no reply will ever be forthcoming
 * (e.g. because the entire connection is being destroyed, or because
 * the server initiated channel closure before we saw the response)
 * and the handler should free any storage it's holding.
 */
static struct Packet *ssh2_chanreq_init(struct ssh_channel *c,
                                        const char *type,
					cchandler_fn_t handler, void *ctx)
{
    struct Packet *pktout;

    assert(!(c->closes & (CLOSES_SENT_CLOSE | CLOSES_RCVD_CLOSE)));
    pktout = ssh2_pkt_init(SSH2_MSG_CHANNEL_REQUEST);
    ssh2_pkt_adduint32(pktout, c->remoteid);
    ssh2_pkt_addstring(pktout, type);
    ssh2_pkt_addbool(pktout, handler != NULL);
    if (handler != NULL)
	ssh2_queue_chanreq_handler(c, handler, ctx);
    return pktout;
}

static void ssh_channel_unthrottle(struct ssh_channel *c, int bufsize)
{
    Ssh ssh = c->ssh;
    int buflimit;

    if (ssh->version == 1) {
	buflimit = SSH1_BUFFER_LIMIT;
    } else {
	if (ssh_is_simple(ssh))
	    buflimit = 0;
	else
	    buflimit = c->v.v2.locmaxwin;
	if (bufsize < buflimit)
	    ssh2_set_window(c, buflimit - bufsize);
    }
    if (c->throttling_conn && bufsize <= buflimit) {
	c->throttling_conn = 0;
	ssh_throttle_conn(ssh, -1);
    }
}

/*
 * Potentially enlarge the window on an SSH-2 channel.
 */
static void ssh2_handle_winadj_response(struct ssh_channel *, struct Packet *,
					void *);
static void ssh2_set_window(struct ssh_channel *c, int newwin)
{
    Ssh ssh = c->ssh;

    /*
     * Never send WINDOW_ADJUST for a channel that the remote side has
     * already sent EOF on; there's no point, since it won't be
     * sending any more data anyway. Ditto if _we've_ already sent
     * CLOSE.
     */
    if (c->closes & (CLOSES_RCVD_EOF | CLOSES_SENT_CLOSE))
	return;

    /*
     * base_layer identifies the bottommost packet protocol layer, the
     * one connected directly to the BPP's packet queues. Any
     * operation that needs to talk to all layers (e.g. free, or
     * get_specials) will do it by talking to this, which will
     * recursively propagate it if necessary.
     */
    PacketProtocolLayer *base_layer;

    /*
     * The ConnectionLayer vtable from our connection layer.
     */
    ConnectionLayer *cl;

    /*
     * A dummy ConnectionLayer that can be used for logging sharing
     * downstreams that connect before the real one is ready.
     */
    ConnectionLayer cl_dummy;

    /*
     * session_started is false until we initialise the main protocol
     * layers. So it distinguishes between base_layer==NULL meaning
     * that the SSH protocol hasn't been set up _yet_, and
     * base_layer==NULL meaning the SSH protocol has run and finished.
     * It's also used to mark the point where we stop counting proxy
     * command diagnostics as pre-session-startup.
     */
    bool session_started;

    Pinger *pinger;

    char *deferred_abort_message;

    bool need_random_unref;
};


#define ssh_logevent(params) ( \
        logevent_and_free((ssh)->logctx, dupprintf params))

static void ssh_shutdown(Ssh *ssh);
static void ssh_throttle_all(Ssh *ssh, bool enable, size_t bufsize);
static void ssh_bpp_output_raw_data_callback(void *vctx);

LogContext *ssh_get_logctx(Ssh *ssh)
{
    return ssh->logctx;
}

static void ssh_connect_bpp(Ssh *ssh)
{
    ssh->bpp->ssh = ssh;
    ssh->bpp->in_raw = &ssh->in_raw;
    ssh->bpp->out_raw = &ssh->out_raw;
    bufchain_set_callback(ssh->bpp->out_raw, &ssh->ic_out_raw);
    ssh->bpp->pls = &ssh->pls;
    ssh->bpp->logctx = ssh->logctx;
    ssh->bpp->remote_bugs = ssh->remote_bugs;
}

static void ssh_connect_ppl(Ssh *ssh, PacketProtocolLayer *ppl)
{
    ppl->bpp = ssh->bpp;
    ppl->user_input = &ssh->user_input;
    ppl->seat = ssh->seat;
    ppl->ssh = ssh;
    ppl->logctx = ssh->logctx;
    ppl->remote_bugs = ssh->remote_bugs;
}

static void ssh_got_ssh_version(struct ssh_version_receiver *rcv,
                                int major_version)
{
    Ssh *ssh = container_of(rcv, Ssh, version_receiver);
    BinaryPacketProtocol *old_bpp;
    PacketProtocolLayer *connection_layer;

    ssh->session_started = true;

    /*
     * We don't support choosing a major protocol version dynamically,
     * so this should always be the same value we set up in
     * connect_to_host().
     */
    assert(ssh->version == major_version);

    old_bpp = ssh->bpp;
    ssh->remote_bugs = ssh_verstring_get_bugs(old_bpp);

    if (!ssh->bare_connection) {
        if (ssh->version == 2) {
            PacketProtocolLayer *userauth_layer, *transport_child_layer;

            /*
             * We use the 'simple' variant of the SSH protocol if
             * we're asked to, except not if we're also doing
             * connection-sharing (either tunnelling our packets over
             * an upstream or expecting to be tunnelled over
             * ourselves), since then the assumption that we have only
             * one channel to worry about is not true after all.
             */
            bool is_simple =
                (conf_get_bool(ssh->conf, CONF_ssh_simple) && !ssh->connshare);

            ssh->bpp = ssh2_bpp_new(ssh->logctx, &ssh->stats, false);
            ssh_connect_bpp(ssh);

#ifndef NO_GSSAPI
            /* Load and pick the highest GSS library on the preference
             * list. */
            if (!ssh->gss_state.libs)
                ssh->gss_state.libs = ssh_gss_setup(ssh->conf);
            ssh->gss_state.lib = NULL;
            if (ssh->gss_state.libs->nlibraries > 0) {
                int i, j;
                for (i = 0; i < ngsslibs; i++) {
                    int want_id = conf_get_int_int(ssh->conf,
                                                   CONF_ssh_gsslist, i);
                    for (j = 0; j < ssh->gss_state.libs->nlibraries; j++)
                        if (ssh->gss_state.libs->libraries[j].id == want_id) {
                            ssh->gss_state.lib =
                                &ssh->gss_state.libs->libraries[j];
                            goto got_gsslib;   /* double break */
                        }
                }
              got_gsslib:
                /*
                 * We always expect to have found something in
                 * the above loop: we only came here if there
                 * was at least one viable GSS library, and the
                 * preference list should always mention
                 * everything and only change the order.
                 */
                assert(ssh->gss_state.lib);
            }
#endif

            connection_layer = ssh2_connection_new(
                ssh, ssh->connshare, is_simple, ssh->conf,
                ssh_verstring_get_remote(old_bpp), &ssh->cl);
            ssh_connect_ppl(ssh, connection_layer);

            if (conf_get_bool(ssh->conf, CONF_ssh_no_userauth)) {
                userauth_layer = NULL;
                transport_child_layer = connection_layer;
            } else {
                char *username = get_remote_username(ssh->conf);

                userauth_layer = ssh2_userauth_new(
                    connection_layer, ssh->savedhost, ssh->fullhostname,
                    conf_get_filename(ssh->conf, CONF_keyfile),
                    conf_get_bool(ssh->conf, CONF_ssh_show_banner),
                    conf_get_bool(ssh->conf, CONF_tryagent), username,
                    conf_get_bool(ssh->conf, CONF_change_username),
                    conf_get_bool(ssh->conf, CONF_try_ki_auth),
#ifndef NO_GSSAPI
                    conf_get_bool(ssh->conf, CONF_try_gssapi_auth),
                    conf_get_bool(ssh->conf, CONF_try_gssapi_kex),
                    conf_get_bool(ssh->conf, CONF_gssapifwd),
                    &ssh->gss_state
#else
                    false,
                    false,
                    false,
                    NULL
#endif
                    );
                ssh_connect_ppl(ssh, userauth_layer);
                transport_child_layer = userauth_layer;

                sfree(username);
            }

            ssh->base_layer = ssh2_transport_new(
                ssh->conf, ssh->savedhost, ssh->savedport,
                ssh->fullhostname,
                ssh_verstring_get_local(old_bpp),
                ssh_verstring_get_remote(old_bpp),
#ifndef NO_GSSAPI
                &ssh->gss_state,
#else
                NULL,
#endif
                &ssh->stats, transport_child_layer, NULL);
            ssh_connect_ppl(ssh, ssh->base_layer);

            if (userauth_layer)
                ssh2_userauth_set_transport_layer(userauth_layer,
                                                  ssh->base_layer);

        } else {

            ssh->bpp = ssh1_bpp_new(ssh->logctx);
            ssh_connect_bpp(ssh);

            connection_layer = ssh1_connection_new(ssh, ssh->conf, &ssh->cl);
            ssh_connect_ppl(ssh, connection_layer);

            ssh->base_layer = ssh1_login_new(
                ssh->conf, ssh->savedhost, ssh->savedport, connection_layer);
            ssh_connect_ppl(ssh, ssh->base_layer);

        }

    } else {
        ssh->bpp = ssh2_bare_bpp_new(ssh->logctx);
        ssh_connect_bpp(ssh);

        connection_layer = ssh2_connection_new(
            ssh, NULL, false, ssh->conf, ssh_verstring_get_remote(old_bpp),
            &ssh->cl);
        ssh_connect_ppl(ssh, connection_layer);
        ssh->base_layer = connection_layer;
    }

    /* Connect the base layer - whichever it is - to the BPP, and set
     * up its selfptr. */
    ssh->base_layer->selfptr = &ssh->base_layer;
    ssh_ppl_setup_queues(ssh->base_layer, &ssh->bpp->in_pq, &ssh->bpp->out_pq);

    seat_update_specials_menu(ssh->seat);
    ssh->pinger = pinger_new(ssh->conf, &ssh->backend);

    queue_idempotent_callback(&ssh->bpp->ic_in_raw);
    ssh_ppl_process_queue(ssh->base_layer);

    /* Pass in the initial terminal size, if we knew it already. */
    ssh_terminal_size(ssh->cl, ssh->term_width, ssh->term_height);

    ssh_bpp_free(old_bpp);
}

void ssh_check_frozen(Ssh *ssh)
{
    if (!ssh->s)
        return;

    bool prev_frozen = ssh->socket_frozen;
    ssh->socket_frozen = (ssh->logically_frozen ||
                          bufchain_size(&ssh->in_raw) > SSH_MAX_BACKLOG);
    sk_set_frozen(ssh->s, ssh->socket_frozen);
    if (prev_frozen && !ssh->socket_frozen && ssh->bpp) {
        /*
         * If we've just unfrozen, process any SSH connection data
         * that was stashed in our queue while we were frozen.
         */
        queue_idempotent_callback(&ssh->bpp->ic_in_raw);
    }
}

void ssh_conn_processed_data(Ssh *ssh)
{
    ssh_check_frozen(ssh);
}

static void ssh_bpp_output_raw_data_callback(void *vctx)
{
    Ssh *ssh = (Ssh *)vctx;

    if (!ssh->s)
        return;

    while (bufchain_size(&ssh->out_raw) > 0) {
        size_t backlog;

        ptrlen data = bufchain_prefix(&ssh->out_raw);

        if (ssh->logctx)
            log_packet(ssh->logctx, PKT_OUTGOING, -1, NULL, data.ptr, data.len,
                       0, NULL, NULL, 0, NULL);
        backlog = sk_write(ssh->s, data.ptr, data.len);

        bufchain_consume(&ssh->out_raw, data.len);

        if (backlog > SSH_MAX_BACKLOG) {
            ssh_throttle_all(ssh, true, backlog);
            return;
        }
    }

    ssh_check_frozen(ssh);

    if (ssh->pending_close) {
        sk_close(ssh->s);
        ssh->s = NULL;
    }
}

static void ssh_shutdown_internal(Ssh *ssh)
{
    expire_timer_context(ssh);

    if (ssh->connshare) {
        sharestate_free(ssh->connshare);
        ssh->connshare = NULL;
    }

    if (ssh->pinger) {
        pinger_free(ssh->pinger);
        ssh->pinger = NULL;
    }

    /*
     * We only need to free the base PPL, which will free the others
     * (if any) transitively.
     */
    if (ssh->base_layer) {
        ssh_ppl_free(ssh->base_layer);
        ssh->base_layer = NULL;
    }

    ssh->cl = NULL;
}

static void ssh_shutdown(Ssh *ssh)
{
    ssh_shutdown_internal(ssh);

    if (ssh->bpp) {
        ssh_bpp_free(ssh->bpp);
        ssh->bpp = NULL;
    }

    if (ssh->s) {
        sk_close(ssh->s);
        ssh->s = NULL;
    }

    bufchain_clear(&ssh->in_raw);
    bufchain_clear(&ssh->out_raw);
    bufchain_clear(&ssh->user_input);
}

static void ssh_initiate_connection_close(Ssh *ssh)
{
    /* Wind up everything above the BPP. */
    ssh_shutdown_internal(ssh);

    /* Force any remaining queued SSH packets through the BPP, and
     * schedule closing the network socket after they go out. */
    ssh_bpp_handle_output(ssh->bpp);
    ssh->pending_close = true;
    queue_idempotent_callback(&ssh->ic_out_raw);

    /* Now we expect the other end to close the connection too in
     * response, so arrange that we'll receive notification of that
     * via ssh_remote_eof. */
    ssh->bpp->expect_close = true;
}

#define GET_FORMATTED_MSG                       \
    char *msg;                                  \
    va_list ap;                                 \
    va_start(ap, fmt);                          \
    msg = dupvprintf(fmt, ap);                  \
    va_end(ap);

void ssh_remote_error(Ssh *ssh, const char *fmt, ...)
{
    if (ssh->base_layer || !ssh->session_started) {
        GET_FORMATTED_MSG;

        /* Error messages sent by the remote don't count as clean exits */
        ssh->exitcode = 128;

        /* Close the socket immediately, since the server has already
         * closed its end (or is about to). */
        ssh_shutdown(ssh);

        logevent(ssh->logctx, msg);
        seat_connection_fatal(ssh->seat, "%s", msg);
        sfree(msg);
    }
}

void ssh_remote_eof(Ssh *ssh, const char *fmt, ...)
{
    if (ssh->base_layer || !ssh->session_started) {
        GET_FORMATTED_MSG;

        /* EOF from the remote, if we were expecting it, does count as
         * a clean exit */
        ssh->exitcode = 0;

        /* Close the socket immediately, since the server has already
         * closed its end. */
        ssh_shutdown(ssh);

        logevent(ssh->logctx, msg);
        sfree(msg);
        seat_notify_remote_exit(ssh->seat);
    } else {
        /* This is responding to EOF after we've already seen some
         * other reason for terminating the session. */
        ssh_shutdown(ssh);
    }
}

void ssh_proto_error(Ssh *ssh, const char *fmt, ...)
{
    if (ssh->base_layer || !ssh->session_started) {
        GET_FORMATTED_MSG;

        ssh->exitcode = 128;

        ssh_bpp_queue_disconnect(ssh->bpp, msg,
                                 SSH2_DISCONNECT_PROTOCOL_ERROR);
        ssh_initiate_connection_close(ssh);

        logevent(ssh->logctx, msg);
        seat_connection_fatal(ssh->seat, "%s", msg);
        sfree(msg);
    }
}

void ssh_sw_abort(Ssh *ssh, const char *fmt, ...)
{
    if (ssh->base_layer || !ssh->session_started) {
        GET_FORMATTED_MSG;

        ssh->exitcode = 128;

        ssh_initiate_connection_close(ssh);

        logevent(ssh->logctx, msg);
        seat_connection_fatal(ssh->seat, "%s", msg);
        sfree(msg);

        seat_notify_remote_exit(ssh->seat);
    }
}

void ssh_user_close(Ssh *ssh, const char *fmt, ...)
{
    if (ssh->base_layer || !ssh->session_started) {
        GET_FORMATTED_MSG;

        /* Closing the connection due to user action, even if the
         * action is the user aborting during authentication prompts,
         * does count as a clean exit - except that this is also how
         * we signal ordinary session termination, in which case we
         * should use the exit status already sent from the main
         * session (if any). */
        if (ssh->exitcode < 0)
            ssh->exitcode = 0;

        ssh_initiate_connection_close(ssh);

        logevent(ssh->logctx, msg);
        sfree(msg);

        seat_notify_remote_exit(ssh->seat);
    }
}

void ssh_deferred_abort_callback(void *vctx)
{
    Ssh *ssh = (Ssh *)vctx;
    char *msg = ssh->deferred_abort_message;
    ssh->deferred_abort_message = NULL;
    ssh_sw_abort(ssh, msg);
    sfree(msg);
}

void ssh_sw_abort_deferred(Ssh *ssh, const char *fmt, ...)
{
    if (!ssh->deferred_abort_message) {
        GET_FORMATTED_MSG;
        ssh->deferred_abort_message = msg;
        queue_toplevel_callback(ssh_deferred_abort_callback, ssh);
    }
}

static void ssh_socket_log(Plug *plug, int type, SockAddr *addr, int port,
                           const char *error_msg, int error_code)
{
    Ssh *ssh = container_of(plug, Ssh, plug);

    /*
     * While we're attempting connection sharing, don't loudly log
     * everything that happens. Real TCP connections need to be logged
     * when we _start_ trying to connect, because it might be ages
     * before they respond if something goes wrong; but connection
     * sharing is local and quick to respond, and it's sufficient to
     * simply wait and see whether it worked afterwards.
     */

    if (!ssh->attempting_connshare)
        backend_socket_log(ssh->seat, ssh->logctx, type, addr, port,
                           error_msg, error_code, ssh->conf,
                           ssh->session_started);
}

static void ssh_closing(Plug *plug, const char *error_msg, int error_code,
                        bool calling_back)
{
    Ssh *ssh = container_of(plug, Ssh, plug);
    if (error_msg) {
        ssh_remote_error(ssh, "%s", error_msg);
    } else if (ssh->bpp) {
        ssh->bpp->input_eof = true;
        queue_idempotent_callback(&ssh->bpp->ic_in_raw);
    }
}

static void ssh_receive(Plug *plug, int urgent, const char *data, size_t len)
{
    Ssh *ssh = container_of(plug, Ssh, plug);

    /* Log raw data, if we're in that mode. */
    if (ssh->logctx)
        log_packet(ssh->logctx, PKT_INCOMING, -1, NULL, data, len,
                   0, NULL, NULL, 0, NULL);

    bufchain_add(&ssh->in_raw, data, len);
    if (!ssh->logically_frozen && ssh->bpp)
        queue_idempotent_callback(&ssh->bpp->ic_in_raw);

    ssh_check_frozen(ssh);
}

static void ssh_sent(Plug *plug, size_t bufsize)
{
    Ssh *ssh = container_of(plug, Ssh, plug);
    /*
     * If the send backlog on the SSH socket itself clears, we should
     * unthrottle the whole world if it was throttled. Also trigger an
     * extra call to the consumer of the BPP's output, to try to send
     * some more data off its bufchain.
     */
    if (bufsize < SSH_MAX_BACKLOG) {
        ssh_throttle_all(ssh, false, bufsize);
        queue_idempotent_callback(&ssh->ic_out_raw);
    }
}

static void ssh_hostport_setup(const char *host, int port, Conf *conf,
                               char **savedhost, int *savedport,
                               char **loghost_ret)
{
    char *loghost = conf_get_str(conf, CONF_loghost);
    if (loghost_ret)
        *loghost_ret = loghost;

    if (*loghost) {
        char *tmphost;
        char *colon;

        tmphost = dupstr(loghost);
        *savedport = 22;               /* default ssh port */

        /*
         * A colon suffix on the hostname string also lets us affect
         * savedport. (Unless there are multiple colons, in which case
         * we assume this is an unbracketed IPv6 literal.)
         */
        colon = host_strrchr(tmphost, ':');
        if (colon && colon == host_strchr(tmphost, ':')) {
            *colon++ = '\0';
            if (*colon)
                *savedport = atoi(colon);
        }

        *savedhost = host_strduptrim(tmphost);
        sfree(tmphost);
    } else {
        *savedhost = host_strduptrim(host);
        if (port < 0)
            port = 22;                 /* default ssh port */
        *savedport = port;
    }
}

static bool ssh_test_for_upstream(const char *host, int port, Conf *conf)
{
    char *savedhost;
    int savedport;
    bool ret;

    random_ref(); /* platform may need this to determine share socket name */
    ssh_hostport_setup(host, port, conf, &savedhost, &savedport, NULL);
    ret = ssh_share_test_for_upstream(savedhost, savedport, conf);
    sfree(savedhost);
    random_unref();

    return ret;
}

static const PlugVtable Ssh_plugvt = {
    ssh_socket_log,
    ssh_closing,
    ssh_receive,
    ssh_sent,
    NULL
};

/*
 * Connect to specified host and port.
 * Returns an error message, or NULL on success.
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *connect_to_host(
    Ssh *ssh, const char *host, int port, char **realhost,
    bool nodelay, bool keepalive)
{
    SockAddr *addr;
    const char *err;
    char *loghost;
    int addressfamily, sshprot;

    ssh_hostport_setup(host, port, ssh->conf,
                       &ssh->savedhost, &ssh->savedport, &loghost);

    ssh->plug.vt = &Ssh_plugvt;

    /*
     * Try connection-sharing, in case that means we don't open a
     * socket after all. ssh_connection_sharing_init will connect to a
     * previously established upstream if it can, and failing that,
     * establish a listening socket for _us_ to be the upstream. In
     * the latter case it will return NULL just as if it had done
     * nothing, because here we only need to care if we're a
     * downstream and need to do our connection setup differently.
     */
    ssh->connshare = NULL;
    ssh->attempting_connshare = true;  /* affects socket logging behaviour */
    ssh->s = ssh_connection_sharing_init(
        ssh->savedhost, ssh->savedport, ssh->conf, ssh->logctx,
        &ssh->plug, &ssh->connshare);
    if (ssh->connshare)
        ssh_connshare_provide_connlayer(ssh->connshare, &ssh->cl_dummy);
    ssh->attempting_connshare = false;
    if (ssh->s != NULL) {
        /*
         * We are a downstream.
         */
        ssh->bare_connection = true;
        ssh->fullhostname = NULL;
        *realhost = dupstr(host);      /* best we can do */

        if ((flags & FLAG_VERBOSE) || (flags & FLAG_INTERACTIVE)) {
            /* In an interactive session, or in verbose mode, announce
             * in the console window that we're a sharing downstream,
             * to avoid confusing users as to why this session doesn't
             * behave in quite the usual way. */
            const char *msg =
                "Reusing a shared connection to this server.\r\n";
            seat_stderr_pl(ssh->seat, ptrlen_from_asciz(msg));
        }
    } else {
        /*
         * We're not a downstream, so open a normal socket.
         */

        /*
         * Try to find host.
         */
        addressfamily = conf_get_int(ssh->conf, CONF_addressfamily);
        addr = name_lookup(host, port, realhost, ssh->conf, addressfamily,
                           ssh->logctx, "SSH connection");
        if ((err = sk_addr_error(addr)) != NULL) {
            sk_addr_free(addr);
            return err;
        }
        ssh->fullhostname = dupstr(*realhost);   /* save in case of GSSAPI */

        ssh->s = new_connection(addr, *realhost, port,
                                false, true, nodelay, keepalive,
                                &ssh->plug, ssh->conf);
        if ((err = sk_socket_error(ssh->s)) != NULL) {
            ssh->s = NULL;
            seat_notify_remote_exit(ssh->seat);
            return err;
        }
    }

    /*
     * The SSH version number is always fixed (since we no longer support
     * fallback between versions), so set it now.
     */
    sshprot = conf_get_int(ssh->conf, CONF_sshprot);
    assert(sshprot == 0 || sshprot == 3);
    if (sshprot == 0)
        /* SSH-1 only */
        ssh->version = 1;
    if (sshprot == 3 || ssh->bare_connection) {
        /* SSH-2 only */
        ssh->version = 2;
    }

    /*
     * Set up the initial BPP that will do the version string
     * exchange, and get it started so that it can send the outgoing
     * version string early if it wants to.
     */
    ssh->version_receiver.got_ssh_version = ssh_got_ssh_version;
    ssh->bpp = ssh_verstring_new(
        ssh->conf, ssh->logctx, ssh->bare_connection,
        ssh->version == 1 ? "1.5" : "2.0", &ssh->version_receiver,
        false, "PuTTY");
    ssh_connect_bpp(ssh);
    queue_idempotent_callback(&ssh->bpp->ic_in_raw);

    /*
     * loghost, if configured, overrides realhost.
     */
    if (*loghost) {
        sfree(*realhost);
        *realhost = dupstr(loghost);
    }

    return NULL;
}

/*
 * Throttle or unthrottle the SSH connection.
 */
void ssh_throttle_conn(Ssh *ssh, int adjust)
{
    int old_count = ssh->conn_throttle_count;
    bool frozen;

    ssh->conn_throttle_count += adjust;
    assert(ssh->conn_throttle_count >= 0);

    if (ssh->conn_throttle_count && !old_count) {
        frozen = true;
    } else if (!ssh->conn_throttle_count && old_count) {
        frozen = false;
    } else {
        return;                /* don't change current frozen state */
    }

    ssh->logically_frozen = frozen;
    ssh_check_frozen(ssh);
}

/*
 * Throttle or unthrottle _all_ local data streams (for when sends
 * on the SSH connection itself back up).
 */
static void ssh_throttle_all(Ssh *ssh, bool enable, size_t bufsize)
{
    if (enable == ssh->throttled_all)
        return;
    ssh->throttled_all = enable;
    ssh->overall_bufsize = bufsize;

    ssh_throttle_all_channels(ssh->cl, enable);
}

static void ssh_cache_conf_values(Ssh *ssh)
{
    ssh->pls.omit_passwords = conf_get_bool(ssh->conf, CONF_logomitpass);
    ssh->pls.omit_data = conf_get_bool(ssh->conf, CONF_logomitdata);
}

/*
 * Called to set up the connection.
 *
 * Returns an error message, or NULL on success.
 */
static const char *ssh_init(Seat *seat, Backend **backend_handle,
                            LogContext *logctx, Conf *conf,
                            const char *host, int port, char **realhost,
                            bool nodelay, bool keepalive)
{
    const char *p;
    Ssh *ssh;

    ssh = snew(Ssh);
    memset(ssh, 0, sizeof(Ssh));

    ssh->conf = conf_copy(conf);
    ssh_cache_conf_values(ssh);
    ssh->exitcode = -1;
    ssh->pls.kctx = SSH2_PKTCTX_NOKEX;
    ssh->pls.actx = SSH2_PKTCTX_NOAUTH;
    bufchain_init(&ssh->in_raw);
    bufchain_init(&ssh->out_raw);
    bufchain_init(&ssh->user_input);
    ssh->ic_out_raw.fn = ssh_bpp_output_raw_data_callback;
    ssh->ic_out_raw.ctx = ssh;

    ssh->term_width = conf_get_int(ssh->conf, CONF_width);
    ssh->term_height = conf_get_int(ssh->conf, CONF_height);

    ssh->backend.vt = &ssh_backend;
    *backend_handle = &ssh->backend;

    ssh->seat = seat;
    ssh->cl_dummy.logctx = ssh->logctx = logctx;

    random_ref(); /* do this now - may be needed by sharing setup code */
    ssh->need_random_unref = true;

    /* Map IP to loopback if SSH tunnel flag set. */
	if (conf_get_int(ssh->conf, CONF_lport_loopback)) {
        int nbAddr = 0;
		char* key, * val, type;
        char *loopback_addr[16];
		for (val = conf_get_str_strs(ssh->conf, CONF_portfwd, NULL, &key);
			val != NULL;
			val = conf_get_str_strs(ssh->conf, CONF_portfwd, key, &key)) {
			char* kp, * kp2, * vp, * vp2;
			char address_family, type;
			int sport, dport, sserv, dserv;
			char* sports, * dports, * saddr, * host;

			kp = key;

			address_family = 'A';
			type = 'L';
			if (*kp == 'A' || *kp == '4' || *kp == '6')
				address_family = *kp++;
			if (*kp == 'L' || *kp == 'R')
				type = *kp++;

			if ((kp2 = host_strchr(kp, ':')) != NULL) {
				/*
				 * There's a colon in the middle of the source port
				 * string, which means that the part before it is
				 * actually a source address.
				 */
				char* saddr_tmp = dupprintf("%.*s", (int)(kp2 - kp), kp);
				saddr = host_strduptrim(saddr_tmp);
				sfree(saddr_tmp);
			}
			else {
				saddr = NULL;
			}

			if (type == 'L') {
				char* errmsg;
                ULONG nteContext = 0;
                if (nbAddr == 16) {
                    bomb_out(ssh, "Too many IP addresses to map (>16)");
                }
                if (nbAddr < 16) {
                    char* result;
                    loopback_addr[nbAddr++] = saddr;
                }
			}
		}

        if (map_ip_to_loopback(&ssh->ipl, loopback_addr, nbAddr) != 0) {
            bomb_out(ssh, "Cannot map IP(s) to loopback");
        }
    }

    p = connect_to_host(ssh, host, port, realhost, nodelay, keepalive);
    if (p != NULL) {
        /* Call random_unref now instead of waiting until the caller
         * frees this useless Ssh object, in case the caller is
         * impatient and just exits without bothering, in which case
         * the random seed won't be re-saved. */
        ssh->need_random_unref = false;
        random_unref();
        return p;
    }

    return NULL;
}

static void ssh_free(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    bool need_random_unref;

    ssh_shutdown(ssh);

    conf_free(ssh->conf);
    if (ssh->connshare)
        sharestate_free(ssh->connshare);
    sfree(ssh->savedhost);
    sfree(ssh->fullhostname);
    sfree(ssh->specials);

#ifndef NO_GSSAPI
    if (ssh->gss_state.srv_name)
        ssh->gss_state.lib->release_name(
            ssh->gss_state.lib, &ssh->gss_state.srv_name);
    if (ssh->gss_state.ctx != NULL)
        ssh->gss_state.lib->release_cred(
            ssh->gss_state.lib, &ssh->gss_state.ctx);
    if (ssh->gss_state.libs)
        ssh_gss_cleanup(ssh->gss_state.libs);
#endif

    sfree(ssh->deferred_abort_message);

    delete_callbacks_for_context(ssh); /* likely to catch ic_out_raw */

    need_random_unref = ssh->need_random_unref;
    sfree(ssh);

    if (need_random_unref)
        random_unref();
}

/*
 * Reconfigure the SSH backend.
 */
static void ssh_reconfig(Backend *be, Conf *conf)
{
    Ssh *ssh = container_of(be, Ssh, backend);

    if (ssh->pinger)
        pinger_reconfig(ssh->pinger, ssh->conf, conf);

    ssh_ppl_reconfigure(ssh->base_layer, conf);

    conf_free(ssh->conf);
    ssh->conf = conf_copy(conf);
    ssh_cache_conf_values(ssh);
}

/*
 * Called to send data down the SSH connection.
 */
static size_t ssh_send(Backend *be, const char *buf, size_t len)
{
    Ssh *ssh = container_of(be, Ssh, backend);

    if (ssh == NULL || ssh->s == NULL)
        return 0;

    bufchain_add(&ssh->user_input, buf, len);
    if (ssh->base_layer)
        ssh_ppl_got_user_input(ssh->base_layer);

    return backend_sendbuffer(&ssh->backend);
}

/*
 * Called to query the current amount of buffered stdin data.
 */
static size_t ssh_sendbuffer(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    size_t backlog;

    if (!ssh || !ssh->s || !ssh->cl)
        return 0;

    backlog = ssh_stdin_backlog(ssh->cl);

    /* FIXME: also include sizes of pqs */

    /*
     * If the SSH socket itself has backed up, add the total backup
     * size on that to any individual buffer on the stdin channel.
     */
    if (ssh->throttled_all)
        backlog += ssh->overall_bufsize;

    return backlog;
}

/*
 * Called to set the size of the window from SSH's POV.
 */
static void ssh_size(Backend *be, int width, int height)
{
    Ssh *ssh = container_of(be, Ssh, backend);

    ssh->term_width = width;
    ssh->term_height = height;
    if (ssh->cl)
        ssh_terminal_size(ssh->cl, ssh->term_width, ssh->term_height);
}

struct ssh_add_special_ctx {
    SessionSpecial *specials;
    size_t nspecials, specials_size;
};

static void ssh_add_special(void *vctx, const char *text,
                            SessionSpecialCode code, int arg)
{
    struct ssh_add_special_ctx *ctx = (struct ssh_add_special_ctx *)vctx;
    SessionSpecial *spec;

    sgrowarray(ctx->specials, ctx->specials_size, ctx->nspecials);
    spec = &ctx->specials[ctx->nspecials++];
    spec->name = text;
    spec->code = code;
    spec->arg = arg;
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
static const SessionSpecial *ssh_get_specials(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);

    /*
     * Ask all our active protocol layers what specials they've got,
     * and amalgamate the list into one combined one.
     */

    struct ssh_add_special_ctx ctx;

    ctx.specials = NULL;
    ctx.nspecials = ctx.specials_size = 0;

    if (ssh->base_layer)
        ssh_ppl_get_specials(ssh->base_layer, ssh_add_special, &ctx);

    if (ctx.specials) {
        /* If the list is non-empty, terminate it with a SS_EXITMENU. */
        ssh_add_special(&ctx, NULL, SS_EXITMENU, 0);
    }

    sfree(ssh->specials);
    ssh->specials = ctx.specials;
    return ssh->specials;
}

/*
 * Send special codes.
 */
static void ssh_special(Backend *be, SessionSpecialCode code, int arg)
{
    Ssh *ssh = container_of(be, Ssh, backend);

    if (ssh->base_layer)
        ssh_ppl_special_cmd(ssh->base_layer, code, arg);
}

/*
 * This is called when the seat's output channel manages to clear some
 * backlog.
 */
static void ssh_unthrottle(Backend *be, size_t bufsize)
{
    Ssh *ssh = container_of(be, Ssh, backend);

    if (ssh->cl)
        ssh_stdout_unthrottle(ssh->cl, bufsize);
}

static bool ssh_connected(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    return ssh->s != NULL;
}

static bool ssh_sendok(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    return ssh->base_layer && ssh_ppl_want_user_input(ssh->base_layer);
}

void ssh_ldisc_update(Ssh *ssh)
{
    /* Called when the connection layer wants to propagate an update
     * to the line discipline options */
    if (ssh->ldisc)
        ldisc_echoedit_update(ssh->ldisc);
}

static bool ssh_ldisc(Backend *be, int option)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    return ssh->cl ? ssh_ldisc_option(ssh->cl, option) : false;
}

static void ssh_provide_ldisc(Backend *be, Ldisc *ldisc)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    ssh->ldisc = ldisc;
}

void ssh_got_exitcode(Ssh *ssh, int exitcode)
{
    ssh->exitcode = exitcode;
}

static int ssh_return_exitcode(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    if (ssh->s && (!ssh->session_started || ssh->base_layer))
        return -1;
    else
        return (ssh->exitcode >= 0 ? ssh->exitcode : INT_MAX);
}

/*
 * cfg_info for SSH is the protocol running in this session.
 * (1 or 2 for the full SSH-1 or SSH-2 protocol; -1 for the bare
 * SSH-2 connection protocol, i.e. a downstream; 0 for not-decided-yet.)
 */
static int ssh_cfg_info(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    if (ssh->version == 0)
        return 0; /* don't know yet */
    else if (ssh->bare_connection)
        return -1;
    else
        return ssh->version;
}

/*
 * Gross hack: pscp will try to start SFTP but fall back to scp1 if
 * that fails. This variable is the means by which scp.c can reach
 * into the SSH code and find out which one it got.
 */
extern bool ssh_fallback_cmd(Backend *be)
{
    Ssh *ssh = container_of(be, Ssh, backend);
    return ssh->fallback_cmd;
}

void ssh_got_fallback_cmd(Ssh *ssh)
{
    ssh->fallback_cmd = true;
}

const struct BackendVtable ssh_backend = {
    ssh_init,
    ssh_free,
    ssh_reconfig,
    ssh_send,
    ssh_sendbuffer,
    ssh_size,
    ssh_special,
    ssh_get_specials,
    ssh_connected,
    ssh_return_exitcode,
    ssh_sendok,
    ssh_ldisc,
    ssh_provide_ldisc,
    ssh_unthrottle,
    ssh_cfg_info,
    ssh_test_for_upstream,
    "ssh",
    PROT_SSH,
    22
};
