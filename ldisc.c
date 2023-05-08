/*
 * ldisc.c: PuTTY line discipline. Sits between the input coming
 * from keypresses in the window, and the output channel leading to
 * the back end. Implements echo and/or local line editing,
 * depending on what's currently configured.
 */

#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include "putty.h"
#include "terminal.h"

typedef enum InputType { NORMAL, DEDICATED, NONINTERACTIVE } InputType;

struct input_chunk {
    struct input_chunk *next;
    InputType type;
    size_t size;
};

struct Ldisc_tag {
    Terminal *term;
    Backend *backend;
    Seat *seat;

    /*
     * When the backend is not reporting true from sendok(), we must
     * buffer the input received by ldisc_send(). It's stored in the
     * bufchain below, together with a linked list of input_chunk
     * blocks storing the extra metadata about special keys and
     * interactivity that ldisc_send() receives.
     *
     * All input is added to this buffer initially, but we then
     * process as much of it as possible immediately and hand it off
     * to the backend or a TermLineEditor. Anything left stays in this
     * buffer until ldisc_check_sendok() is next called, triggering a
     * run of the callback that tries again to process the queue.
     */
    bufchain input_queue;
    struct input_chunk *inchunk_head, *inchunk_tail;

    IdempotentCallback input_queue_callback;

    /*
     * Values cached out of conf.
     */
    bool telnet_keyboard, telnet_newline;
    int protocol, localecho, localedit;

    TermLineEditor *le;
    TermLineEditorCallbackReceiver le_rcv;

    /* We get one of these communicated to us by
     * term_get_userpass_input while it's reading a prompt, so that we
     * can push data straight into it */
    TermLineEditor *userpass_le;
};

#define ECHOING (ldisc->localecho == FORCE_ON || \
                 (ldisc->localecho == AUTO && \
                      (backend_ldisc_option_state(ldisc->backend, LD_ECHO))))
#define EDITING (ldisc->localedit == FORCE_ON || \
                 (ldisc->localedit == AUTO && \
                      (backend_ldisc_option_state(ldisc->backend, LD_EDIT))))

static void ldisc_input_queue_callback(void *ctx);

static const TermLineEditorCallbackReceiverVtable ldisc_lineedit_receiver_vt;

#define CTRL(x) (x^'@')

Ldisc *ldisc_create(Conf *conf, Terminal *term, Backend *backend, Seat *seat)
{
    Ldisc *ldisc = snew(Ldisc);
    memset(ldisc, 0, sizeof(Ldisc));

    ldisc->backend = backend;
    ldisc->term = term;
    ldisc->seat = seat;

    bufchain_init(&ldisc->input_queue);

    ldisc->input_queue_callback.fn = ldisc_input_queue_callback;
    ldisc->input_queue_callback.ctx = ldisc;
    bufchain_set_callback(&ldisc->input_queue, &ldisc->input_queue_callback);

    if (ldisc->term) {
        ldisc->le_rcv.vt = &ldisc_lineedit_receiver_vt;
        ldisc->le = lineedit_new(ldisc->term, 0, &ldisc->le_rcv);
    }

    ldisc_configure(ldisc, conf);

    /* Link ourselves into the backend and the terminal */
    if (term)
        term->ldisc = ldisc;
    if (backend)
        backend_provide_ldisc(backend, ldisc);

    return ldisc;
}

void ldisc_configure(Ldisc *ldisc, Conf *conf)
{
    ldisc->telnet_keyboard = conf_get_bool(conf, CONF_telnet_keyboard);
    ldisc->telnet_newline = conf_get_bool(conf, CONF_telnet_newline);
    ldisc->protocol = conf_get_int(conf, CONF_protocol);
    ldisc->localecho = conf_get_int(conf, CONF_localecho);
    ldisc->localedit = conf_get_int(conf, CONF_localedit);

    unsigned flags = 0;
    if (ldisc->protocol == PROT_RAW)
        flags |= LE_CRLF_NEWLINE;
    if (ldisc->telnet_keyboard)
        flags |= LE_INTERRUPT | LE_SUSPEND | LE_ABORT;
    lineedit_modify_flags(ldisc->le, ~0U, flags);
}

void ldisc_free(Ldisc *ldisc)
{
    bufchain_clear(&ldisc->input_queue);
    while (ldisc->inchunk_head) {
        struct input_chunk *oldhead = ldisc->inchunk_head;
        ldisc->inchunk_head = ldisc->inchunk_head->next;
        sfree(oldhead);
    }
    lineedit_free(ldisc->le);
    if (ldisc->term)
        ldisc->term->ldisc = NULL;
    if (ldisc->backend)
        backend_provide_ldisc(ldisc->backend, NULL);
    delete_callbacks_for_context(ldisc);
    sfree(ldisc);
}

void ldisc_echoedit_update(Ldisc *ldisc)
{
    seat_echoedit_update(ldisc->seat, ECHOING, EDITING);

    /*
     * If we've just turned off local line editing mode, and our
     * TermLineEditor had a partial buffer, then send the contents of
     * the buffer. Rationale: (a) otherwise you lose data; (b) the
     * user quite likely typed the buffer contents _anticipating_ that
     * local editing would be turned off shortly, and the event was
     * slow arriving.
     */
    if (!EDITING)
        lineedit_send_line(ldisc->le);
}

void ldisc_provide_userpass_le(Ldisc *ldisc, TermLineEditor *le)
{
    /*
     * Called by term_get_userpass_input to tell us when it has its
     * own TermLineEditor processing a password prompt, so that we can
     * inject our input into that instead of putting it into our own
     * TermLineEditor or sending it straight to the backend.
     */
    ldisc->userpass_le = le;
}

static inline bool is_dedicated_byte(char c, InputType type)
{
    switch (type) {
      case DEDICATED:
        return true;
      case NORMAL:
        return false;
      case NONINTERACTIVE:
        /*
         * Non-interactive input (e.g. from a paste) doesn't come with
         * the ability to distinguish dedicated keypresses like Return
         * from generic ones like Ctrl+M. So we just have to make up
         * an answer to this question. In particular, we _must_ treat
         * Ctrl+M as the Return key, because that's the only way a
         * newline can be pasted at all.
         */
        return c == '\r';
      default:
        unreachable("those values should be exhaustive");
    }
}

static void ldisc_input_queue_consume(Ldisc *ldisc, size_t size)
{
    bufchain_consume(&ldisc->input_queue, size);
    while (size > 0) {
        size_t thissize = (size < ldisc->inchunk_head->size ?
                           size : ldisc->inchunk_head->size);
        ldisc->inchunk_head->size -= thissize;
        size -= thissize;

        if (!ldisc->inchunk_head->size) {
            struct input_chunk *oldhead = ldisc->inchunk_head;
            ldisc->inchunk_head = ldisc->inchunk_head->next;
            if (!ldisc->inchunk_head)
                ldisc->inchunk_tail = NULL;
            sfree(oldhead);
        }
    }
}

static void ldisc_lineedit_to_terminal(
    TermLineEditorCallbackReceiver *rcv, ptrlen data)
{
    Ldisc *ldisc = container_of(rcv, Ldisc, le_rcv);
    if (ECHOING)
        seat_stdout(ldisc->seat, data.ptr, data.len);
}

static void ldisc_lineedit_to_backend(
    TermLineEditorCallbackReceiver *rcv, ptrlen data)
{
    Ldisc *ldisc = container_of(rcv, Ldisc, le_rcv);
    backend_send(ldisc->backend, data.ptr, data.len);
}

static void ldisc_lineedit_special(
    TermLineEditorCallbackReceiver *rcv, SessionSpecialCode code, int arg)
{
    Ldisc *ldisc = container_of(rcv, Ldisc, le_rcv);
    backend_special(ldisc->backend, code, arg);
}

static void ldisc_lineedit_newline(TermLineEditorCallbackReceiver *rcv)
{
    Ldisc *ldisc = container_of(rcv, Ldisc, le_rcv);
    if (ldisc->protocol == PROT_RAW)
        backend_send(ldisc->backend, "\r\n", 2);
    else if (ldisc->protocol == PROT_TELNET && ldisc->telnet_newline)
        backend_special(ldisc->backend, SS_EOL, 0);
    else
        backend_send(ldisc->backend, "\r", 1);
}

static const TermLineEditorCallbackReceiverVtable
ldisc_lineedit_receiver_vt = {
    .to_terminal = ldisc_lineedit_to_terminal,
    .to_backend = ldisc_lineedit_to_backend,
    .special = ldisc_lineedit_special,
    .newline = ldisc_lineedit_newline,
};

void ldisc_check_sendok(Ldisc *ldisc)
{
    queue_idempotent_callback(&ldisc->input_queue_callback);
}

void ldisc_send(Ldisc *ldisc, const void *vbuf, int len, bool interactive)
{
    assert(ldisc->term);

    if (interactive) {
        /*
         * Interrupt a paste from the clipboard, if one was in
         * progress when the user pressed a key. This is easier than
         * buffering the current piece of data and saving it until the
         * terminal has finished pasting, and has the potential side
         * benefit of permitting a user to cancel an accidental huge
         * paste.
         */
        term_nopaste(ldisc->term);
    }

    InputType type;
    if (len < 0) {
        /*
         * Less than zero means null terminated special string.
         */
        len = strlen(vbuf);
        type = DEDICATED;
    } else {
        type = interactive ? NORMAL : NONINTERACTIVE;
    }

    /*
     * Append our data to input_queue, and ensure it's marked with the
     * right type.
     */
    bufchain_add(&ldisc->input_queue, vbuf, len);
    if (!(ldisc->inchunk_tail && ldisc->inchunk_tail->type == type)) {
        struct input_chunk *new_chunk = snew(struct input_chunk);

        new_chunk->type = type;
        new_chunk->size = 0;

        new_chunk->next = NULL;
        if (ldisc->inchunk_tail)
            ldisc->inchunk_tail->next = new_chunk;
        else
            ldisc->inchunk_head = new_chunk;
        ldisc->inchunk_tail = new_chunk;
    }
    ldisc->inchunk_tail->size += len;

    /*
     * And process as much of the data immediately as we can.
     */
    if (EDITING) {
        while (len--) {
            int c;
            c = (unsigned char)(*buf++) + keyflag;
            if (!interactive && c == '\r')
                c += KCTRL('@');
            switch (ldisc->quotenext ? ' ' : c) {
                /*
                 * ^h/^?: delete, and output BSBs, to return to
                 * last character boundary (in UTF-8 mode this may
                 * be more than one byte)
                 * ^w: delete, and output BSBs, to return to last
                 * space/nonspace boundary
                 * ^u: delete, and output BSBs, to return to BOL
                 * ^c: Do a ^u then send a telnet IP
                 * ^z: Do a ^u then send a telnet SUSP
                 * ^\: Do a ^u then send a telnet ABORT
                 * ^r: echo "^R\n" and redraw line
                 * ^v: quote next char
                 * ^d: if at BOL, end of file and close connection,
                 * else send line and reset to BOL
                 * ^m: send line-plus-\r\n and reset to BOL
                 */
              case KCTRL('H'):
              case KCTRL('?'):         /* backspace/delete */
                if (ldisc->buflen > 0) {
                    do {
                        if (ECHOING)
                            bsb(ldisc, plen(ldisc, ldisc->buf[ldisc->buflen - 1]));
                        ldisc->buflen--;
                    } while (!char_start(ldisc, ldisc->buf[ldisc->buflen]));
                }
                break;
              case CTRL('W'):          /* delete word */
                while (ldisc->buflen > 0) {
                    if (ECHOING)
                        bsb(ldisc, plen(ldisc, ldisc->buf[ldisc->buflen - 1]));
                    ldisc->buflen--;
                    if (ldisc->buflen > 0 &&
                        isspace((unsigned char)ldisc->buf[ldisc->buflen-1]) &&
                        !isspace((unsigned char)ldisc->buf[ldisc->buflen]))
                        break;
                }
                break;
              case CTRL('U'):          /* delete line */
              case CTRL('C'):          /* Send IP */
              case CTRL('\\'):         /* Quit */
              case CTRL('Z'):          /* Suspend */
                while (ldisc->buflen > 0) {
                    if (ECHOING)
                        bsb(ldisc, plen(ldisc, ldisc->buf[ldisc->buflen - 1]));
                    ldisc->buflen--;
                }
                if (c == CTRL('U'))
                    break;             /* ^U *just* erases a line */
                ldisc_to_backend_special(ldisc, SS_EL, 0);
                /*
                 * We don't send IP, SUSP or ABORT if the user has
                 * configured telnet specials off! This breaks
                 * talkers otherwise.
                 */
                if (!ldisc->telnet_keyboard)
                    goto default_case;
                if (c == CTRL('C'))
                    ldisc_to_backend_special(ldisc, SS_IP, 0);
                if (c == CTRL('Z'))
                    ldisc_to_backend_special(ldisc, SS_SUSP, 0);
                if (c == CTRL('\\'))
                    ldisc_to_backend_special(ldisc, SS_ABORT, 0);
                break;
              case CTRL('R'):          /* redraw line */
                if (ECHOING) {
                    int i;
                    c_write(ldisc, "^R\r\n", 4);
                    for (i = 0; i < ldisc->buflen; i++)
                        pwrite(ldisc, ldisc->buf[i]);
                }
                break;
              case CTRL('V'):          /* quote next char */
                ldisc->quotenext = true;
                break;
              case CTRL('D'):          /* logout or send */
                if (ldisc->buflen == 0) {
                    ldisc_to_backend_special(ldisc, SS_EOF, 0);
                } else {
                    ldisc_to_backend_raw(ldisc, ldisc->buf, ldisc->buflen);
                    ldisc->buflen = 0;
                }
                break;
                /*
                 * This particularly hideous bit of code from RDB
                 * allows ordinary ^M^J to do the same thing as
                 * magic-^M when in Raw protocol. The line `case
                 * KCTRL('M'):' is _inside_ the if block. Thus:
                 *
                 *  - receiving regular ^M goes straight to the
                 *    default clause and inserts as a literal ^M.
                 *  - receiving regular ^J _not_ directly after a
                 *    literal ^M (or not in Raw protocol) fails the
                 *    if condition, leaps to the bottom of the if,
                 *    and falls through into the default clause
                 *    again.
                 *  - receiving regular ^J just after a literal ^M
                 *    in Raw protocol passes the if condition,
                 *    deletes the literal ^M, and falls through
                 *    into the magic-^M code
                 *  - receiving a magic-^M empties the line buffer,
                 *    signals end-of-line in one of the various
                 *    entertaining ways, and _doesn't_ fall out of
                 *    the bottom of the if and through to the
                 *    default clause because of the break.
                 */
              case CTRL('J'):
                if (ldisc->protocol == PROT_RAW &&
                    ldisc->buflen > 0 && ldisc->buf[ldisc->buflen - 1] == '\r') {
                    if (ECHOING)
                        bsb(ldisc, plen(ldisc, ldisc->buf[ldisc->buflen - 1]));
                    ldisc->buflen--;
                    /* FALLTHROUGH */
              case KCTRL('M'):         /* send with newline */
                    if (ldisc->buflen > 0)
                        ldisc_to_backend_raw(ldisc, ldisc->buf, ldisc->buflen);
                    if (ldisc->protocol == PROT_RAW)
                        ldisc_to_backend_raw(ldisc, "\r\n", 2);
                    else if (ldisc->protocol == PROT_TELNET && ldisc->telnet_newline)
                        ldisc_to_backend_special(ldisc, SS_EOL, 0);
                    else
                        ldisc_to_backend_raw(ldisc, "\r", 1);
                    if (ECHOING)
                        c_write(ldisc, "\r\n", 2);
                    ldisc->buflen = 0;
                    break;
                }
                /* FALLTHROUGH */
              default:                 /* get to this label from ^V handler */
              default_case:
                sgrowarray(ldisc->buf, ldisc->bufsiz, ldisc->buflen);
                ldisc->buf[ldisc->buflen++] = c;
                if (ECHOING)
                    pwrite(ldisc, (unsigned char) c);
                ldisc->quotenext = false;
                break;
            }
        }

        if (!backend_sendok(ldisc->backend)) {
            ldisc_input_queue_consume(ldisc, buf - start);
            break;
        }

        /*
         * Either perform local editing, or just send characters.
         */
        if (EDITING) {
            while (len > 0) {
                char c = *buf++;
                len--;

                bool dedicated = is_dedicated_byte(c, type);
                lineedit_input(ldisc->le, c, dedicated);
            }
            ldisc_input_queue_consume(ldisc, buf - start);
        } else {
            if (ECHOING)
                seat_stdout(ldisc->seat, buf, len);
            if (type == DEDICATED && ldisc->protocol == PROT_TELNET) {
                while (len > 0) {
                    char c = *buf++;
                    len--;
                    switch (c) {
                      case CTRL('M'):
                        if (ldisc->telnet_newline)
                            backend_special(ldisc->backend, SS_EOL, 0);
                        else
                            backend_send(ldisc->backend, "\r", 1);
                        break;
                      case CTRL('?'):
                      case CTRL('H'):
                        if (ldisc->telnet_keyboard) {
                            backend_special(ldisc->backend, SS_EC, 0);
                            break;
                        }
                      case CTRL('C'):
                        if (ldisc->telnet_keyboard) {
                            backend_special(ldisc->backend, SS_IP, 0);
                            break;
                        }
                      case CTRL('Z'):
                        if (ldisc->telnet_keyboard) {
                            backend_special(ldisc->backend, SS_SUSP, 0);
                            break;
                        }

                      default:
                        backend_send(ldisc->backend, &c, 1);
                        break;
                    }
                }
                ldisc_input_queue_consume(ldisc, buf - start);
            } else {
                backend_send(ldisc->backend, buf, len);
                ldisc_input_queue_consume(ldisc, len);
            }
        }
    }
}
