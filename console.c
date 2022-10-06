/*
 * Common pieces between the platform console frontend modules.
 */

#include <stdbool.h>
#include <stdarg.h>

#include "putty.h"
#include "misc.h"
#include "console.h"

const char weakcrypto_msg_common_fmt[] =
    "服务器支持的第一个 %s 是\n"
    "%s，低于设置的警告阀值。\n";

const char weakhk_msg_common_fmt[] =
    "我们为此服务器存储的第一个主机密钥类似\n"
    "是 %s，低于配置的警告阀值。\n"
    "服务器还提供以下类型的主机密钥\n"
    "超过过阀值， 我们还没有存储:\n"
    "%s\n";

const char console_continue_prompt[] = "继续连接？？(y/n) ";
const char console_abandoned_msg[] = "已放弃连接。\n";

const SeatDialogPromptDescriptions *console_prompt_descriptions(Seat *seat)
{
    static const SeatDialogPromptDescriptions descs = {
        .hk_accept_action = "enter \"y\"",
        .hk_connect_once_action = "enter \"n\"",
        .hk_cancel_action = "press Return",
        .hk_cancel_action_Participle = "Pressing Return",
    };
    return &descs;
}

bool console_batch_mode = false;

/*
 * Error message and/or fatal exit functions, all based on
 * console_print_error_msg which the platform front end provides.
 */
void console_print_error_msg_fmt_v(
    const char *prefix, const char *fmt, va_list ap)
{
    char *msg = dupvprintf(fmt, ap);
    console_print_error_msg(prefix, msg);
    sfree(msg);
}

void console_print_error_msg_fmt(const char *prefix, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v(prefix, fmt, ap);
    va_end(ap);
}

void modalfatalbox(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v("致命错误", fmt, ap);
    va_end(ap);
    cleanup_exit(1);
}

void nonfatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v("错误", fmt, ap);
    va_end(ap);
}

void console_connection_fatal(Seat *seat, const char *msg)
{
    console_print_error_msg("致命错误", msg);
    cleanup_exit(1);
}

/*
 * Console front ends redo their select() or equivalent every time, so
 * they don't need separate timer handling.
 */
void timer_change_notify(unsigned long next)
{
}
