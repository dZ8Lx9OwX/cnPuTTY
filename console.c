/*
 * Common pieces between the platform console frontend modules.
 */

#include <stdbool.h>
#include <stdarg.h>

#include "putty.h"
#include "misc.h"
#include "console.h"

char *hk_absentmsg_common(const char *host, int port,
                          const char *keytype, const char *fingerprint)
{
    return dupprintf(
        "未缓存当前服务器主机密钥：\n"
        "  %s (端口 %d)\n"
        "无法为您保证服务器就是您\n"
        "需要连接的主机。\n"
        "服务器的 %s 密钥指纹是：\n"
        "  %s\n", host, port, keytype, fingerprint);
}

const char hk_absentmsg_interactive_intro[] =
    "如果您信任此主机，请输入\"y\"以将密钥\n"
    "添加到PuTTY的缓存并继续连接。\n"
    "如果您只想继续，仅连接一次，则不需要\n"
    "将密钥添加到缓存中，请输入\"n\"。\n"
    "如果您不信任此主机，请按Return放弃连接。\n";
const char hk_absentmsg_interactive_prompt[] =
    "将密钥存储在缓存中吗？？(y/n, 或者Return取消连接, "
    "i 了解更多信息) ";

char *hk_wrongmsg_common(const char *host, int port,
                         const char *keytype, const char *fingerprint)
{
    return dupprintf(
        "警告 - 潜在安全漏洞！！！\n"
        "主机密钥与PuTTY为此服务器缓存\n"
        "的不匹配:\n"
        "  %s (端口 %d)\n"
        "这意味着服务器管理员已经更改了主机密钥，\n"
        "或者您实际连接到了另外一台伪装成服务器的计算机。\n"
        "新的 %s 密钥指纹是:\n"
        "  %s\n", host, port, keytype, fingerprint);
}

const char hk_wrongmsg_interactive_intro[] =
    "如果您期待此更改并信任新的密钥，\n"
    "输入\"y\"以更新PuTTY缓存并继续连接。\n"
    "如果您想继续连接但不更新缓存，\n"
    "请输入\"n\"。\n"
    "如果您想完全放弃连接，请选择\n"
    "Return来取消连接。Return是唯一保证\n"
    "安全的选择。\n";
const char hk_wrongmsg_interactive_prompt[] =
    "更新缓存的密钥吗？？(y/n, 或者Return取消连接, "
    "i 了解更多信息) ";

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
