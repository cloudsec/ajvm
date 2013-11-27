/*
 * safe_printf.c 

 * by Zhitong Wang	zhitong.wangzt@aliyun-inc.com
 *
 * XXX work on x86_64 system.
 *
 */

#include <stdio.h>
#include <string.h>

#include "safe_printf.h"

char *itoa(long num, char *str, int radix)
{
        char string[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        char *s = str, *p;
        char tmp;

        if (num < 0)
                return NULL;

        if (!num) {
                *s++ = '0';
                *s = 0;
                return s;
        }

        while (num) {
                *s++ = string[num % radix];
                num /= radix;
        }
        *s = 0;

        --s;
        for (p = str; p < s; s--, p++) {
                tmp = *p;
                *p = *s;
                *s = tmp;
        }

        return s;
}

int safe_write_char(char value)
{
	write(1, &value, sizeof(char));
}

int safe_write_string(char *value)
{
	write(1, value, strlen(value) + 1);
}

int handle_format_string(char *format, char *buf)
{
	int i, num;
	char c;

	if (format[0] == '\0') {
		safe_write_string(buf);
		return 0;
	}

	if (format[0] == '0') {
		num = atoi(format + 1);
		c = '0';
	}
	else {
		num = atoi(format);
		c = ' ';
	}

	num -= strlen(buf);
	for (i = 0; i < num; i++)
		safe_write_char(c);
	safe_write_string(buf);
}

void safe_printf(const char *fmt, ...)
{
	FUNC_ARG func_arg;
	const char *s = fmt;
	int type_flag = 0;
	int long_flag = 0;
	char tmp[32] = {0}, *q = tmp;

	INIT_ARG(func_arg)
	GET_ARG(func_arg)
	VA_START_ARG(func_arg)

	while (*s) {
		switch (*s) {
		case '%':
			if (type_flag == 1) {
				safe_write_char(*s);
				type_flag = 0;
			}
			else
				type_flag = 1;
			s++;
			break;
		case 'd':
			if (type_flag == 1) {
				long value;
				char buf[32] = {0};

				if (long_flag == 1)
					VA_NEXT_ARG(value, func_arg, long)
				else
					VA_NEXT_ARG(value, func_arg, int)
				itoa(value, buf, 10);
				safe_write_string(buf);
				type_flag = 0;
				long_flag = 0;
			}
			else
				safe_write_char(*s);
			s++;
			break;
		case 'x':
			if (type_flag == 1) {
				long value;
				char buf[64] = {0};

				*q = 0;
				if (long_flag == 1)
					VA_NEXT_ARG(value, func_arg, long)
				else
					VA_NEXT_ARG(value, func_arg, int)
				itoa(value, buf, 16);
				handle_format_string(tmp, buf);

				memset(tmp, '\0', 32);
				q = tmp;
				type_flag = 0;
				long_flag = 0;
			}
			else
				safe_write_char(*s);
			s++;
			break;
		case 'l':
			if (type_flag == 1)
				long_flag = 1;
			else
				safe_write_char(*s);
			s++;
			break;
		case 'c':
			if (type_flag == 1) {
				char value;

				VA_NEXT_ARG(value, func_arg, char)
				safe_write_char(value);
				type_flag = 0;
			}
			else
				safe_write_char(*s);
			s++;
			break;
		case 's':
			if (type_flag == 1) {
				char *value;

				VA_NEXT_ARG(value, func_arg, char *)
				safe_write_string(value);
				type_flag = 0;
			}
			else
				safe_write_char(*s);
			s++;
			break;
		case '0' ... '9':
			if (type_flag == 1)
				*q++ = *s;
			else
				safe_write_char(*s);
			s++;	
			break;
		default:
			safe_write_char(*s++);
		}
	}
}
