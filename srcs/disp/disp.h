#pragma once

void
disp_err_mode(void);

void
puts_nolock(_In_z_ const char *str);

void
printf(_In_z_ _Printf_format_string_ const char *format, ...)
	__attribute__((format(printf, 1, 2)));

