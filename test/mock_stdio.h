#ifndef STDIO_WRAPPER
#define STDIO_WRAPPER

#include <stdbool.h>

const char *mock_stdio_get_stdout(void);
void mock_stdio_reset_stdout(void);
void mock_stdio_set_capture_stdout(bool capture);
const char *mock_stdio_get_stderr(void);
void mock_stdio_reset_stderr(void);
void mock_stdio_set_capture_stderr(bool capture);

#endif
