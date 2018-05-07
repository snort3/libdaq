#ifndef _DAQ_API_INTERNAL_H
#define _DAQ_API_INTERNAL_H

#include <stdio.h>

#include "daq_api.h"

extern int daq_verbosity;

#ifdef WIN32
inline void DEBUG(char *fmt, ...)
{

    if (daq_verbosity > 0)
    {
        va_list ap;
        va_start(ap, fmt);

        printf(fmt, ap);

        va_end(ap);
    }
}
#else
#define DEBUG(...) do { if (daq_verbosity > 0) { printf(__VA_ARGS__); } } while (0)
#endif

void daq_instance_set_context(DAQ_Instance_h instance, void *context);
void *daq_instance_get_context(DAQ_Instance_h instance);
void daq_instance_set_errbuf(DAQ_Instance_h instance, const char *format, ...);

#endif /* _DAQ_API_INTERNAL_H */
