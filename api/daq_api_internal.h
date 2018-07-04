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

void daq_instance_set_errbuf(DAQ_Instance_h instance, const char *format, ...);
int daq_module_instantiate(DAQ_ModuleConfig_h modcfg, DAQ_Instance_h instance);
void daq_modinst_resolve_subapi(DAQ_ModuleInstance_h modinst, DAQ_InstanceAPI_t *api);

#endif /* _DAQ_API_INTERNAL_H */
