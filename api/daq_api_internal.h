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

DAQ_Config_h daq_module_config_get_config(DAQ_ModuleConfig_h modcfg);
int daq_module_instantiate(DAQ_Instance_h instance, DAQ_ModuleConfig_h modcfg);
DAQ_Instance_h daq_modinst_get_instance(DAQ_ModuleInstance_h modinst);
void daq_modinst_resolve_subapi(DAQ_ModuleInstance_h modinst, DAQ_InstanceAPI_t *api);
void daq_instance_set_errbuf(DAQ_Instance_h instance, const char *format, ...);
void daq_instance_set_errbuf_va(DAQ_Instance_h instance, const char *format, va_list ap);
void populate_base_api(DAQ_BaseAPI_t *base_api);

#endif /* _DAQ_API_INTERNAL_H */
