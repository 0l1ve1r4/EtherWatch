//========================================================================
//    This file is part of EtherWatch, a forensics basic toolkit.
//    Copyright (C) 2024 Guilherme Oliveira Santos
//    This is free software: you can redistribute it and/or modify it
//    under the terms of the GNU GPL3 or any later version.
//======================================================================

#ifndef PKG_HANDLER_H
#define PKG_HANDLER_H

// Session to be saved in a database to future analysis
#include <stdint.h>
#define IPV4_STRING_LEN 16
#define SESSION_SAVE_FILE "./packages.dat   "

typedef struct {
    int32_t src_port;
    int32_t dest_port;
    char src_ip[IPV4_STRING_LEN];
    char dest_ip[IPV4_STRING_LEN];
    char protocol[INT8_MAX];
} Session;


void * startPackageCapture(void * args); 

Session *loadSessions(const char *filename, size_t *session_count);

size_t countSessions(const char *filename);

#endif