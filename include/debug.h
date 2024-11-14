//========================================================================
//    This file is part of EtherWatch, a forensics basic toolkit.
//    Copyright (C) 2024 Guilherme Oliveira Santos
//    This is free software: you can redistribute it and/or modify it
//    under the terms of the GNU GPL3 or any later version.
//========================================================================

#ifndef DEBUG_H
#define DEBUG_H

//========================================================================
// INCLUDES
//========================================================================

#include <stdio.h>

//========================================================================
// DEFINES
//========================================================================

#define RESET           "\033[0m"
#define BOLD            "\033[1m"
#define RED_DEBUG       "\033[31m"
#define GREEN_DEBUG     "\033[32m"
#define YELLOW_DEBUG    "\033[33m"
#define BLUE_DEBUG      "\033[34m"
#define CYAN_DEBUG      "\033[36m"

#define DEBUG_PRINT(color, msg) \
 printf(color BOLD "[DEBUG]: %s" RESET "\n", msg)

#define DEBUGGING_EXAMPLE()                                     \
 DEBUG_PRINT(RED_DEBUG, "This is a critical error message!");   \
 DEBUG_PRINT(GREEN_DEBUG, "This is a success message.");        \
 DEBUG_PRINT(YELLOW_DEBUG, "This is a warning message.");       \
 DEBUG_PRINT(BLUE_DEBUG, "This is an informational message.");  \
 DEBUG_PRINT(CYAN_DEBUG, "This is a debugging message.");       \

#endif