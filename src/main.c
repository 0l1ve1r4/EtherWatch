//========================================================================
//    This file is part of mocd EtherWatch, a forensics basic toolkit.
//    Copyright (C) 2024 Guilherme Oliveira Santos
//    This is free software: you can redistribute it and/or modify it
//    under the terms of the GNU GPL3 or any later version.
//======================================================================

#include "../include/debug.h"
#include "../include/pkg_handler.h"

#include <pthread.h>

int main(){
    pthread_t capture_thread;

    pthread_create(&capture_thread, NULL, startPackageCapture, NULL);
    
    pthread_join(capture_thread, NULL);
    
    return 0;

}