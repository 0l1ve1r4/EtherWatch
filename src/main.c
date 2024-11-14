//========================================================================
//    This file is part of EtherWatch, a forensics basic toolkit.
//    Copyright (C) 2024 Guilherme Oliveira Santos
//    This is free software: you can redistribute it and/or modify it
//    under the terms of the GNU GPL3 or any later version.
//========================================================================


#include "../include/debug.h"
#include "../include/pkg_handler.h"

#define RAYGUI_IMPLEMENTATION

#include "../libs/raygui.h"

#include <pthread.h>

#define SCREEN_WIDTH    720
#define SCREEN_HEIGHT   600
#define TARGET_FPS      30

static Session * g_sessionsArray;
static uint8_t is_loaded = 0;
static size_t session_count;
int main() {
    InitWindow(SCREEN_WIDTH, SCREEN_HEIGHT, "EtherWatch");
    SetTargetFPS(TARGET_FPS);
    
    pthread_t capture_thread;


    // Main GUI loop
    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        // Capture button
        if (GuiButton((Rectangle){0, 0, 100, 30}, "Start Capture")) {
            pthread_create(&capture_thread, NULL, &startPackageCapture, NULL);

            // Start packet capture (pseudo code, integrate with libpcap)
            // start_packet_capture();
        }
        
        if (GuiButton((Rectangle){100, 0, 100, 30}, "Stop Capture")) {
            pthread_join(capture_thread, NULL);            
            g_sessionsArray = loadSessions(SESSION_SAVE_FILE, &session_count);
            is_loaded = 1;
            // Stop packet capture
            // stop_packet_capture();
        }

        if (GuiButton((Rectangle){200, 0, 100, 30}, "Log Packets")) {
            // Save captured packets to a log file
            // log_packets(packets, packetCount);
        }

        // Packet Display Area
        DrawRectangle(10, 100, 700, 450, LIGHTGRAY);
        DrawText("ID    "
                 "Timestamp          "
                 "Source IP         "
                 "Destination IP    "
                 "Protocol          "
                 "Source Port       "
                 "Destinatination Port"
                 , 20, 110, 10, DARKGRAY);
        DrawLine(10, 125, 710, 125, DARKGRAY);

        // Display packets
        if (is_loaded){ 
            for (size_t i = 0; i < 21; i++) {
                int yPos = 130 + i * 20;
                DrawText(TextFormat("%d", i), 20, yPos, 10, BLACK);
                DrawText("-", 60, yPos, 10, BLACK);
                DrawText(g_sessionsArray[i].src_ip, 130, yPos, 10, BLACK);
                DrawText(g_sessionsArray[i].dest_ip, 230, yPos, 10, BLACK);
                DrawText(g_sessionsArray[i].protocol, 320, yPos, 10, BLACK);
                DrawText(TextFormat("%d", g_sessionsArray[i].src_port), 
                        430, yPos, 10, BLACK);
                DrawText(TextFormat("%d", g_sessionsArray[i].dest_ip),
                         530, yPos, 10, BLACK);
            }
            
        }

        EndDrawing();
    }

    // Clean up
    CloseWindow();
    return 0;
}