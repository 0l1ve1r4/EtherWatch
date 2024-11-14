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

int main() {
    InitWindow(SCREEN_WIDTH, SCREEN_HEIGHT, "EtherWatch");
    SetTargetFPS(TARGET_FPS);
    
    pthread_t capture_thread;


    // Main GUI loop
    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        // Capture button
        if (GuiButton((Rectangle){10, 50, 100, 30}, "Start Capture")) {
            pthread_create(&capture_thread, NULL, &startPackageCapture, NULL);

            // Start packet capture (pseudo code, integrate with libpcap)
            // start_packet_capture();
        }
        
        if (GuiButton((Rectangle){120, 50, 100, 30}, "Stop Capture")) {
            pthread_join(capture_thread, NULL);

            // Stop packet capture
            // stop_packet_capture();
        }

        if (GuiButton((Rectangle){230, 50, 100, 30}, "Log Packets")) {
            // Save captured packets to a log file
            // log_packets(packets, packetCount);
        }

        // Packet Display Area
        DrawRectangle(10, 100, 700, 450, LIGHTGRAY);
        DrawText("ID    Timestamp          Source IP        Destination IP    Protocol", 20, 110, 10, DARKGRAY);
        DrawLine(10, 125, 700, 125, DARKGRAY);

        // Display packets
        /*
        for (int i = 0; i < packetCount; i++) {
            int yPos = 130 + i * 20;
            DrawText(TextFormat("%d", packets[i].id), 20, yPos, 10, BLACK);
            DrawText(packets[i].timestamp, 60, yPos, 10, BLACK);
            DrawText(packets[i].srcIP, 180, yPos, 10, BLACK);
            DrawText(packets[i].dstIP, 320, yPos, 10, BLACK);
            DrawText(packets[i].protocol, 480, yPos, 10, BLACK);
        }*/

        EndDrawing();
    }

    // Clean up
    CloseWindow();
    return 0;
}