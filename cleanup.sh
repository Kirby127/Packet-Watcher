#!/bin/bash

#Cleaning file for packet_watcher

echo -----------------------------------------------------
echo "Cleaning up packet-watcher."
echo -----------------------------------------------------

#Removes all log files and sends output to /dev/null
rm *.log > /dev/null 2>&1

#Removes the txt file and sends output to /dev/null
rm *.txt > /dev/null 2>&1

echo ""
echo -----------------------------------------------------
echo "All log files and protocols file have been removed"
echo -----------------------------------------------------
