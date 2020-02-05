# Packet-Watcher
Full project for Packet-Watcher project

This project is an adaptation of a packet sniffer.

Description:
  - Captures all incoming packets directed toward the system it is running on.
  - Will display information within the packet header and tcp header.
  - Creates log files for each Layer 7 protocol you specify.
  - Directs packet information into those log files for further analysis.
  
Setup:
  - In this repository is a bash script that will ask you what protocols you would like to watch for.
    - Make sure you enter the correct name and port number or protocol (This matters when the log files are created)
  - When running the setup.sh you MUST execute like this ... source setup.sh
    - DO NOT execute like ./setup.sh or sh setup.sh
    
Once the setup is finished the python program will run and it will start capturing incoming packets.

Note - This program does not halt any packets from reaching the rest of your system. All functions still work normally.
