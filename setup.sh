#!/bin/bash

#Setup file for packet watcher project.

#IMPORTANT! YOU MUST RUN THIS FILE WITH THE SOURCE COMMAND IN FRONT --- source setup.sh

echo What protocols would you like to watch?

#Array is using a key pair to store the protocol and the port number
declare -A protocols
x=1
while [ $x -lt 999 ]
do
	read proto
	echo ""
	echo What is the port number?
	read port
	echo ""
	echo "Would you like to enter another? (y or n)"
	read ans
	protocols[$proto]=$port
	if [ $ans = "n" ]; then
		let x=x+1000
		continue
	fi
	echo ""
	echo Enter another protocol
done


echo ---------------------------
echo Creating log Files
echo ---------------------------

#echo ${protocols["ssh"]}

#Creates the log files and protocol.txt file used in the python watcher
y=0
for i in "${!protocols[@]}"
do
	proto=$i
	port=${protocols[$i]}
	touch protocol.txt
	echo "$proto : $port" >> protocol.txt
	touch $proto.log
done

echo ""

echo ---------------------------
echo Setup Complete!
echo ---------------------------

num_proto=$(wc -l protocol.txt | awk '{print $1}')

export num_proto

echo ""
echo ----------------------------
echo Starting packet-watcher.py
echo ----------------------------

python packet-watcher.py
