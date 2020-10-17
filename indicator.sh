#!/bin/bash

loading_indicator () {
    delay=0.10
    while true;
    do
	    for num in $( seq 10240 10360 )
	    do
			hex_rep=$( echo -n "${num}" + 0x0000 )
			echo -en "\u$( printf "%x" "$((hex_rep))" )"
			hex_rep=$( echo -n "${num}" + 0x0001 )
			echo -en "\u$( printf "%x" "$((hex_rep))" )"
			hex_rep=$( echo -n "${num}" + 0x0002 )
			echo -en "\u$( printf "%x" "$((hex_rep))" )"
			hex_rep=$( echo -n "${num}" + 0x0003 )
			echo -en "\u$( printf "%x" "$((hex_rep))" )"
			hex_rep=$( echo -n "${num}" + 0x0004 )
			echo -en "\u$( printf "%x" "$((hex_rep))" )"
			hex_rep=$( echo -n "${num}" + 0x0005 )
			echo -en "\u$( printf "%x" "$((hex_rep))" )"
			sleep $delay
			echo -ne '\b\b\b\b\b\b\b\b\b\b'
	    done
    done
}


loading_indicator
