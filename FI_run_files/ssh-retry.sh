#!/usr/bin/env bash

# Code taken from https://gist.github.com/9point6/ace9c7db75dc694d434d 
# Check we've got command line arguments
if [ -z "$*" ] ; then
    echo "Need to specify ssh options"
    exit 1
fi

# Start trying and retrying
((count = 1000))
while [[ $count -ne 0 ]] ; do
    ssh $*
    rc=$? #Return the response of the last command 0 -> true 1 -> false
    if [[ $rc -eq 0 ]] ; then
        ((count = 1)) # if connected
    fi
    ((count = count - 1))
    sleep 1
done

# Print a message if we failed
if [[ $rc -ne 0 ]] ; then  #true if not equal
    echo "Could not connect to $* after 100 attempts - stopping."
fi
