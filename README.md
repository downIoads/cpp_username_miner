# cpp_username_miner
Can't think of a good username? Mine it! Has been tested on Ubuntu 20.04 LTS.

## What does it do? 

Takes a word like "cafe" (must be hex-compatible) and then generates numbers which get added to your word and hashed using SHA256 and KECCAK256. If the result contains the word "cafe" again in both outputs you have found a cool username. You can find even cooler usernames by toggling a bool value to true, then the result must contain your word at least TWICE in BOTH hash outputs. Have fun!

## Features

The only feature I cared about was multithreading, so the program checks how many threads your CPU supports and then evenly splits the input space among those threads.
