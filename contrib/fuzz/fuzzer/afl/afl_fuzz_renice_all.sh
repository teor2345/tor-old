#!/bin/bash
ps auxwww | grep afl-fuzz | cut -c 15-22 | xargs sudo renice -20
