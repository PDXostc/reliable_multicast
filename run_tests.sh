#!/bin/sh

gnome-terminal --geometry 132x32 --title "PUBLISH"  -- sh run_tests_pub.sh
gnome-terminal --geometry 132x32 --title "SUBSCRIBE"  -- sh run_tests_sub.sh
