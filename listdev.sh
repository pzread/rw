#!/bin/bash

ls -l /sys/dev/block | awk 'BEGIN{printf "Major:Minor  Dev\n"} /[a-z]$/{n=split($11,a,"/")} '/[a-z]$/'{printf "%-12s %s\n",$9,a[n]}'
