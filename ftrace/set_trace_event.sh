#!/bin/bash

pushd /sys/kernel/debug/tracing
trace_event=mlx5_esw_vport_qos_destroy

rm -rf ~/a.txt
echo > trace
cat /sys/kernel/debug/tracing/available_events | grep $trace_event
cat /sys/kernel/debug/tracing/events/mlx5/$trace_event/enable
echo 1 > /sys/kernel/debug/tracing/events/mlx5/$trace_event/enable
cat /dev/null > trace
echo 1 > tracing_on
cat /sys/kernel/debug/tracing/events/mlx5/$trace_event/enable
popd

cat /sys/kernel/tracing/trace_pipe | tee ~/a.txt