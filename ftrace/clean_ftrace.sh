#!/bin/bash

pushd /sys/kernel/debug/tracing
echo 0 > tracing_on
#cat trace > ~/a.txt

echo > set_graph_function
echo 0 > options/func_stack_trace
echo > set_ftrace_filter
cat set_ftrace_filter
cat available_tracers
echo nop > current_tracer
popd