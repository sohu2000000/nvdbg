#!/bin/bash



# mount -t debugfs none /sys/kernel/debug

pushd /sys/kernel/debug/tracing

#function=mlx5_eq_comp_int
#function=mlx5_cq_tasklet_cb
#function=mlx5_ib_cq_comp
# function=mlx5e_napi_poll
# function=mlx5e_poll_rx_cq
function=mlx5e_poll_rx_cq

rm -rf ~/a.txt
echo > trace
echo function_graph > current_tracer
#echo mlx5_eq_comp_int > set_graph_function
echo $function > set_graph_function
echo funcgraph-abstime > trace_options
echo funcgraph-duration > trace_options
echo 1 > tracing_on

popd

cat trace > ~/a.txt
cat ~/a.txt


