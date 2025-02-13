#!/bin/bash

pushd /sys/kernel/debug/tracing
#function=mlx5_eq_comp_int
# function=mlx5_cq_tasklet_cb
# function=mlx5e_poll_rx_cq
# function=mlx5e_poll_rx_cq
# function=mlx5e_handle_rx_cqe
# function=mlx5e_skb_from_cqe_linear
function=napi_gro_receive

rm -rf ~/a.txt
echo > trace
echo function > current_tracer
echo $function > set_ftrace_filter
echo 1 > options/func_stack_trace
cat /dev/null > trace
echo 1 > tracing_on
popd

cat trace > ~/a.txt
cat ~/a.txt
