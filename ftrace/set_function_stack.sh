#!/bin/bash

pushd /sys/kernel/debug/tracing
#function=mlx5_eq_comp_int
# function=mlx5_cq_tasklet_cb
# function=mlx5e_poll_rx_cq
# function=mlx5e_poll_rx_cq
# function=mlx5e_handle_rx_cqe
# function=mlx5e_skb_from_cqe_linear
# function=napi_gro_receive
# function=mlx5_esw_qos_vport_enable
# function=mlx5_esw_qos_vport_disable
# function=mlx5_esw_qos_vport_disable
# function=devlink_nl_port_get_dumpit
# function=devlink_nl_cmd_port_get_doit
function=esw_qos_vport_disable
# function=devlink_rate_nodes_destroy

rm -rf ~/a.txt
echo > trace
echo function > current_tracer
echo $function > set_ftrace_filter
echo 1 > options/func_stack_trace
cat /dev/null > trace
echo 1 > tracing_on
popd

cat /sys/kernel/tracing/trace_pipe | tee ~/a.txt