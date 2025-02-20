#!/bin/bash



# mount -t debugfs none /sys/kernel/debug

pushd /sys/kernel/debug/tracing

#function=mlx5_eq_comp_int
#function=mlx5_cq_tasklet_cb
#function=mlx5_ib_cq_comp
# function=mlx5e_napi_poll
# function=mlx5e_poll_rx_cq
# function=esw_qos_vport_update_parent
# function=mlx5_esw_qos_vport_enable
# function=mlx5_esw_qos_vport_disable
# function=mlx5_esw_qos_pre_cleanup
# function=devlink_nl_port_get_dumpit
function=mlx5e_probe

rm -rf ~/a.txt
echo > trace
echo function_graph > current_tracer
#echo mlx5_eq_comp_int > set_graph_function
echo > /sys/kernel/tracing/set_ftrace_filter
echo > /sys/kernel/tracing/set_graph_function
echo $function > /sys/kernel/tracing/set_graph_function
echo funcgraph-abstime > trace_options
echo funcgraph-duration > trace_options
echo 1 > tracing_on

popd

# cat trace > ~/a.txt
# cat ~/a.txt

cat /sys/kernel/tracing/trace_pipe | tee ~/a.txt

# 通过添加 trace_print 增加调试信息
# echo 1 > /sys/kernel/debug/tracing/events/enable
# 例如
# 	trace_printk("godfeng esw_qos_vport_update_parent called\n");



