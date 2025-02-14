package utils

import (
	"fmt"
	"math"
	"net"
)

func InputAddTask(state *State, input []string) {
	cmd := input[1]
	var args []byte

	// parse args
	for i := 2; i < len(input); i++ {
		if len(args) > 0 {
			args = append(args, ' ')
		}
		args = append(args, input[i]...)
	}

	task := Task{
		Status: state.StatusCode,
		Cmd:    cmd,
		Args:   string(args),
	}

	state.TaskQueue <- &task
	fmt.Printf("Adding task {%s, %s} to queue\n", cmd, string(args))
}
func InputAddAllTask(state *State, input []string) {

}

func InputAddScanTask(state *State, input []string) {
	ip, subnet, _ := net.ParseCIDR(input[1])
	subnetMask, _ := subnet.Mask.Size()
	mask := ip.DefaultMask()
	umask := (uint32(mask[0]) << 24) | (uint32(mask[1]) << 16) | (uint32(mask[2]) << 8) | uint32(mask[3])

	// ip range we're covering
	var network uint32 = PackIP(ip) & umask
	var broadcast uint32 = 1<<(32-uint(subnetMask)) + network

	// set up for number of tasks we need
	nips_per_task := uint32(math.Pow(2, TASK_MASK))
	var nips uint32 = broadcast - network
	var ntasks uint32 = max(nips/nips_per_task, 1)

	// parse args
	var args []byte
	for i := 3; i < len(input); i++ {
		if len(args) > 0 {
			args = append(args, ' ')
		}
		args = append(args, input[i]...)
	}

	// append tasks to state
	state.IPRanges = append(state.IPRanges, input[1])
	for i := uint32(0); i < ntasks; i++ {
		var task Task

		task.Cmd = input[2]
		task.Args = string(args) + fmt.Sprintf(" %s/%d", UnpackIP((i*nips_per_task)+network), TASK_MASK)

		// add task to queue
		state.TaskQueue <- &task
	}

	fmt.Printf("Adding Scan Task {%s, %s} to queue\n", input[2], string(args)+" "+input[1])
}
