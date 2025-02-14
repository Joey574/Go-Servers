package utils

import "sync"

type Task struct {
	Status uint8
	Cmd    string
	Args   string
}

type Result struct {
	CmdResult string
	CmdTime   float32
}

type State struct {
	sync.Mutex
	StatusCode   uint8
	TaskQueue    chan *Task
	ResultQueue  chan *Result
	PasswordHash []byte
	IPRanges     []string
}
