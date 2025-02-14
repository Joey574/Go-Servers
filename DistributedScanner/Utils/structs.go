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

type Worker struct {
	Id    uint32
	Tasks []Task
}

type State struct {
	sync.Mutex
	StatusCode   uint8
	WorkerID     uint32
	Workers      []Worker
	TaskQueue    chan *Task
	ResultQueue  chan *Result
	PasswordHash []byte
	IPRanges     []string
}
