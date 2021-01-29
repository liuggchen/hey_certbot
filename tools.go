package main

import (
	"log"
	"os/exec"
	"strings"
)

// 执行命令
func execCmd(str string) error {
	split := strings.Split(str, " ")
	cmd := exec.Command(split[0], split[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	log.Println("cmd output: ", string(output))
	return nil
}
