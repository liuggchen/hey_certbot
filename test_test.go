package main

import (
	"log"
	"testing"
)

func TestName(t *testing.T) {
	err := updateConfig(CertConfigItem{
		Name:       "",
		Domains:    "",
		Emails:     "",
		CreateTime: 0,
		ExpireTime: 0,
	})
	log.Println(err)
}
