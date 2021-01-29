package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type CertConfigItem struct {
	Name       string `json:"name"`
	Domains    string `json:"domains"`
	Emails     string `json:"emails"`
	CreateTime int64  `json:"install_time"`
	ExpireTime int64  `json:"expire_time"`
}

// 读取配置文件
func readConfig() (map[string]CertConfigItem, error) {
	var configStr = "{}"
	if _, err := os.Stat(configFile); !os.IsNotExist(err) {
		configBytes, err := ioutil.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		configStr = string(configBytes)
	}
	var config = make(map[string]CertConfigItem, 0)
	err := json.Unmarshal([]byte(configStr), &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// 更新 配置
func updateConfig(item CertConfigItem) error {
	config, err := readConfig()
	if err != nil {
		return err
	}
	config[item.Name] = item
	jsonBytes, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configFile, jsonBytes, 0666)
	return err
}
