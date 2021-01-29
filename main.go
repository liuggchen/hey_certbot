package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultContactsList = "2213054327@qq.com"

	accountFile   = "/etc/letsencrypt/account.json"
	configFile    = "/etc/letsencrypt/config.json"
	tmpCertDir    = "/etc/letsencrypt/tmp"
	deployCertDir = "/etc/letsencrypt/live"
)

var (
	domains      string
	contactsList string
	certName     string
	action       string
	run          string
)

func main() {
	var logPath = "/var/log/hey_certbot.log"
	logF, _ := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logF != nil {
		defer logF.Close()
		log.SetOutput(io.MultiWriter(logF, os.Stdout))
	}
	flag.StringVar(&domains, "d", "",
		"域名，使用英文逗号隔开 *.abc.com,abc.com")
	flag.StringVar(&contactsList, "e", defaultContactsList,
		"联系邮箱，使用英文逗号隔开")
	flag.StringVar(&certName, "n", "",
		"证书名称")
	flag.StringVar(&run, "r", "",
		"在 create 或 update 后，证书发生修改执行命令，一般重启服务器")
	flag.StringVar(&action, "a", "",
		`list|create|update
create 接收参数: d,e,n,r
update 接收参数: n,r 如果不传递名称将全部更新
`)
	flag.Parse()

	const (
		List   = "list"   // 查看当前的证书
		Create = "create" // 创建一个新的证书
		Update = "update" // 更新证书，安装并执行cmd
	)

	// 判断是哪个action
	switch action {
	case List:
		doList()
	case Create:
		doCreate(domains, contactsList, certName)
		runCmd(run)
	case Update:
		doUpdate(certName)
		runCmd(run)
	default:
		fmt.Printf(` -h 查看使用帮助
1. 设置 _acme-challenge.example.com CNAME 解析到 _acme-challenge.yourcname.com
2. hey_certbot -a create -d *.example.com,example.com -n example.com
3. 配置nginx
4. 添加定时脚本 6 4 */2 * * /usr/bin/hey_certbot -a update -r "nginx -s reload"

`)
	}

}

// 列出当前的证书
func doList() {
	config, err := readConfig()
	if err != nil {
		log.Fatal("read config error: ", err.Error())
	}
	fmt.Printf("%-20s| %-12s| Domains\n", "Name", "Expire date")
	var plnStr string
	for certName, item := range config {
		plnStr += fmt.Sprintf("%-20s| %-12s| %v\n", certName, time.Unix(item.ExpireTime, 0).Format("2006-01-02"), item.Domains)
	}
	fmt.Println(plnStr)
}

func runCmd(cmd string) {
	if cmd != "" {
		log.Printf("run cmd `%v` ...", cmd)
		err := execCmd(cmd)
		if err != nil {
			log.Println("run cmd error: ", err.Error())
		}
	}
}

// 将临时目录的证书移动到部署目录
func doInstall(certName string) error {
	tmpCertFile := filepath.Join(tmpCertDir, certName, CertFileName)
	tmpKeyFile := filepath.Join(tmpCertDir, certName, CertKeyFileName)

	if _, err := os.Stat(tmpCertFile); os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("certfile not exits: %v", tmpCertFile))
	}
	if _, err := os.Stat(tmpKeyFile); os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("certfile not exits: %v", tmpKeyFile))
	}

	distDir := filepath.Join(deployCertDir, certName)
	if _, err := os.Stat(distDir); err != nil {
		err := os.MkdirAll(distDir, 0755)
		if err != nil {
			return errors.New(fmt.Sprintf("mkdir %v fail", distDir))
		}
	}

	tmpCertBytes, err := ioutil.ReadFile(tmpCertFile)
	if err != nil {
		return errors.New(fmt.Sprintf("read cert file fail: %v", err.Error()))
	}

	tmpCertKeyBytes, err := ioutil.ReadFile(tmpKeyFile)
	if err != nil {
		return errors.New(fmt.Sprintf("read key file fail: %v", err.Error()))
	}

	err = ioutil.WriteFile(filepath.Join(distDir, CertFileName), tmpCertBytes, 0666)
	if err != nil {
		return errors.New(fmt.Sprintf("write cert file fail: %v", err.Error()))
	}

	err = ioutil.WriteFile(filepath.Join(distDir, CertKeyFileName), tmpCertKeyBytes, 0666)
	if err != nil {
		return errors.New(fmt.Sprintf("write key file fail: %v", err.Error()))
	}
	return nil
}

// 创建证书到临时目录
func doCreate(domains string, emails string, certName string) {
	// check domains are provided
	if domains == "" {
		log.Fatal("No domains provided")
	}
	if certName == "" {
		log.Fatalln("No certname provided")
	}
	encryptClient, err := NewLetsEncrypt(domains, emails, certName, accountFile, tmpCertDir)
	if err != nil {
		log.Fatalln("New error: ", err.Error())
	}
	err = encryptClient.Run()
	if err != nil {
		log.Fatalln("create error: ", err.Error())
	}

	// 安装到部署目录
	err = doInstall(certName)
	if err != nil {
		log.Fatalf("install to deploy fail: %v", err.Error())
	}

	nowTs := time.Now().Unix()

	// 更新到配置文件
	err = updateConfig(CertConfigItem{
		Name:       certName,
		Domains:    domains,
		Emails:     emails,
		CreateTime: nowTs,
		ExpireTime: nowTs + 90*86400,
	})
	if err != nil {
		log.Fatalln("update config error", err.Error())
	}
	log.Println("copy to deploy dir success.")
}

// 更新证书
func doUpdate(certName string) {
	configs, err := readConfig()
	if err != nil {
		log.Fatalf("read config error ")
	}
	if certName != "" {
		if _, ok := configs[certName]; !ok {
			log.Fatalf("cert %v have not install", certName)
		}
	}
	var updateNum = 0

	nowTs := time.Now().Unix()
	for name, configItem := range configs {
		if certName == "" || certName == name {
			if configItem.ExpireTime-nowTs > 30*86400 {
				log.Printf("证书 %v 有效期大于30天", name)
				continue
			}
			doCreate(configItem.Domains, configItem.Emails, configItem.Name)
			updateNum++
		}
	}
	log.Printf("一共更新了%v个证书. ", updateNum)
	if updateNum == 0 {
		log.Fatalf("没有更改，不执行CMD")
	}
}
