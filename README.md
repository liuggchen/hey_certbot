## 生成`letsencrypt`证书
* 设置 `_acme-challenge.example.com` CNAME解析到 `_acme-challenge.youcname.com`

 
* 如下命令生成证书
```shell script
hey_certbot -a create -d *.example.com,example.com -e abc@qq.com -n example.com -r "nginx -s reload"
```

    生成的证书会在 `/etc/letsencrypt/live` 目录下

* 配置 nginx 
```nginx
server {
    listen 443 ssl;
    server_name abc.example.com

    ssl_certificate /etc/letsencrypt/live/example.com/cert.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privateKey.pem;
    
    root /root;
}
```
    
* 添加定时脚本
```shell script
  6 4 */2 * * /usr/bin/hey_certbot -a update -r "nginx -s reload"
```

## 其它命令
* 列出证书
```shell script
hey_certbot -a list
```

* 根据名称更新指定证书
```shell script
hey_certbot -a update -n example.com -r "nginx -s reload"
```