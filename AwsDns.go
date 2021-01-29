package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"log"
)

type AwsDns struct {
	domain string
	zoneId string
	client *route53.Route53
}

// 替换成自己的
// 申请教程 https://github.com/acmesh-official/acme.sh/wiki/dnsapi
const (
	accessId        = "AKIA3HAH123232323QPSWBOBT"
	secretKey       = "fWSDri22nSwpELhaB34343444/BROb9eP"
	heychargeDomain = "yourcname.com."
)

func NewAwsDns() *AwsDns {
	newSession, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(accessId, secretKey, ""),
	})
	if err != nil {
		log.Fatalln("newSession fail: ", err.Error())
	}
	dns := &AwsDns{domain: heychargeDomain, client: route53.New(newSession)}
	return dns.getHostZoneIdByName()
}

// 创建或修改txt记录
func (a *AwsDns) createDnsRecord(txt string) error {
	return a.editRecord(route53.ChangeActionUpsert, txt)
}

// 删除txt记录
func (a *AwsDns) deleteDnxRecord(txt string) {
	_ = a.editRecord(route53.ChangeActionDelete, txt)
}

func (a *AwsDns) editRecord(tye string, txt string) error {
	recordSet := &route53.ResourceRecordSet{
		Name: aws.String("_acme-challenge." + a.domain),
		Type: aws.String("TXT"),
		TTL:  aws.Int64(10),
		ResourceRecords: []*route53.ResourceRecord{
			{Value: aws.String(`"` + txt + `"`)},
		},
	}
	reqParam := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{Action: aws.String(tye), ResourceRecordSet: recordSet},
			},
			Comment: aws.String("for letsencrypt"),
		},
		HostedZoneId: aws.String(a.zoneId),
	}
	_, err := a.client.ChangeResourceRecordSets(reqParam)
	if err != nil {
		log.Println("change record error: ", err.Error())
		return err
	}
	return nil
}

// 获取域名的托管区域ID
func (a *AwsDns) getHostZoneIdByName() *AwsDns {
	rest, err := a.client.ListHostedZonesByName(&route53.ListHostedZonesByNameInput{
		DNSName: aws.String(a.domain),
	})
	if err != nil {
		log.Fatalln("list host fail: ", err.Error())
	}
	for _, zone := range rest.HostedZones {
		if !*zone.Config.PrivateZone && *zone.Name == a.domain {
			a.zoneId = *zone.Id
			break
		}
	}
	return a
}
