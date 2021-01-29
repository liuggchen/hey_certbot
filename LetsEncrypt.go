package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/pem"

	"github.com/eggsampler/acme/v3"
)

const (
	CertFileName    = "cert.pem"
	CertKeyFileName = "privateKey.pem"
)

type acmeAccountFile struct {
	PrivateKey string `json:"privateKey"`
	Url        string `json:"url"`
}

type LetsEncrypt struct {
	domains     string
	accountFile string

	emails      []string
	tmpCertFile string
	tmpKeyFile  string
}

func NewLetsEncrypt(domains string, contactsList string, certName string, accountFile string, certDir string, ) (*LetsEncrypt, error) {
	// 临时目录
	certTmpDir := filepath.Join(certDir, certName)
	if _, err := os.Stat(certTmpDir); os.IsNotExist(err) {
		err := os.MkdirAll(certTmpDir, 0755)
		if err != nil {
			return nil, err
		}
	}

	var emails []string
	emails = strings.Split(contactsList, ",")
	for i := 0; i < len(emails); i++ {
		if emails[i] != "" {
			emails[i] = "mailto:" + emails[i]
		}
	}

	return &LetsEncrypt{
		domains:     domains,
		emails:      emails,
		accountFile: accountFile,
		tmpCertFile: filepath.Join(certTmpDir, CertFileName),
		tmpKeyFile:  filepath.Join(certTmpDir, CertKeyFileName),
	}, nil
}

func (l *LetsEncrypt) Run() error {
	// create a new acme client given a provided (or default) directory url
	client, err := acme.NewClient(acme.LetsEncryptProduction)
	if err != nil {
		return errors.New(fmt.Sprintf("Error connecting to acme directory: %v", err.Error()))
	}

	// attempt to load an existing account from file
	account, err := l.loadAccount(client)
	if err != nil {
		log.Printf("Creating new account")
		account, err = l.createAccount(client)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creaing new account: %v", err))
		}
	}
	log.Printf("Account url: %s", account.URL)

	// collect the comma separated domains into acme identifiers
	domainList := strings.Split(l.domains, ",")
	var ids []acme.Identifier
	for _, domain := range domainList {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	// create a new order with the acme service given the provided identifiers
	log.Printf("Creating new order for domains: %s", domainList)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating new order: %v", err))
	}
	// loop through each of the provided authorization urls
	for _, authUrl := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		auth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			return errors.New(fmt.Sprintf("Error fetching authorization url %q: %v", authUrl, err))
		}
		log.Printf("Fetched authorization: %s", auth.Identifier.Value)

		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
		if !ok {
			return errors.New(fmt.Sprintf("Unable to find dns challenge for auth %s", auth.Identifier.Value))
		}
		txt := acme.EncodeDNS01KeyAuthorization(chal.KeyAuthorization)
		awsDns := NewAwsDns()
		err = awsDns.createDnsRecord(txt)
		if err != nil {
			return errors.New(fmt.Sprintf("create dns record error: %v ", err.Error()))
		}
		log.Println("sleep 15 second...")
		// sleep一下
		time.Sleep(15 * time.Second)
		// update the acme server that the challenge file is ready to be queried
		log.Printf("Updating challenge...")
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			return errors.New(fmt.Sprintf("Error updating authorization %s challenge: %v", auth.Identifier.Value, err))
		}
		log.Printf("Challenge updated")

		awsDns.deleteDnxRecord(txt)
	}

	// create a csr for the new certificate
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.New(fmt.Sprintf("Error generating certificate key: %v", err))
	}

	b, err := key2pem(certKey)
	if err != nil {
		return err
	}

	// write the key to the key file as a pem encoded key
	log.Printf("Writing key file: %s", l.tmpKeyFile)
	if err := ioutil.WriteFile(l.tmpKeyFile, b, 0600); err != nil {
		return errors.New(fmt.Sprintf("Error writing key file %q: %v", l.tmpKeyFile, err))
	}

	// create the new csr template
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating certificate request: %v", err))
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing certificate request: %v", err))
	}

	// finalize the order with the acme server given a csr
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		return errors.New(fmt.Sprintf("Error finalizing order: %v", err))
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		return errors.New(fmt.Sprintf("Error fetching order certificates: %v", err))
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", l.tmpCertFile)
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := ioutil.WriteFile(l.tmpCertFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		return errors.New(fmt.Sprintf("Error writing certificate file %q: %v", l.tmpCertFile, err))
	}

	return nil
}

func (l *LetsEncrypt) loadAccount(client acme.Client) (acme.Account, error) {
	log.Printf("Loading account file %s", l.accountFile)
	raw, err := ioutil.ReadFile(l.accountFile)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %v", l.accountFile, err)
	}
	var aaf acmeAccountFile
	if err := json.Unmarshal(raw, &aaf); err != nil {
		return acme.Account{}, fmt.Errorf("error parsing account file %q: %v", l.accountFile, err)
	}
	privateKey, err := pem2key([]byte(aaf.PrivateKey))
	if err != nil {
		return acme.Account{}, err
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: privateKey, URL: aaf.Url}, l.emails...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %v", err)
	}
	return account, nil
}

func (l *LetsEncrypt) createAccount(client acme.Client) (acme.Account, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privateKey, false, true, l.emails...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	bytes, err := key2pem(privateKey)
	if err != nil {
		return acme.Account{}, err
	}
	raw, err := json.Marshal(acmeAccountFile{PrivateKey: string(bytes), Url: account.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := ioutil.WriteFile(l.accountFile, raw, 0600); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

func key2pem(certKey *ecdsa.PrivateKey) ([]byte, error) {
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error encoding key: %v", err))
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	}), nil
}

func pem2key(data []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error decoding key: %v", err))
	}
	return key, nil
}
