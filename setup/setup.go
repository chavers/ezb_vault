// This file is part of ezBastion.

//     ezBastion is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.

//     ezBastion is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.

//     You should have received a copy of the GNU Affero General Public License
//     along with ezBastion.  If not, see <https://www.gnu.org/licenses/>.

package setup

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"ezb_vault/configuration"
	"ezb_lib/certmanager"
	fqdn "github.com/ShowMax/go-fqdn"
)

var exPath string

func init() {
	ex, _ := os.Executable()
	exPath = filepath.Dir(ex)
}

func CheckConfig(isIntSess bool) (conf configuration.Configuration, err error) {
	confFile := path.Join(exPath, "conf/config.json")
	raw, err := ioutil.ReadFile(confFile)
	if err != nil {
		return conf, err
	}
	json.Unmarshal(raw, &conf)
	return conf, nil
}

func CheckFolder(isIntSess bool) {

	if _, err := os.Stat(path.Join(exPath, "cert")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(exPath, "cert"), 0600)
		if err != nil {
			return
		}
		log.Println("Make cert folder.")
	}
	if _, err := os.Stat(path.Join(exPath, "log")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(exPath, "log"), 0600)
		if err != nil {
			return
		}
		log.Println("Make log folder.")
	}
	if _, err := os.Stat(path.Join(exPath, "conf")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(exPath, "conf"), 0600)
		if err != nil {
			return
		}
		log.Println("Make conf folder.")
	}
	if _, err := os.Stat(path.Join(exPath, "db")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(exPath, "db"), 0600)
		if err != nil {
			return
		}
		log.Println("Make db folder.")
	}
}

func Setup(isIntSess bool) error {

	_fqdn := fqdn.Get()
	quiet := true
	hostname, _ := os.Hostname()
	confFile := path.Join(exPath, "conf/config.json")
	CheckFolder(isIntSess)
	conf, err := CheckConfig(isIntSess)
	if err != nil {
		quiet = true
		conf.Listen = ":5100"
		conf.ServiceFullName = "Easy Bastion Vault"
		conf.ServiceName = "ezb_vault"
		conf.LogLevel = "warning"
		conf.CaCert = "cert/ca.crt"
		conf.PrivateKey = "cert/ezb_vault.key"
		conf.PublicCert = "cert/ezb_vault.crt"
		conf.DB = "db/ezb_vault.db"
		conf.EzbPki = "localhost:6000"
		conf.SAN = []string{_fqdn, hostname}
	}

	if quiet == false {
		fmt.Print("\n\n")
		fmt.Println("***********")
		fmt.Println("*** PKI ***")
		fmt.Println("***********")
		fmt.Println("ezBastion nodes use elliptic curve digital signature algorithm ")
		fmt.Println("(ECDSA) to communicate.")
		fmt.Println("We need ezb_pki address and port, to request certificat pair.")
		fmt.Println("ex: 10.20.1.2:6000 pki.domain.local:6000")

		for {
			p := askForValue("ezb_pki", conf.EzbPki, `^[a-zA-Z0-9-\.]+:[0-9]{4,5}$`)
			c := askForConfirmation(fmt.Sprintf("pki address (%s) ok?", p))
			if c {
				conn, err := net.Dial("tcp", p)
				if err != nil {
					fmt.Printf("## Failed to connect to %s ##\n", p)
				} else {
					conn.Close()
					conf.EzbPki = p
					break
				}
			}
		}

		fmt.Print("\n\n")
		fmt.Println("Certificat Subject Alternative Name.")
		fmt.Printf("\nBy default using: <%s, %s> as SAN. Add more ?\n", _fqdn, hostname)
		for {
			tmp := conf.SAN

			san := askForValue("SAN (comma separated list)", strings.Join(conf.SAN, ","), `(?m)^[[:ascii:]]*,?$`)

			t := strings.Replace(san, " ", "", -1)
			tmp = strings.Split(t, ",")
			c := askForConfirmation(fmt.Sprintf("SAN list %s ok?", tmp))
			if c {
				conf.SAN = tmp
				break
			}
		}
	}

	if os.IsNotExist(fica) || os.IsNotExist(fipriv) || os.IsNotExist(fipub) {
		keyFile := path.Join(exPath, conf.PrivateKey)
		certFile := path.Join(exPath, conf.PublicCert)
		caFile := path.Join(exPath, conf.CaCert)
		request := newCertificateRequest(conf.ServiceName, 730, conf.SAN)
		generate(request, conf.EzbPki, certFile, keyFile, caFile)
	}
	
	if quiet {
		c, _ := json.Marshal(conf)
		ioutil.WriteFile(confFile, c, 0600)
		log.Println(confFile, " saved.")
	}
	return nil
}
