//go:generate goversioninfo

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/cloudfoundry-incubator/candiedyaml"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/oauth2"

	"models"
)

const (
	installBatTemplate = `msiexec /passive /norestart /i %~dp0\DiegoWindows.msi ^{{ if .BbsRequireSsl }}
  BBS_CA_FILE=%~dp0\bbs_ca.crt ^
  BBS_CLIENT_CERT_FILE=%~dp0\bbs_client.crt ^
  BBS_CLIENT_KEY_FILE=%~dp0\bbs_client.key ^{{ end }}
  CONSUL_DOMAIN={{.ConsulDomain}} ^
  CONSUL_IPS={{.ConsulIPs}} ^
  CF_ETCD_CLUSTER=http://{{.EtcdCluster}}:4001 ^
  STACK=windows2012R2 ^
  REDUNDANCY_ZONE={{.Zone}} ^
  LOGGREGATOR_SHARED_SECRET={{.SharedSecret}} ^
  MACHINE_IP={{.MachineIp}}{{ if .SyslogHostIP }} ^
  SYSLOG_HOST_IP={{.SyslogHostIP}} ^
  SYSLOG_PORT={{.SyslogPort}}{{ end }}{{if .ConsulRequireSSL }} ^
  CONSUL_ENCRYPT_FILE=%~dp0\consul_encrypt.key ^
  CONSUL_CA_FILE=%~dp0\consul_ca.crt ^
  CONSUL_AGENT_CERT_FILE=%~dp0\consul_agent.crt ^
  CONSUL_AGENT_KEY_FILE=%~dp0\consul_agent.key{{end}}{{if .MetronPreferTLS }} ^
  METRON_CA_FILE=%~dp0\metron_ca.crt ^
  METRON_AGENT_CERT_FILE=%~dp0\metron_agent.crt ^
  METRON_AGENT_KEY_FILE=%~dp0\metron_agent.key{{end}}

msiexec /passive /norestart /i %~dp0\GardenWindows.msi ^
  MACHINE_IP={{.MachineIp}}{{ if .SyslogHostIP }} ^
  SYSLOG_HOST_IP={{.SyslogHostIP}} ^
  SYSLOG_PORT={{.SyslogPort}}{{ end }}`
)

func main() {
	boshServerUrl := flag.String("boshUrl", "", "Bosh URL (https://admin:admin@bosh.example:25555)")
	outputDir := flag.String("outputDir", "", "Output directory (/tmp/scripts)")
	machineIp := flag.String("machineIp", "", "(optional) IP address of this cell")

	flag.Parse()
	if *boshServerUrl == "" || *outputDir == "" {
		fmt.Fprintf(os.Stderr, "Usage of generate:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	u, _ := url.Parse(*boshServerUrl)

	_, err := os.Stat(*outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(*outputDir, 0755)
		}
	}

	bosh := NewBosh(*u)
	bosh.Authorize()

	response := bosh.MakeRequest("/deployments")
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(response.Body)
		if err != nil {
			fmt.Printf("Could not read response from BOSH director.")
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Unexpected BOSH director response: %v, %v", response.StatusCode, buf.String())
		os.Exit(1)
	}

	deployments := []models.IndexDeployment{}
	json.NewDecoder(response.Body).Decode(&deployments)
	idx := GetDiegoDeployment(deployments)
	if idx == -1 {
		fmt.Fprintf(os.Stderr, "BOSH Director does not have exactly one deployment containing a cf and diego release.")
		os.Exit(1)
	}

	response = bosh.MakeRequest("/deployments/" + deployments[idx].Name)
	defer response.Body.Close()

	deployment := models.ShowDeployment{}
	json.NewDecoder(response.Body).Decode(&deployment)
	buf := bytes.NewBufferString(deployment.Manifest)
	var manifest models.Manifest

	decoder := candiedyaml.NewDecoder(buf)
	err = decoder.Decode(&manifest)
	if err != nil {
		FailOnError(err)
	}

	args := models.InstallerArguments{}

	fillEtcdCluster(&args, manifest)
	fillSharedSecret(&args, manifest)
	fillMetronAgent(&args, manifest, *outputDir)
	fillSyslog(&args, manifest)
	fillConsul(&args, manifest, *outputDir)

	fillMachineIp(&args, manifest, *machineIp)

	fillBBS(&args, manifest, *outputDir)
	generateInstallScript(*outputDir, args)
}

func fillMachineIp(args *models.InstallerArguments, manifest models.Manifest, machineIp string) {
	if machineIp == "" {
		consulIp := strings.Split(args.ConsulIPs, ",")[0]
		conn, err := net.Dial("udp", consulIp+":65530")
		FailOnError(err)
		machineIp = strings.Split(conn.LocalAddr().String(), ":")[0]
	}
	args.MachineIp = machineIp
}

func fillSharedSecret(args *models.InstallerArguments, manifest models.Manifest) {
	repJob := firstRepJob(manifest)
	properties := repJob.Properties
	if properties.MetronEndpoint == nil {
		properties = manifest.Properties
	}
	args.SharedSecret = properties.MetronEndpoint.SharedSecret
}

func fillMetronAgent(args *models.InstallerArguments, manifest models.Manifest, outputDir string) {
	repJob := firstRepJob(manifest)
	properties := repJob.Properties

	if properties.MetronAgent == nil || properties.MetronAgent.PreferredProtocol == nil {
		properties = manifest.Properties
	}

	if properties != nil && properties.MetronAgent != nil && properties.MetronAgent.PreferredProtocol != nil {
		if *properties.MetronAgent.PreferredProtocol == "tls" {
			args.MetronPreferTLS = true
			extractMetronKeyAndCert(properties, outputDir)
		}
	}
}

func fillSyslog(args *models.InstallerArguments, manifest models.Manifest) {
	repJob := firstRepJob(manifest)
	properties := repJob.Properties
	// TODO: this is broken on ops manager:
	//   1. there are no global properties section
	//   2. none of the diego jobs (including rep) has syslog_daemon_config
	if properties.Syslog == nil && manifest.Properties != nil {
		properties = manifest.Properties
	}

	if properties.Syslog == nil {
		return
	}

	args.SyslogHostIP = properties.Syslog.Address
	args.SyslogPort = properties.Syslog.Port
}

func fillBBS(args *models.InstallerArguments, manifest models.Manifest, outputDir string) {
	repJob := firstRepJob(manifest)
	properties := repJob.Properties
	if properties.Diego.Rep.BBS == nil {
		properties = manifest.Properties
	}

	requireSSL := properties.Diego.Rep.BBS.RequireSSL
	// missing requireSSL implies true
	if requireSSL == nil || *requireSSL {
		args.BbsRequireSsl = true
		extractBbsKeyAndCert(properties, outputDir)
	}
}

func stringToEncryptKey(str string) string {
	decodedStr, err := base64.StdEncoding.DecodeString(str)
	if err == nil && len(decodedStr) == 16 {
		return str
	}

	key := pbkdf2.Key([]byte(str), nil, 20000, 16, sha1.New)
	return base64.StdEncoding.EncodeToString(key)
}

func fillConsul(args *models.InstallerArguments, manifest models.Manifest, outputDir string) {
	repJob := firstRepJob(manifest)
	properties := repJob.Properties
	if properties.Consul == nil {
		properties = manifest.Properties
	}

	consuls := properties.Consul.Agent.Servers.Lan

	if len(consuls) == 0 {
		fmt.Fprintf(os.Stderr, "Could not find any Consul VMs in your BOSH deployment")
		os.Exit(1)
	}

	args.ConsulIPs = strings.Join(consuls, ",")

	// missing requireSSL implies true
	requireSSL := properties.Consul.RequireSSL
	if requireSSL == nil || *requireSSL != "false" {
		args.ConsulRequireSSL = true
		extractConsulKeyAndCert(properties, outputDir)
	}

	if properties.Consul.Agent.Domain != "" {
		args.ConsulDomain = properties.Consul.Agent.Domain
	} else {
		args.ConsulDomain = "cf.internal"
	}
}

func fillEtcdCluster(args *models.InstallerArguments, manifest models.Manifest) {
	repJob := firstRepJob(manifest)
	properties := repJob.Properties
	if properties.Loggregator == nil {
		properties = manifest.Properties
	}

	args.EtcdCluster = properties.Loggregator.Etcd.Machines[0]
}

func firstRepJob(manifest models.Manifest) models.Job {
	jobs := manifest.Jobs

	for _, job := range jobs {
		if job.Properties.Diego != nil && job.Properties.Diego.Rep != nil {
			return job
		}

	}
	panic("no rep jobs found")
}

func extractConsulKeyAndCert(properties *models.Properties, outputDir string) {
	encryptKey := stringToEncryptKey(properties.Consul.EncryptKeys[0])

	for key, filename := range map[string]string{
		properties.Consul.AgentCert: "consul_agent.crt",
		properties.Consul.AgentKey:  "consul_agent.key",
		properties.Consul.CACert:    "consul_ca.crt",
		encryptKey:                  "consul_encrypt.key",
	} {
		err := ioutil.WriteFile(path.Join(outputDir, filename), []byte(key), 0644)
		if err != nil {
			FailOnError(err)
		}
	}
}

func extractBbsKeyAndCert(properties *models.Properties, outputDir string) {
	for key, filename := range map[string]string{
		properties.Diego.Rep.BBS.ClientCert: "bbs_client.crt",
		properties.Diego.Rep.BBS.ClientKey:  "bbs_client.key",
		properties.Diego.Rep.BBS.CACert:     "bbs_ca.crt",
	} {
		err := ioutil.WriteFile(path.Join(outputDir, filename), []byte(key), 0644)
		if err != nil {
			FailOnError(err)
		}
	}
}

func extractMetronKeyAndCert(properties *models.Properties, outputDir string) {
	for key, filename := range map[string]string{
		properties.MetronAgent.TlsClient.Cert: "metron_agent.crt",
		properties.MetronAgent.TlsClient.Key:  "metron_agent.key",
		properties.Loggregator.Tls.CA:         "metron_ca.crt",
	} {
		err := ioutil.WriteFile(path.Join(outputDir, filename), []byte(key), 0644)
		if err != nil {
			FailOnError(err)
		}
	}
}

func FailOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func generateInstallScript(outputDir string, args models.InstallerArguments) {
	content := strings.Replace(installBatTemplate, "\n", "\r\n", -1)
	temp := template.Must(template.New("").Parse(content))
	args.Zone = "windows"
	filename := "install.bat"
	file, err := os.OpenFile(path.Join(outputDir, filename), os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	err = temp.Execute(file, args)
	if err != nil {
		log.Fatal(err)
	}
}

func GetDiegoDeployment(deployments []models.IndexDeployment) int {
	deploymentIndex := -1

	for i, deployment := range deployments {
		releases := map[string]bool{}
		for _, rel := range deployment.Releases {
			releases[rel.Name] = true
		}

		if releases["cf"] && releases["diego"] && releases["garden-linux"] {
			if deploymentIndex != -1 {
				return -1
			}

			deploymentIndex = i
		}

	}

	return deploymentIndex
}

func NewBosh(endpoint url.URL) *Bosh {
	return &Bosh{
		endpoint: endpoint,
	}
}

type Bosh struct {
	endpoint  url.URL
	authToken string
	authType  string
}

type BoshInfo struct {
	UserAuthentication struct {
		Type    string `json:"type"`
		Options struct {
			Url string `json:"url"`
		} `json:"options"`
	} `json:"user_authentication"`
}

func (b *Bosh) Authorize() {
	if b.endpoint.User == nil {
		log.Fatalln("Director username and password are required.")
	}
	password, _ := b.endpoint.User.Password()
	if password == "" {
		log.Fatalln("Director password is required.")
	}
	resp := b.MakeRequest("/info")
	defer resp.Body.Close()
	var info BoshInfo
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &info)
	b.authType = info.UserAuthentication.Type
	if b.authType == "uaa" {
		tokenEndpoint, err := url.Parse("oauth/token")
		if err != nil {
			log.Fatal(err)
		}
		authEndpoint, err := url.Parse("oauth/authorize")
		if err != nil {
			log.Fatal(err)
		}
		uaaUrl, err := url.Parse(info.UserAuthentication.Options.Url)
		if err != nil {
			log.Fatal(err)
		}
		authURL := uaaUrl.ResolveReference(authEndpoint).String()
		tokenURL := uaaUrl.ResolveReference(tokenEndpoint).String()
		conf := &oauth2.Config{
			ClientID:     "bosh_cli",
			ClientSecret: "",
			Scopes:       []string{"bosh.read"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		}

		token, err := conf.PasswordCredentialsToken(nil, b.endpoint.User.Username(), password)
		if err != nil {
			log.Fatal(err)
		}

		b.authToken = token.AccessToken
		b.endpoint.User = nil
	}
}

func (b *Bosh) MakeRequest(path string) *http.Response {
	request, err := http.NewRequest("GET", b.endpoint.String()+path, nil)
	if err != nil {
		log.Fatal(err)
	}
	if b.authType == "uaa" {
		request.Header.Set("Authorization", fmt.Sprintf("bearer %s", b.authToken))
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	http.DefaultClient.Timeout = 10 * time.Second
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalln("Unable to establish connection to BOSH Director.", err)
	}
	return response
}
