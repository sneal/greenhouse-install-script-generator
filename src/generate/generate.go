package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v2"

	"models"
)

const (
	installBatTemplate = `msiexec /passive /norestart /i %~dp0\DiegoWindows.msi ^{{ if .BbsRequireSsl }}
  BBS_CA_FILE=%~dp0\bbs_ca.crt ^
  BBS_CLIENT_CERT_FILE=%~dp0\bbs_client.crt ^
  BBS_CLIENT_KEY_FILE=%~dp0\bbs_client.key ^{{ end }}
  CONSUL_IPS={{.ConsulIPs}} ^
  CF_ETCD_CLUSTER=http://{{.EtcdCluster}}:4001 ^
  STACK=windows2012R2 ^
  REDUNDANCY_ZONE={{.Zone}} ^
  LOGGREGATOR_SHARED_SECRET={{.SharedSecret}} ^{{ if .SyslogHostIP }}
  SYSLOG_HOST_IP={{.SyslogHostIP}} ^
  SYSLOG_PORT={{.SyslogPort}} {{ end }}{{if .ConsulRequireSSL }}^
  CONSUL_ENCRYPT_FILE=%~dp0\consul_encrypt.key ^
  CONSUL_CA_FILE=%~dp0\consul_ca.crt ^
  CONSUL_AGENT_CERT_FILE=%~dp0\consul_agent.crt ^
  CONSUL_AGENT_KEY_FILE=%~dp0\consul_agent.key{{end}}

msiexec /passive /norestart /i %~dp0\GardenWindows.msi ^
  ADMIN_USERNAME={{.Username}} ^
  ADMIN_PASSWORD={{.Password}}{{ if .SyslogHostIP }}^
  SYSLOG_HOST_IP={{.SyslogHostIP}} ^
  SYSLOG_PORT={{.SyslogPort}}{{ end }}`
)

func main() {
	boshServerUrl := flag.String("boshUrl", "", "Bosh URL (https://admin:admin@bosh.example:25555)")
	outputDir := flag.String("outputDir", "", "Output directory (/tmp/scripts)")
	windowsUsername := flag.String("windowsUsername", "", "Windows username")
	windowsPassword := flag.String("windowsPassword", "", "Windows password")

	flag.Parse()
	if *boshServerUrl == "" || *outputDir == "" {
		fmt.Fprintf(os.Stderr, "Usage of generate:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	_, err := os.Stat(*outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(*outputDir, 0755)
		}
	}

	*windowsUsername = EscapeSpecialCharacters(*windowsUsername)
	*windowsPassword = EscapeSpecialCharacters(*windowsPassword)

	response := NewBoshRequest(*boshServerUrl + "/deployments")
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

	response = NewBoshRequest(*boshServerUrl + "/deployments/" + deployments[idx].Name)
	defer response.Body.Close()

	deployment := models.ShowDeployment{}
	json.NewDecoder(response.Body).Decode(&deployment)
	buf := bytes.NewBufferString(deployment.Manifest)
	var manifest models.Manifest
	err = yaml.Unmarshal(buf.Bytes(), &manifest)
	if err != nil {
		FailOnError(err)
	}

	etcdCluster := manifest.Properties.Etcd.Machines[0]

	consulRequireSSL := false
	if consulRequiresSSL(manifest) {
		consulRequireSSL = true
		extractConsulKeyAndCert(manifest, *outputDir)
	}

	consuls := manifest.Properties.Consul.Agent.Servers.Lan

	if len(etcdCluster) == 0 {
		// jobs := repJobs(manifest)
		// if len(jobs) > 0 {
		// 	firstJob := jobs[0]
		// 	etcdCluster, err = GetIn(firstJob, "properties", "etcd", "machines", 0)
		// 	FailOnError(err)
		// }
	}
	if len(consuls) == 0 {
		// jobs := repJobs(manifest)
		// if len(jobs) > 0 {
		// 	firstJob := jobs[0]
		// 	consuls, err = GetIn(firstJob, "properties", "consul", "agent", "servers", "lan")
		// 	FailOnError(err)
		// 	if consulRequiresSSL(firstJob) {
		// 		consulRequireSSL = true
		// 		extractConsulKeyAndCert(firstJob, *outputDir)
		// 	}
		// }
	}

	joinedConsulIPs := strings.Join(consuls, ",")

	result, err := GetIn(manifest, "properties", "loggregator_endpoint", "shared_secret")
	FailOnError(err)
	sharedSecret := result.(string)
	result, err = GetIn(manifest, "properties", "syslog_daemon_config", "address")
	FailOnError(err)
	syslogHostIP, _ := result.(string)
	result, err = GetIn(manifest, "properties", "syslog_daemon_config", "port")
	FailOnError(err)
	syslogPort := fmt.Sprintf("%v", result)

	var bbsRequireSsl bool
	result, _ = GetIn(manifest, "properties", "diego", "rep", "bbs", "require_ssl")
	if result == nil {
		bbsRequireSsl = false
	} else {
		bbsRequireSsl = result.(bool)
	}

	if bbsRequireSsl {
		extractBbsKeyAndCert(manifest, *outputDir)
	}

	args := models.InstallerArguments{
		ConsulRequireSSL: consulRequireSSL,
		ConsulIPs:        joinedConsulIPs,
		EtcdCluster:      etcdCluster,
		SharedSecret:     sharedSecret,
		Username:         *windowsUsername,
		Password:         *windowsPassword,
		SyslogHostIP:     syslogHostIP,
		SyslogPort:       syslogPort,
		BbsRequireSsl:    bbsRequireSsl,
	}
	generateInstallScript(*outputDir, args)
}

func repJobs(manifest interface{}) []interface{} {
	result, err := GetIn(manifest, "jobs")
	FailOnError(err)
	jobs := result.([]interface{})
	var repJobs []interface{}

	for _, job := range jobs {
		jopHashRep, err := GetIn(job, "properties", "diego", "rep")
		FailOnError(err)
		if jopHashRep != nil {
			repJobs = append(repJobs, job)
		}
	}
	return repJobs
}

func consulRequiresSSL(manifest interface{}) bool {
	requireSSL, err := GetIn(manifest, "properties", "consul", "require_ssl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	consulRequireSSL := false
	if val, ok := requireSSL.(bool); ok {
		consulRequireSSL = val
	}

	return consulRequireSSL
}

func extractConsulKeyAndCert(manifest interface{}, outputDir string) {
	for key, filename := range map[string]string{
		"properties.consul.agent_cert":     "consul_agent.crt",
		"properties.consul.agent_key":      "consul_agent.key",
		"properties.consul.ca_cert":        "consul_ca.crt",
		"properties.consul.encrypt_keys.0": "consul_encrypt.key",
	} {
		err := extractCert(manifest, outputDir, filename, key)
		if err != nil {
			FailOnError(err)
		}
	}
}

func extractBbsKeyAndCert(manifest interface{}, outputDir string) {
	for key, filename := range map[string]string{
		"properties.diego.rep.bbs.client_cert": "bbs_client.crt",
		"properties.diego.rep.bbs.client_key":  "bbs_client.key",
		"properties.diego.rep.bbs.ca_cert":     "bbs_ca.crt",
	} {
		err := extractCert(manifest, outputDir, filename, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}
	}
}

func EscapeSpecialCharacters(str string) string {
	specialCharacters := []string{"^", "%", "(", ")", `"`, "<", ">", "&", "!", "|"}
	for _, c := range specialCharacters {
		str = strings.Replace(str, c, "^"+c, -1)
	}
	return str
}

func FailOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func getSubnetNetworkName(networks []interface{}, awsSubnet string) string {
	for _, network := range networks {
		networkName := network.(map[interface{}]interface{})["name"]

		result, err := GetIn(network, "subnets")
		FailOnError(err)
		subnets := result.([]interface{})

		for _, subnetProperties := range subnets {
			result, err = GetIn(subnetProperties, "cloud_properties", "subnet")
			FailOnError(err)
			subnet := result.(string)
			if subnet == awsSubnet {
				return networkName.(string)
			}
		}
	}
	return ""
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

func extractCert(manifest interface{}, outputDir, filename, pathString string) error {
	manifestPath := []interface{}{}
	for _, s := range strings.Split(pathString, ".") {
		manifestPath = append(manifestPath, s)
	}
	result, err := GetIn(manifest, manifestPath...)
	FailOnError(err)
	if result == nil {
		return errors.New("Failed to extract cert from deployment: " + pathString)
	}
	cert := result.(string)
	ioutil.WriteFile(path.Join(outputDir, filename), []byte(cert), 0644)
	return nil
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

func NewBoshRequest(endpoint string) *http.Response {
	request, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Fatal(err)
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
