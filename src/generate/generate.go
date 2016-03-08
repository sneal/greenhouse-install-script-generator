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
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfoundry-incubator/candiedyaml"

	"golang.org/x/crypto/pbkdf2"

	"models"
)

func main() {
	boshServerUrl := flag.String("boshUrl", "", "Bosh URL (https://admin:admin@bosh.example:25555)")
	outputDir := flag.String("outputDir", "", "Output directory (/tmp/scripts)")
	windowsUsername := flag.String("windowsUsername", "", "Windows username")
	windowsPassword := flag.String("windowsPassword", "", "Windows password")
	machineIp := flag.String("machineIp", "", "(optional) IP address of this cell")

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

	validateCredentials(*windowsUsername, *windowsPassword)
	escapeWindowsPassword(windowsPassword)

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

	decoder := candiedyaml.NewDecoder(buf)
	err = decoder.Decode(&manifest)
	if err != nil {
		FailOnError(err)
	}

	args := models.InstallerArguments{
		Username: *windowsUsername,
		Password: *windowsPassword,
	}

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

	// missing requireSSL implies true
	requireSSL := properties.Consul.RequireSSL
	if requireSSL == nil || *requireSSL {
		args.ConsulRequireSSL = true
		extractConsulKeyAndCert(properties, outputDir)
	}

	consuls := properties.Consul.Agent.Servers.Lan

	if len(consuls) == 0 {
		fmt.Fprintf(os.Stderr, "Could not find any Consul VMs in your BOSH deployment")
		os.Exit(1)
	}

	args.ConsulIPs = strings.Join(consuls, ",")
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
	args.Zone = "windows"

	configFilename := "config.json"
	bytes, err := json.Marshal(args)

	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(path.Join(outputDir, configFilename), bytes, 0644)

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

func escapeWindowsPassword(password *string) {
	newPassword := *password
	newPassword = strings.Replace(newPassword, "%", "%%", -1)
	newPassword = "\"\"\"" + newPassword + "\"\"\""
	*password = newPassword
}

func validateCredentials(username, password string) {
	pattern := regexp.MustCompile("^[a-zA-Z0-9]+$")

	if !pattern.Match([]byte(username)) {
		log.Fatalln("Invalid windowsUsername, must be alphanumeric")
	}

	if strings.Contains(password, `"`) {
		log.Fatalln("Invalid windowsPassword, must not contain double-quotes")
	}
}
