package models

type Release struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type IndexDeployment struct {
	Name     string    `json:"name"`
	Releases []Release `json:"releases"`
}

type ShowDeployment struct {
	Manifest string `json:"manifest"`
}

type InstallerArguments struct {
	ConsulRequireSSL bool
	ConsulIPs        string
	EtcdCluster      string
	Zone             string
	SharedSecret     string
	Username         string
	Password         string
	SyslogHostIP     string
	SyslogPort       string
	BbsRequireSsl    bool
	MachineIp        string
}

type ConsulProperties struct {
	RequireSSL  *bool    `yaml:"require_ssl"`
	CACert      string   `yaml:"ca_cert"`
	AgentCert   string   `yaml:"agent_cert"`
	AgentKey    string   `yaml:"agent_key"`
	EncryptKeys []string `yaml:"encrypt_keys"`
	Agent       struct {
		Servers struct {
			Lan []string `yaml:"lan"`
		} `yaml:"servers"`
	} `yaml:"agent"`
}

type BBSProperties struct {
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	RequireSSL *bool  `yaml:"require_ssl"`
}

type DiegoProperties struct {
	Rep *struct {
		Zone string         `yaml:"zone"`
		BBS  *BBSProperties `yaml:"bbs"`
	} `yaml:"rep"`
}

type LoggregatorProperties struct {
	Etcd struct {
		Machines []string `yaml:"machines"`
	} `yaml:"etcd"`
}

type LoggregatorEndpoint struct {
	SharedSecret string `yaml:"shared_secret"`
}

type SyslogProperties struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Properties struct {
	Consul              *ConsulProperties      `yaml:"consul"`
	Diego               *DiegoProperties       `yaml:"diego"`
	Loggregator         *LoggregatorProperties `yaml:"loggregator"`
	LoggregatorEndpoint *LoggregatorEndpoint   `yaml:"loggregator_endpoint"`
	Syslog              *SyslogProperties      `yaml:"syslog_daemon_config"`
}

type Job struct {
	Name       string      `yaml:"name"`
	Properties *Properties `yaml:"properties"`
}

type Manifest struct {
	Jobs       []Job       `yaml:"jobs"`
	Properties *Properties `yaml:"properties"`
}
