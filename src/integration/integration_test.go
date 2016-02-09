package integration_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"text/template"

	"models"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
)

func DefaultServer() *ghttp.Server {
	return CreateServer("one_zone_manifest.yml", DefaultIndexDeployment())
}

func CreateServer(manifest string, deployments []models.IndexDeployment) *ghttp.Server {
	yaml, err := ioutil.ReadFile(manifest)
	Expect(err).ToNot(HaveOccurred())

	diegoDeployment := models.ShowDeployment{
		Manifest: string(yaml),
	}

	server := ghttp.NewServer()
	server.AppendHandlers(
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/deployments"),
			ghttp.RespondWithJSONEncoded(200, deployments),
		),
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/deployments/cf-warden-diego"),
			ghttp.RespondWithJSONEncoded(200, diegoDeployment),
		),
	)

	return server
}

func Create401Server() *ghttp.Server {
	server := ghttp.NewServer()
	server.AppendHandlers(
		ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/deployments"),
			ghttp.RespondWith(401, "Not authorized"),
		),
	)

	return server
}

func StartGeneratorWithURL(serverUrl string) (*gexec.Session, string) {
	var err error
	outputDir, err := ioutil.TempDir("", "XXXXXXX")
	Expect(err).NotTo(HaveOccurred())

	return StartGeneratorWithArgs(
		"-boshUrl", serverUrl,
		"-outputDir", outputDir,
		"-windowsUsername", "admin",
		"-windowsPassword", "password",
	), outputDir
}

func StartGeneratorWithArgs(args ...string) *gexec.Session {
	generatePath, err := gexec.Build("generate")
	Expect(err).NotTo(HaveOccurred())
	command := exec.Command(generatePath, args...)
	session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	return session
}

func DefaultIndexDeployment() []models.IndexDeployment {
	return []models.IndexDeployment{
		{
			Name: "cf-warden",
			Releases: []models.Release{
				{
					Name:    "cf",
					Version: "213+dev.2",
				},
			},
		},
		{
			Name: "cf-warden-diego",
			Releases: []models.Release{
				{
					Name:    "cf",
					Version: "213+dev.2",
				},
				{
					Name:    "diego",
					Version: "0.1366.0+dev.2",
				},
				{
					Name:    "garden-linux",
					Version: "0.305.0",
				},
			},
		},
		{
			Name: "diego-vizzini",
			Releases: []models.Release{
				{
					Name:    "cf",
					Version: "213+dev.2",
				},
				{
					Name:    "diego",
					Version: "0.1366.0+dev.2",
				},
			},
		},
	}
}

func AmbiguousIndexDeployment() []models.IndexDeployment {
	return []models.IndexDeployment{
		{
			Name: "cf-warden",
			Releases: []models.Release{
				{
					Name:    "cf",
					Version: "213+dev.2",
				},
			},
		},
		{
			Name: "cf-warden-diego",
			Releases: []models.Release{
				{
					Name:    "cf",
					Version: "213+dev.2",
				},
				{
					Name:    "diego",
					Version: "0.1366.0+dev.2",
				},
				{
					Name:    "garden-linux",
					Version: "0.305.0",
				},
			},
		},
		{
			Name: "cf-warden-diego-2",
			Releases: []models.Release{
				{
					Name:    "cf",
					Version: "213+dev.2",
				},
				{
					Name:    "diego",
					Version: "0.1366.0+dev.2",
				},
				{
					Name:    "garden-linux",
					Version: "0.305.0",
				},
			},
		},
	}
}

func ExpectedContent(args models.InstallerArguments) string {
	content := `msiexec /passive /norestart /i %~dp0\DiegoWindows.msi ^{{ if .BbsRequireSsl }}
  BBS_CA_FILE=%~dp0\bbs_ca.crt ^
  BBS_CLIENT_CERT_FILE=%~dp0\bbs_client.crt ^
  BBS_CLIENT_KEY_FILE=%~dp0\bbs_client.key ^{{ end }}
  CONSUL_IPS=127.0.0.1 ^
  CF_ETCD_CLUSTER=http://etcd1.foo.bar:4001 ^
  STACK=windows2012R2 ^
  REDUNDANCY_ZONE=windows ^
  LOGGREGATOR_SHARED_SECRET=secret123 ^
  MACHINE_IP={{if .MachineIp }}{{.MachineIp}}{{else}}127.0.0.1{{end}}{{ if .SyslogHostIP }} ^
  SYSLOG_HOST_IP=logs2.test.com ^
  SYSLOG_PORT=11111{{ end }}{{ if .ConsulRequireSSL }} ^
  CONSUL_ENCRYPT_FILE=%~dp0\consul_encrypt.key ^
  CONSUL_CA_FILE=%~dp0\consul_ca.crt ^
  CONSUL_AGENT_CERT_FILE=%~dp0\consul_agent.crt ^
  CONSUL_AGENT_KEY_FILE=%~dp0\consul_agent.key{{end}}

msiexec /passive /norestart /i %~dp0\GardenWindows.msi ^
  ADMIN_USERNAME={{.Username}} ^
  ADMIN_PASSWORD={{.Password}} ^
  MACHINE_IP={{if .MachineIp }}{{.MachineIp}}{{else}}127.0.0.1{{end}}{{ if .SyslogHostIP }} ^
  SYSLOG_HOST_IP=logs2.test.com ^
  SYSLOG_PORT=11111{{ end }}`
	content = strings.Replace(content, "\n", "\r\n", -1)
	temp := template.Must(template.New("").Parse(content))
	buf := bytes.NewBufferString("")
	err := temp.Execute(buf, args)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

var _ = Describe("Generate", func() {
	var outputDir string
	var script string
	var server *ghttp.Server
	var manifestYaml string
	var deployments []models.IndexDeployment
	var session *gexec.Session

	BeforeEach(func() {
		manifestYaml = "syslog_manifest.yml"
		deployments = DefaultIndexDeployment()
	})

	AfterEach(func() {
		server.Close()
		Expect(os.RemoveAll(outputDir)).To(Succeed())
	})

	JustBeforeEach(func() {
		server = CreateServer(manifestYaml, deployments)
	})

	Describe("Success scenarios", func() {
		Context("with default arguments", func() {
			JustBeforeEach(func() {
				session, outputDir = StartGeneratorWithURL(server.URL())
				Eventually(session).Should(gexec.Exit(0))
				content, err := ioutil.ReadFile(path.Join(outputDir, "install.bat"))
				Expect(err).NotTo(HaveOccurred())
				script = strings.TrimSpace(string(content))
			})

			Context("when the deployment has syslog", func() {
				expectedContent := ExpectedContent(models.InstallerArguments{
					ConsulRequireSSL: true,
					SyslogHostIP:     "logs2.test.com",
					BbsRequireSsl:    true,
					Username:         "admin",
					Password:         `"""password"""`,
				})

				Context("when values are explicitly set", func() {
					BeforeEach(func() {
						manifestYaml = "syslog_manifest.yml"
					})

					It("contains all the MSI parameters", func() {
						Expect(script).To(Equal(expectedContent))
					})
				})

				Context("when values are implicitly set by defaults", func() {
					BeforeEach(func() {
						manifestYaml = "syslog_manifest_default_values.yml"
					})

					It("contains all the MSI parameters", func() {
						Expect(script).To(Equal(expectedContent))
					})
				})
			})

			Context("when the deployment has a string port in the syslog", func() {
				BeforeEach(func() {
					manifestYaml = "syslog_with_string_port_manifest.yml"
				})

				It("contains all the MSI parameters", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						ConsulRequireSSL: true,
						SyslogHostIP:     "logs2.test.com",
						BbsRequireSsl:    true,
						Username:         "admin",
						Password:         `"""password"""`,
					})
					Expect(script).To(Equal(expectedContent))
				})
			})

			Context("when the deployment has a null address and port in the syslog", func() {
				BeforeEach(func() {
					manifestYaml = "syslog_with_null_address_and_port.yml"
				})

				It("contains all the MSI parameters", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						ConsulRequireSSL: true,
						BbsRequireSsl:    true,
						Username:         "admin",
						Password:         `"""password"""`,
					})
					Expect(script).To(Equal(expectedContent))
				})
			})

			Context("when the server returns a one zone manifest", func() {
				JustBeforeEach(func() {
					manifestYaml = "one_zone_manifest.yml"
					server = CreateServer(manifestYaml, DefaultIndexDeployment())
					var session *gexec.Session
					session, outputDir = StartGeneratorWithURL(server.URL())
					Eventually(session).Should(gexec.Exit(-1))
				})

				It("sends get requests to get the deployments", func() {
					Expect(server.ReceivedRequests()).To(HaveLen(2))
				})

				Context("consul files", func() {
					It("generates the certificate authority cert", func() {
						cert, err := ioutil.ReadFile(path.Join(outputDir, "consul_ca.crt"))
						Expect(err).NotTo(HaveOccurred())
						Expect(cert).To(BeEquivalentTo("CONSUL_CA_CERT"))
					})

					It("generates the agent cert", func() {
						cert, err := ioutil.ReadFile(path.Join(outputDir, "consul_agent.crt"))
						Expect(err).NotTo(HaveOccurred())
						Expect(cert).To(BeEquivalentTo("CONSUL_AGENT_CERT"))
					})

					It("generates the agent key", func() {
						cert, err := ioutil.ReadFile(path.Join(outputDir, "consul_agent.key"))
						Expect(err).NotTo(HaveOccurred())
						Expect(cert).To(BeEquivalentTo("CONSUL_AGENT_KEY"))
					})

					AssertEncryptKeyIsBase64Encoded := func() {
						It("generates the encrypt key", func() {
							cert, err := ioutil.ReadFile(path.Join(outputDir, "consul_encrypt.key"))
							Expect(err).NotTo(HaveOccurred())
							Expect(cert).To(BeEquivalentTo("mBevws9TpU1sFPHK/Fq0IQ=="))
						})
					}

					Context("when the manifest has base64 encoded key", func() {
						AssertEncryptKeyIsBase64Encoded()
					})

					Context("when the manifest is using a passphrase", func() {
						BeforeEach(func() {
							manifestYaml = "encrypt_key_passphrase_manifest.yml"
						})

						AssertEncryptKeyIsBase64Encoded()
					})
				})

				Describe("the lines of the batch script", func() {
					var script string

					JustBeforeEach(func() {
						content, err := ioutil.ReadFile(path.Join(outputDir, "install.bat"))
						Expect(err).NotTo(HaveOccurred())
						script = strings.TrimSpace(string(content))
					})

					It("contains all the MSI parameters", func() {
						expectedContent := ExpectedContent(models.InstallerArguments{
							ConsulRequireSSL: true,
							BbsRequireSsl:    true,
							Username:         "admin",
							Password:         `"""password"""`,
						})
						Expect(script).To(Equal(expectedContent))
					})
				})
			})

			Context("when the deployment has no bbs certs", func() {
				BeforeEach(func() {
					manifestYaml = "no_bbs_cert_manifest.yml"
				})

				It("does not contain bbs parameters", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						ConsulRequireSSL: true,
						BbsRequireSsl:    false,
						Username:         "admin",
						Password:         `"""password"""`,
					})
					Expect(script).To(Equal(expectedContent))
				})
			})

			Context("when the deployment has no bbs or consul certs", func() {
				BeforeEach(func() {
					manifestYaml = "no_consul_or_bbs_cert_manifest.yml"
				})

				It("does not contain bbs parameters", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						ConsulRequireSSL: false,
						BbsRequireSsl:    false,
						Username:         "admin",
						Password:         `"""password"""`,
					})
					Expect(script).To(Equal(expectedContent))
				})
			})

			Context("when the deployment has no consul certs", func() {
				BeforeEach(func() {
					manifestYaml = "no_consul_cert_manifest.yml"
				})

				It("does not contain consul parameters", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						Username:         "admin",
						Password:         `"""password"""`,
						ConsulRequireSSL: false,
						BbsRequireSsl:    true,
					})
					Expect(script).To(Equal(expectedContent))
				})
			})

			Context("when the deployment specifies consul properties in the job", func() {
				BeforeEach(func() {
					manifestYaml = "job_override_manifest.yml"
				})

				It("gets the properties from the job", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						ConsulRequireSSL: true,
						SyslogHostIP:     "logs2.test.com",
						BbsRequireSsl:    true,
						Username:         "admin",
						Password:         `"""password"""`,
					})
					Expect(script).To(Equal(expectedContent))
				})
			})
		})

		Context("with an optional machine IP", func() {
			JustBeforeEach(func() {
				var session *gexec.Session
				outputDir, err := ioutil.TempDir("", "XXXXXXX")
				Expect(err).ToNot(HaveOccurred())
				session = StartGeneratorWithArgs(
					"-boshUrl", server.URL(),
					"-outputDir", outputDir,
					"-windowsUsername", "admin",
					"-windowsPassword", "password",
					"-machineIp", "10.10.3.21",
				)
				Eventually(session).Should(gexec.Exit(0))
				content, err := ioutil.ReadFile(path.Join(outputDir, "install.bat"))
				Expect(err).NotTo(HaveOccurred())
				script = strings.TrimSpace(string(content))
			})

			It("gets the properties from the job", func() {
				expectedContent := ExpectedContent(models.InstallerArguments{
					ConsulRequireSSL: true,
					SyslogHostIP:     "logs2.test.com",
					BbsRequireSsl:    true,
					Username:         "admin",
					Password:         `"""password"""`,
					MachineIp:        "10.10.3.21",
				})
				Expect(script).To(Equal(expectedContent))
			})
		})
	})

	Describe("Failure scenarios", func() {
		Context("non alphanumeric credentials", func() {
			var username, password string

			BeforeEach(func() {
				username = "username"
				password = "password"
			})

			JustBeforeEach(func() {
				var err error
				outputDir, err = ioutil.TempDir("", "XXXXXXX")
				Expect(err).ToNot(HaveOccurred())
				session = StartGeneratorWithArgs(
					"-boshUrl", server.URL(),
					"-outputDir", outputDir,
					"-windowsUsername", username,
					"-windowsPassword", password,
				)
			})

			Context("non alphanumeric username", func() {
				BeforeEach(func() {
					username = "%%29529@@"
				})

				It("exits with exit code 1", func() {
					Eventually(session).Should(gexec.Exit(1))
				})

				It("prints an error message", func() {
					Eventually(session.Err).Should(gbytes.Say("Invalid windowsUsername"))
				})
			})

			Context("non alphanumeric password", func() {
				BeforeEach(func() {
					password = "password`~!@#$^&*()_-+={}[]\\|:;<>,.?/123'%"
				})

				JustBeforeEach(func() {
					Eventually(session).Should(gexec.Exit(0))
					content, err := ioutil.ReadFile(path.Join(outputDir, "install.bat"))
					Expect(err).NotTo(HaveOccurred())
					script = strings.TrimSpace(string(content))
				})

				It("escapes the password properly", func() {
					expectedContent := ExpectedContent(models.InstallerArguments{
						ConsulRequireSSL: true,
						SyslogHostIP:     "logs2.test.com",
						BbsRequireSsl:    true,
						Username:         "username",
						Password:         "\"\"\"password`~!@#$^&*()_-+={}[]\\|:;<>,.?/123'%%\"\"\"",
					})
					Expect(script).To(Equal(expectedContent))
				})
			})

			Describe("double quotes in passwords", func() {
				BeforeEach(func() {
					password = `"password"`
				})

				It("does not allow them", func() {
					Eventually(session).Should(gexec.Exit(1))
					Eventually(session.Err).Should(gbytes.Say("Invalid windowsPassword"))
				})
			})
		})

		Context("when the server is not reachable", func() {
			var session *gexec.Session

			BeforeEach(func() {
				session, outputDir = StartGeneratorWithURL("http://1.2.3.4:5555")
				Eventually(session, "15s", "1s").Should(gexec.Exit(1))
			})

			It("displays the reponse error to the user", func() {
				Expect(session.Err).Should(gbytes.Say("Unable to establish connection to BOSH Director"))
			})
		})

		Context("when the server returns an unauthorized error", func() {
			var session *gexec.Session

			BeforeEach(func() {
				server := Create401Server()
				session, outputDir = StartGeneratorWithURL(server.URL())
				Eventually(session).Should(gexec.Exit(1))
			})

			It("displays the reponse error to the user", func() {
				Expect(session.Err).Should(gbytes.Say("Not authorized"))
			})
		})

		Context("when the server returns an ambiguous number of deployments", func() {
			var server *ghttp.Server
			var session *gexec.Session

			BeforeEach(func() {
				server = CreateServer("one_zone_manifest.yml", AmbiguousIndexDeployment())
				session, outputDir = StartGeneratorWithURL(server.URL())
				Eventually(session).Should(gexec.Exit(1))
			})

			It("displays the reponse error to the user", func() {
				Expect(session.Err).Should(gbytes.Say("BOSH Director does not have exactly one deployment containing a cf and diego release."))
			})
		})

		Context("when ran without params", func() {
			var session *gexec.Session
			BeforeEach(func() {
				session = StartGeneratorWithArgs()
			})

			It("prints an error message", func() {
				Eventually(session).Should(gexec.Exit(1))
				Expect(session.Err).Should(gbytes.Say("Usage of generate:"))
			})
		})

		Context("when no consul servers are found in the manifest", func() {
			var server *ghttp.Server
			var session *gexec.Session

			BeforeEach(func() {
				server = CreateServer("no_consul_manifest.yml", DefaultIndexDeployment())
				session, outputDir = StartGeneratorWithURL(server.URL())
				Eventually(session).Should(gexec.Exit(1))
			})

			It("displays an error to the user", func() {
				Expect(session.Err).Should(gbytes.Say("Could not find any Consul VMs in your BOSH deployment"))
			})
		})
	})

	Context("when ran with an ouputDir param that points to a dir that doesn't exist", func() {
		var session *gexec.Session
		var nonExistingDir string
		BeforeEach(func() {
			outputDir, err := ioutil.TempDir("", "XXXXXXX")
			nonExistingDir = path.Join(outputDir, "does_not_exist")
			Expect(err).NotTo(HaveOccurred())
			server := DefaultServer()
			session = StartGeneratorWithArgs(
				"-boshUrl", server.URL(),
				"-outputDir", nonExistingDir,
				"-windowsUsername", "admin",
				"-windowsPassword", "password",
			)
		})

		It("creates the directory", func() {
			Eventually(session).Should(gexec.Exit(0))
			_, err := os.Stat(nonExistingDir)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
