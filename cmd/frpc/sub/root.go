// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sub

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

const (
	CfgFileTypeIni = iota
	CfgFileTypeCmd
)

var (
	cfgFile       string
	cfgDir        string
	showVersion   bool
	laetoken      string
	tunnelid      string
	RemoteContent string
	LocalContent  string

	serverAddr      string
	user            string
	protocol        string
	token           string
	logLevel        string
	logFile         string
	logMaxDays      int
	disableLogColor bool

	proxyName         string
	localIP           string
	localPort         int
	remotePort        int
	useEncryption     bool
	useCompression    bool
	customDomains     string
	subDomain         string
	httpUser          string
	httpPwd           string
	locations         string
	hostHeaderRewrite string
	role              string
	sk                string
	multiplexer       string
	serverName        string
	bindAddr          string
	bindPort          int

	tlsEnable bool
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file of frpc")
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config_dir", "", "", "config directory, run one frpc service for each file in config directory")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of frpc")
	rootCmd.PersistentFlags().StringVarP(&laetoken, "laetoken", "t", "", "LaeCloud's API Token")
	rootCmd.PersistentFlags().StringVarP(&tunnelid, "id", "i", "", "Tunnel's ID")
}

func RegisterCommonFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&serverAddr, "server_addr", "s", "127.0.0.1:7000", "frp server's address")
	cmd.PersistentFlags().StringVarP(&user, "user", "u", "", "user")
	cmd.PersistentFlags().StringVarP(&protocol, "protocol", "p", "tcp", "tcp or kcp or websocket")
	cmd.PersistentFlags().StringVarP(&token, "token", "t", "", "auth token")
	cmd.PersistentFlags().StringVarP(&logLevel, "log_level", "", "info", "log level")
	cmd.PersistentFlags().StringVarP(&logFile, "log_file", "", "console", "console or file path")
	cmd.PersistentFlags().IntVarP(&logMaxDays, "log_max_days", "", 3, "log file reversed days")
	cmd.PersistentFlags().BoolVarP(&disableLogColor, "disable_log_color", "", false, "disable log color in console")
	cmd.PersistentFlags().BoolVarP(&tlsEnable, "tls_enable", "", false, "enable frpc tls")
}

func GetJson(laetoken string, tunnelid string) {
	// 设置请求头
	req, err := http.NewRequest("GET", "https://api.laecloud.com/api/modules/frp/hosts/"+tunnelid, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+laetoken)

	// 创建 HTTP 客户端
	client := &http.Client{}

	// 发送 HTTP 请求并获取响应
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("请求到 LaeCloud API 错误 %d", response.StatusCode)
		fmt.Println(err)
		os.Exit(1)
		return
	}
	defer response.Body.Close()

	// 读取响应体并将其转换为字符串
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	jsonString := string(data)
	var tunnelc tunnel
	err1 := json.Unmarshal([]byte(jsonString), &tunnelc)
	if err1 != nil {
		fmt.Println(err1)
		return
	}

	tunnelc.fullconf = tunnelc.Conf.Server + "\n" + "dns_server = 8.8.8.8" + "\n" + tunnelc.Conf.Client
	fmt.Println("获取配置文件成功！ 开始启动隧道" + "\n")
	var content string = tunnelc.fullconf
	RemoteContent = content
	return
}

type tunnel struct {
	Conf     Conf   `json:"config"`
	Name     string `json:"name"`
	fullconf string
}
type Conf struct {
	Client string `json:"client"`
	Server string `json:"server"`
}

var rootCmd = &cobra.Command{
	Use:   "frpc",
	Short: "This APP is MirrorEdge Frp's Modified Version",
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println(version.Full())

			return nil
		}
		fmt.Printf("欢迎使用 MirrorEdge Frp" + "\n")
		// If cfgDir is not empty, run multiple frpc service for each config file in cfgDir.
		// Note that it's only designed for testing. It's not guaranteed to be stable.

		// Do not show command usage here.
		if cfgFile == "" && (laetoken == "" || tunnelid == "") {
			fmt.Println("启动参数不完整！ 使用 frpc -h 获取帮助")
			return nil
		}
		err := runClient(cfgFile, laetoken, tunnelid)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func handleSignal(svr *client.Service, doneCh chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	svr.GracefulClose(500 * time.Millisecond)
	close(doneCh)
}

func parseClientCommonCfgFromCmd() (cfg config.ClientCommonConf, err error) {
	cfg = config.GetDefaultClientConf()

	ipStr, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		err = fmt.Errorf("invalid server_addr: %v", err)
		return
	}

	cfg.ServerAddr = ipStr
	cfg.ServerPort, err = strconv.Atoi(portStr)
	if err != nil {
		err = fmt.Errorf("invalid server_addr: %v", err)
		return
	}

	cfg.User = user
	cfg.Protocol = protocol
	cfg.LogLevel = logLevel
	cfg.LogFile = logFile
	cfg.LogMaxDays = int64(logMaxDays)
	cfg.DisableLogColor = disableLogColor

	// Only token authentication is supported in cmd mode
	cfg.ClientConfig = auth.GetDefaultClientConf()
	cfg.Token = token
	cfg.TLSEnable = tlsEnable

	cfg.Complete()
	if err = cfg.Validate(); err != nil {
		err = fmt.Errorf("parse config error: %v", err)
		return
	}
	return
}

func runClient(cfgFilePath string, laetoken string, tunnelid string) error {
	var content string
	if cfgFilePath != "" {
		LocalContent, err := config.GetRenderedConfFromFile(cfgFile)
		if err != nil {
			return err
		}
		content = string(LocalContent)
	} else {
		GetJson(laetoken, tunnelid)
		content = RemoteContent
	}
	cfg, pxyCfgs, visitorCfgs, err := config.ParseClientConfig(content)
	if err != nil {
		return err
	}
	return startService(cfg, pxyCfgs, visitorCfgs, cfgFilePath)
}

func startService(
	cfg config.ClientCommonConf,
	pxyCfgs map[string]config.ProxyConf,
	visitorCfgs map[string]config.VisitorConf,
	cfgFile string,
) (err error) {
	log.InitLog(cfg.LogWay, cfg.LogFile, cfg.LogLevel,
		cfg.LogMaxDays, cfg.DisableLogColor)

	svr, errRet := client.NewService(cfg, pxyCfgs, visitorCfgs, cfgFile)
	if errRet != nil {
		err = errRet
		return
	}

	kcpDoneCh := make(chan struct{})
	// Capture the exit signal if we use kcp.
	if cfg.Protocol == "kcp" {
		go handleSignal(svr, kcpDoneCh)
	}

	err = svr.Run()
	if err == nil && cfg.Protocol == "kcp" {
		<-kcpDoneCh
	}
	return
}
