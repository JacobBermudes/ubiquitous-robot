package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Payload struct {
	Containers       []Container `json:"containers"`
	DefaultContainer string      `json:"defaultContainer"`
	Description      string      `json:"description"`
	Dns1             string      `json:"dns1"`
}

type Container struct {
	Awg       Awg    `json:"awg"`
	Container string `json:"container"`
}

type Awg struct {
	H1            string `json:"H1"`
	H2            string `json:"H2"`
	H3            string `json:"H3"`
	H4            string `json:"H4"`
	Jc            string `json:"Jc"`
	Jmax          string `json:"Jmax"`
	Jmin          string `json:"Jmin"`
	S1            string `json:"S1"`
	S2            string `json:"S2"`
	ClientID      string `json:"clientId"`
	ClientIP      string `json:"client_ip"`
	ClientPrivKey string `json:"client_priv_key"`
	ClientPubKey  string `json:"client_pub_key"`
	Config        string `json:"config"`
	Hostname      string `json:"hostname"`
	Mtu           string `json:"mtu"`
	Port          int64  `json:"port"`
	PskKey        string `json:"psk_key"`
	ServerPubKey  string `json:"server_pub_key"`
}

func main() {
	serverPub, err := os.ReadFile("/opt/amnezia/awg/wireguard_server_public_key.key")
	if err != nil {
		panic(err)
	}

	clientIP, err := nextIP("/opt/amnezia/awg/wg0.conf")
	if err != nil {
		panic(err)
	}

	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey()

	serverPsk, err := os.ReadFile("/opt/amnezia/awg/wireguard_server_public_key.key")
	if err != nil {
		panic(err)
	}

	wgConf := fmt.Sprintf(`[Interface]
Address = %s/32
DNS = 172.29.172.254, 8.8.8.8
PrivateKey = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 66.151.41.40:40902
PersistentKeepalive = 25
`, clientIP, privKey.String(), string(serverPub), string(serverPsk))

	payload := Payload{
		Containers: []Container{
			{
				Awg: Awg{
					H1:            "1857189466",
					H2:            "1395761759",
					H3:            "855944135",
					H4:            "1518967018",
					Jc:            "4",
					Jmax:          "50",
					Jmin:          "10",
					S1:            "118",
					S2:            "29",
					ClientID:      pubKey.String(),
					ClientIP:      clientIP,
					ClientPrivKey: privKey.String(),
					ClientPubKey:  pubKey.String(),
					Config:        wgConf,
					Hostname:      "66.151.41.40",
					Mtu:           "1280",
					Port:          40902,
					PskKey:        string(serverPsk),
					ServerPubKey:  string(serverPub),
				},
				Container: "amnezia-awg",
			},
		},
		DefaultContainer: "amnezia-awg",
		Description:      "HAMAS VPN",
		Dns1:             "172.29.172.254",
	}

	jsonBytes, _ := json.Marshal(payload)

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write(jsonBytes)
	zw.Close()
	compressed := buf.Bytes()

	// Amnezia SECRET BYTES
	header := []byte{0x00, 0x00, 0x08, 0x28}
	finalBytes := append(header, compressed...)

	enc := base64.RawURLEncoding.EncodeToString(finalBytes)
	link := "vpn://" + enc

	fmt.Println("=== Public key (добавить на сервер) ===")
	fmt.Println(pubKey.String())
	fmt.Println("=== Amnezia link ===")
	fmt.Println(link)
}

func nextIP(serverConf string) (string, error) {
	file, err := os.Open(serverConf)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var lastIP string
	re := regexp.MustCompile(`AllowedIPs\s*=\s*([\d\.]+)/\d+`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); matches != nil {
			lastIP = matches[1]
		}
	}

	if lastIP == "" {
		return "", fmt.Errorf("не найден ни один AllowedIPs")
	}

	ip := net.ParseIP(lastIP).To4()
	if ip == nil {
		return "", fmt.Errorf("не удалось распарсить IP %s", lastIP)
	}

	ip[3]++

	return ip.String(), nil
}
