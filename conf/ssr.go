package conf

type SsrConfig struct {
	LogConfig        SsrLogConfig `json:"Log"`
	StatePath        string       `json:"StatePath"`
	EnableUDP        bool         `json:"EnableUDP"`
	AllowInsecure    bool         `json:"AllowInsecure"`
	FallbackObfs     string       `json:"FallbackObfs"`
	FallbackCipher   string       `json:"FallbackCipher"`
	FallbackProtocol string       `json:"FallbackProtocol"`
}

type SsrLogConfig struct {
	Level string `json:"Level"`
}

func NewSsrConfig() *SsrConfig {
	return &SsrConfig{
		LogConfig: SsrLogConfig{
			Level: "error",
		},
		StatePath:        "/etc/V2bX/ssr_state.json",
		EnableUDP:        true,
		AllowInsecure:    false,
		FallbackObfs:     "http_simple",
		FallbackCipher:   "aes-128-cfb",
		FallbackProtocol: "auth_aes128_md5",
	}
}

type SsrOptions struct {
	UDPEnabled bool `json:"EnableUDP"`
}

func NewSsrOptions() *SsrOptions {
	return &SsrOptions{
		UDPEnabled: true,
	}
}
