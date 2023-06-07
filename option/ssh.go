package option

import "github.com/sagernet/sing/common/auth"

type SSHOutboundOptions struct {
	DialerOptions
	ServerOptions
	User                 string           `json:"user,omitempty"`
	Password             string           `json:"password,omitempty"`
	PrivateKey           string           `json:"private_key,omitempty"`
	PrivateKeyPath       string           `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string           `json:"private_key_passphrase,omitempty"`
	HostKey              Listable[string] `json:"host_key,omitempty"`
	HostKeyAlgorithms    Listable[string] `json:"host_key_algorithms,omitempty"`
	ClientVersion        string           `json:"client_version,omitempty"`
}

type SSHInboundOptions struct {
	ListenOptions
	Users []auth.User `json:"users,omitempty"`

	HostKey string `json:"host_key,omitempty"`

	// 客户端key
	ClientKeys Listable[string] `json:"client_keys,omitempty"`

	ServerVersion        string `json:"server_version,omitempty"`
	PrivateKey           string `json:"private_key,omitempty"`
	PrivateKeyPath       string `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string `json:"private_key_passphrase,omitempty"`
}
