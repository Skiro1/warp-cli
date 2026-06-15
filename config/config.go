package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type AWGConfig struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1"`
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`
}

type Profile struct {
	Name       string    `json:"name"`
	PrivateKey string    `json:"private_key"`
	Address    string    `json:"address"`
	Address6   string    `json:"address6"`
	DNS        string    `json:"dns"`
	PublicKey  string    `json:"public_key"`
	Endpoint   string    `json:"endpoint"`
	AccountID  string    `json:"account_id"`
	ClientID   string    `json:"client_id"`
	Token      string    `json:"token"`
	License    string    `json:"license,omitempty"`
	AWG        AWGConfig `json:"awg"`
}

var DefaultAWG = AWGConfig{
	Jc:   4,
	Jmin: 40,
	Jmax: 70,
	S1:   0,
	S2:   0,
	S3:   0,
	S4:   0,
	H1:   "1",
	H2:   "2",
	H3:   "3",
	H4:   "4",
	I1:   "<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>",
	I2:   "<b 0xa0252c4d2baade38f4eb7a291514fde6678299181e000f5e6e6f3195da044aaf><b 0x66692367cf970c8b6943a67aafbb2fe80c60efefbd7431fceed79000ab5d58803fe3eb82fea6037b00c2564610b7df1f19a4a7bd0d9e><b 0x800ec8cd566c5d670f38240555e658d0642a52fd3b6de1184cf40979334334683ce05470fa8864a2fece>",
	I3:   "<b 0xf6e5d2ab714e586bf71db4295cb2eb17ab77fde047b5529b3cde1e52><b 0xb6b03fa170c886a3c8b470fd63e24015f8ae13cddd05d6a8eb45e2611ac0dda33b0cba85b840e8a1fb438d983e><b 0xc98c18d7ad3233a038f0cdc5318dfd85991556af93de46e0880ca210fa0fc397aacd18c05a39ef7f8e1a863a4e9ea42818526b2a3e37907bf156c6916601aa>",
	I4:   "<b 0x61d8cef65509c807eb953e36286e081b165d8591a72bcb9d6e787a62947c><b 0x6bced8e06c8d4e54d732c7e3bd3f6ce7b7c038d5d016643a9c32aed2023b2d8e98252b74e941bd9fdc548d><b 0x54504efcf46dbcbf05b4c8b77730889232ca3bd7f50720d0287bf0aa08f927850c374b8f008d>",
	I5:   "<b 0x892db5975546d078496542ddf9a0898113f6cc0d7c44cc0813d1e4d9c9d4633a7458af56b73603aa53>",
}

var DefaultEndpoint = "engage.cloudflareclient.com:2408"
var DefaultPublicKey = "bmeXGQk63OMlpJOfmO2B+LHBWNt4VSMHi1kU5Kj7wRc="
var DefaultDNS = "1.1.1.1"

func ProfilesDir() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "profiles")
}

func ProfilePath(name string) string {
	return filepath.Join(ProfilesDir(), name+".json")
}

func (p *Profile) Save() error {
	dir := ProfilesDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create profiles dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(ProfilePath(p.Name), data, 0600); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}
	return nil
}

func LoadProfile(name string) (*Profile, error) {
	data, err := os.ReadFile(ProfilePath(name))
	if err != nil {
		return nil, fmt.Errorf("read profile %q: %w", name, err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal profile %q: %w", name, err)
	}
	if p.Endpoint == "" {
		p.Endpoint = DefaultEndpoint
	}
	if p.PublicKey == "" {
		p.PublicKey = DefaultPublicKey
	}
	if p.DNS == "" {
		p.DNS = DefaultDNS
	}
	return &p, nil
}

func ListProfiles() ([]string, error) {
	dir := ProfilesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name()[:len(e.Name())-5])
		}
	}
	return names, nil
}

func DeleteProfile(name string) error {
	return os.Remove(ProfilePath(name))
}
