package x509

import (
	"io/ioutil"
	"strings"
)

// LoadPEM looks at the spec field and loads the PEM from an external file if needed.
func LoadPEM(spec string) ([]byte, error) {
	if !strings.HasPrefix(strings.TrimSpace(spec), "-----") {
		return ioutil.ReadFile(spec)
	}
	return []byte(spec), nil
}
