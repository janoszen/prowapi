package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

func ReadConfigFromFile(file string, config *AppConfig) error {
	fh, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open config file %s (%w)", file, err)
	}
	defer func() {
		_ = fh.Close()
	}()
	if strings.HasSuffix(file, ".json") {
		decoder := json.NewDecoder(fh)
		if err := decoder.Decode(config); err != nil {
			return fmt.Errorf("failed to decode JSON file %s (%w)", file, err)
		}
	} else if strings.HasSuffix(file, ".yaml") {
		decoder := yaml.NewDecoder(fh)
		if err := decoder.Decode(config); err != nil {
			return fmt.Errorf("failed to decode YAML file %s (%w)", file, err)
		}
	} else {
		return fmt.Errorf("unsupported file format in config file %s", file)
	}
	return nil
}

