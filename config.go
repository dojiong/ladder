package ladder

import (
	"encoding/json"
	"fmt"
	"os"
)

type ConfigNotFound struct {
	Item string
}

func (c *ConfigNotFound) Error() string {
	return fmt.Sprintf("Config Error: %s not found", c.Item)
}

type ConfigInvalidType struct {
	Item       string
	ExpectType string
	Value      string
}

func (c *ConfigInvalidType) Error() string {
	return fmt.Sprintf("Config Error[item: %s]: expect %s, got `%s`",
		c.Item, c.ExpectType, c.Value)
}

type Config map[string]interface{}

func NewConfig(data []byte) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func NewConfigFromFile(path string) (Config, error) {
	if f, err := os.Open(path); err != nil {
		return nil, err
	} else {
		defer f.Close()
		var cfg Config
		decoder := json.NewDecoder(f)
		decoder.UseNumber()
		if err = decoder.Decode(&cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
}

func (c Config) Get(name string) (interface{}, error) {
	if v, ok := c[name]; ok {
		return v, nil
	}
	return nil, &ConfigNotFound{name}
}

func (c Config) Has(name string) bool {
	_, has := c[name]
	return has
}

func (c Config) GetInt(name string, result *int) error {
	var n int64
	if err := c.GetInt64(name, &n); err != nil {
		return err
	} else {
		*result = int(n)
		return nil
	}
}

func (c Config) GetInt64(name string, result *int64) error {
	if v, ok := c[name]; ok {
		if intv, ok := v.(json.Number); ok {
			var err error
			if *result, err = intv.Int64(); err != nil {
				return &ConfigInvalidType{name, "int", fmt.Sprint(v)}
			}
			return nil
		}
		return &ConfigInvalidType{name, "int", fmt.Sprint(v)}
	}
	return &ConfigNotFound{name}
}

func (c Config) GetString(name string, str *string) error {
	if v, ok := c[name]; ok {
		if intv, ok := v.(string); ok {
			*str = intv
			return nil
		}
		return &ConfigInvalidType{name, "string", fmt.Sprint(v)}
	}
	return &ConfigNotFound{name}
}

func (c Config) GetSub(name string) (Config, error) {
	if v, ok := c[name]; ok {
		if cfg, ok := v.(map[string]interface{}); ok {
			return cfg, nil
		}
		return nil, &ConfigInvalidType{name, "map", fmt.Sprint(v)}
	}
	return nil, &ConfigNotFound{name}
}
