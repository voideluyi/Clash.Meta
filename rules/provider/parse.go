package provider

import (
	"errors"
	"fmt"
	"time"

	"github.com/Dreamacro/clash/common/structure"
	"github.com/Dreamacro/clash/component/resource"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
)

var (
	errSubPath = errors.New("path is not subpath of home directory")
)

type ruleProviderSchema struct {
	Type       string `provider:"type"`
	Behavior   string `provider:"behavior"`
	Path       string `provider:"path,omitempty"`
	URL        string `provider:"url,omitempty"`
	P12kFile   string `provider:"p12k-file,omitempty"`
	P12kPass   string `provider:"p12k-pass,omitempty"`
	ClientCert string `provider:"client-cert,omitempty"`
	ClientKey  string `provider:"client-key,omitempty"`
	Format     string `provider:"format,omitempty"`
	Interval   int    `provider:"interval,omitempty"`
}

func ParseRuleProvider(name string, mapping map[string]interface{}, parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) (P.RuleProvider, error) {
	schema := &ruleProviderSchema{}
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}
	var behavior P.RuleBehavior

	switch schema.Behavior {
	case "domain":
		behavior = P.Domain
	case "ipcidr":
		behavior = P.IPCIDR
	case "classical":
		behavior = P.Classical
	default:
		return nil, fmt.Errorf("unsupported behavior type: %s", schema.Behavior)
	}

	var format P.RuleFormat

	switch schema.Format {
	case "", "yaml":
		format = P.YamlRule
	case "text":
		format = P.TextRule
	default:
		return nil, fmt.Errorf("unsupported format type: %s", schema.Format)
	}

	var vehicle P.Vehicle
	switch schema.Type {
	case "file":
		path := C.Path.Resolve(schema.Path)
		vehicle = resource.NewFileVehicle(path)
	case "http":
		if schema.Path != "" {
			path := C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(path) {
				return nil, fmt.Errorf("%w: %s", errSubPath, path)
			}
			vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.P12kFile, schema.P12kPass, schema.ClientCert, schema.ClientKey)
		} else {
			path := C.Path.GetPathByHash("rules", schema.URL)
			vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.P12kFile, schema.P12kPass, schema.ClientCert, schema.ClientKey)
		}

	default:
		return nil, fmt.Errorf("unsupported vehicle type: %s", schema.Type)
	}

	return NewRuleSetProvider(name, behavior, format, time.Duration(uint(schema.Interval))*time.Second, vehicle, parse), nil
}
