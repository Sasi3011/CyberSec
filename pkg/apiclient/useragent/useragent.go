package useragent

import (
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/branding"
)

func Default() string {
	return branding.PlatformSlug + "/" + version.String() + "-" + version.System
}

func AppsecUserAgent() string {
	return "appsec/" + version.String() + "-" + version.System
}
