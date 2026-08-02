module github.com/Sasi3011/CyberSec/enterprise/agent

go 1.25.0

require (
	github.com/Sasi3011/CyberSec/enterprise/shared v0.0.0
	github.com/kardianos/service v1.2.2
	go.etcd.io/bbolt v1.5.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.45.0 // indirect

replace github.com/Sasi3011/CyberSec/enterprise/shared => ../shared
