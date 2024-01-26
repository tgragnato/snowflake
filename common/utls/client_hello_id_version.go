package utls

import (
	"strings"

	"github.com/tgragnato/snowflake/common/version"
)

func generateVersionOutput() string {
	var versionOutputBuilder strings.Builder

	versionOutputBuilder.WriteString(`Known utls-imitate values:
(empty)
`)

	for _, name := range ListAllNames() {
		versionOutputBuilder.WriteString(name)
		versionOutputBuilder.WriteRune('\n')
	}
	return versionOutputBuilder.String()
}

func init() {
	version.AddVersionDetail(generateVersionOutput())
}
