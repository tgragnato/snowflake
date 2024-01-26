package version

import "fmt"
import "runtime/debug"

var version = func() string {
	ver := "2.8.1"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return fmt.Sprintf("%v (%v)", ver, setting.Value[:8])
			}
		}
	}
	return ver
}()

func GetVersion() string {
	return version
}
