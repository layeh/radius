package radius

import (
	"os/exec"
	"testing"
)

func TestRFCBuild(t *testing.T) {
	t.Parallel()

	packages := []string{
		"rfc2865",
		"rfc2866",
		"rfc2867",
		"rfc3576",
		"rfc5176",
	}

	for _, pkg := range packages {
		func(pkg string) {
			t.Run(pkg, func(t *testing.T) {
				t.Parallel()

				cmd := exec.Command("go", "build", "layeh.com/radius/"+pkg)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Errorf("%s: %s\n", err, output)
				}
			})
		}(pkg)
	}
}
