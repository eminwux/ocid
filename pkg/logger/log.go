package logger

import (
	"fmt"
	"os"
)

func Verbose(verbose bool, msg string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, msg, args...)
	}
}
