package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func printResult(out json.RawMessage, pretty bool) {
	if pretty {
		var pretty bytes.Buffer
		json.Indent(&pretty, out, "", "\t")

		fmt.Println(string(pretty.Bytes()))
	} else {
		fmt.Println(string(out))
	}
}
func ifpanic(err error) {
	if err != nil {
		panic(err)
	}
}
