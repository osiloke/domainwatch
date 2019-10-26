// Copyright © 2018 Osiloke Emoekpere <me@osiloke.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/spf13/cobra"
	// "github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"github.com/letsencrypt-cpanel/cpanelgo"
	"github.com/letsencrypt-cpanel/cpanelgo/whm"
)

// cpanelCmd represents the cpanel command
var cpanelCmd = &cobra.Command{
	Use:   "cpanel",
	Short: "perform command on whm/cpanel",
	Long:  `perform command on whm/cpanel.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("please specify function and args, domainwatch cpanel <function> <...args>")
			return
		}
		function := args[0]
		hostname, _ := cmd.Flags().GetString("hostname")
		insecure, _ := cmd.Flags().GetBool("insecure")
		accesshash, _ := cmd.Flags().GetString("accesshash")
		username, _ := cmd.Flags().GetString("username")
		ahBytes, err := ioutil.ReadFile(accesshash)
		ifpanic(err)
		if len(ahBytes) == 0 {
			log.Fatal("accesshash file was empty")
		}

		whmcl := whm.NewWhmApiAccessHash(hostname, username, string(ahBytes), insecure)
		ifpanic(err)

		var out json.RawMessage
		err = whmcl.WHMAPI1(function, getArgs(args[1:]), &out)
		if err != nil {
			ifpanic(err)
			return
		}
		printResult(out, true)
	},
}

func getArgs(cargs []string) cpanelgo.Args {
	var args = cpanelgo.Args{}

	if flag.NArg() > 0 {
		for _, a := range cargs {
			kv := strings.SplitN(a, "=", 2)
			if len(kv) == 1 {
				args[kv[0]] = ""
			} else if len(kv) == 2 {
				args[kv[0]] = kv[1]
			}
		}
	}

	return args
}

func init() {
	rootCmd.AddCommand(cpanelCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cpanelCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	cpanelCmd.Flags().StringP("hostname", "t", "", "hostname")
	cpanelCmd.Flags().StringP("accesshash", "a", "./whmaccesshash", "path to accesshash")
	cpanelCmd.Flags().StringP("user", "u", "", "user")
	cpanelCmd.Flags().BoolP("cpanel", "w", false, "is this a cpanel command")
	cpanelCmd.Flags().BoolP("insecure", "i", false, "use insecure connection")
}
