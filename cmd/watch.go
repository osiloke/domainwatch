// Copyright © 2016 NAME HERE <EMAIL ADDRESS>
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
	// "fmt"
	"github.com/osiloke/domainwatch/whois"
	"github.com/robfig/cron"
	"github.com/spf13/cobra"
	// "github.com/y0ssar1an/q"
	"log"
	"os"
	"os/signal"
)

var (
	url, key, name, schedule, csv string
)

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "watch domains from dostow store",
	Long:  `watch domains from dostow store`,
	Run: func(cmd *cobra.Command, args []string) {
		if schedule != "" {
			c := cron.New()
			if len(csv) > 0 {
				result, err := whois.ParseCSV(csv)
				if err == nil {
					whois.PrintWhoisResults(result)
				} else {
					println(err.Error())
				}
				if err := c.AddFunc(schedule, func() {
					result, err := whois.ParseCSV(csv)
					if err == nil {
						whois.PrintWhoisResults(result)
					} else {
						println(err.Error())
					}
				}); err != nil {
					// q.Q(err)
					log.Fatal(err)
					return
				}
			} else {
				if err := c.AddFunc(schedule, func() {
					whois.WatchDostow(url, key, name)
				}); err != nil {
					// q.Q(err)
					log.Fatal(err)
					return
				}
			}
			s := make(chan os.Signal, 1)
			signal.Notify(s, os.Interrupt)
			c.Start()
			defer c.Stop()
			println("running")
			for _ = range s {
				// sig is a ^C, handle it

				break
			}
			println("stopping")
		} else {
			if len(csv) > 0 {
				res, err := whois.ParseCSV(csv)
				if err != nil {
					ifpanic(err)
					return
				}

				whois.PrintWhoisResults(res)
				return
			}
			whois.WatchDostow(url, key, name)
		}
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// watchCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// watchCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	watchCmd.Flags().StringVarP(&url, "url", "u", "", "dostow url")
	watchCmd.Flags().StringVarP(&key, "key", "k", "", "dostow key")
	watchCmd.Flags().StringVarP(&name, "name", "n", "domains", "name")
	watchCmd.Flags().StringVarP(&schedule, "schedule", "s", "", "schedule the watch command at cron time")
	watchCmd.Flags().StringVarP(&csv, "csv", "c", "", "csv file")

}
