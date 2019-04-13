// This file is part of ezBastion.

//     ezBastion is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.

//     ezBastion is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.

//     You should have received a copy of the GNU Affero General Public License
//     along with ezBastion.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"ezb_vault/setup"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli"
	"golang.org/x/sys/windows/svc"
)

func main() {

	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
	}
	if !isIntSess {
		conf, err := setup.CheckConfig(false)
		if err == nil {
			runService(conf.ServiceName, false)
		}
		return
	}
	app := cli.NewApp()
	app.Name = "ezb_vault"
	app.Version = "0.1.0-rc1"
	app.Usage = "Manage ezBastion key/value vault storage."

	app.Commands = []cli.Command{
		{
			Name:  "init",
			Usage: "Genarate config file.",
			Action: func(c *cli.Context) error {
				err := setup.Setup(true)
				return err
			},
		}, {
			Name:  "debug",
			Usage: "Start ezb_vault in console.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				runService(conf.ServiceName, true)
				return nil
			},
		}, {
			Name:  "install",
			Usage: "Add ezb_vault deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return installService(conf.ServiceName, conf.ServiceFullName)
			},
		}, {
			Name:  "remove",
			Usage: "Remove ezb_vault deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return removeService(conf.ServiceName)
			},
		}, {
			Name:  "start",
			Usage: "Start ezb_vault deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return startService(conf.ServiceName)
			},
		}, {
			Name:  "stop",
			Usage: "Stop ezb_vault deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return controlService(conf.ServiceName, svc.Stop, svc.Stopped)
			},
		},
	}

	cli.AppHelpTemplate = fmt.Sprintf(`
		
		███████╗███████╗██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗
		██╔════╝╚══███╔╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
		█████╗    ███╔╝ ██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║
		██╔══╝   ███╔╝  ██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║
		███████╗███████╗██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║
		╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
																			   
						██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗               
						██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝               
						██║   ██║███████║██║   ██║██║     ██║                  
						╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║                  
						 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║                  
						  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝                  
																			  
%s
INFO:
		http://www.ezbastion.com		
		support@ezbastion.com
		`, cli.AppHelpTemplate)
	app.Run(os.Args)
}
