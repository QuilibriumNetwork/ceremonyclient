package main

import (
	"fmt"
	"time"
)

var HOST string = "https://ceremony.quilibrium.com:8443/"

func main() {
	PrintLogo()
	PrintVersion()

	fmt.Println("Checking sequencer...")
	state := GetSequencerState()
	for state != SEQUENCER_ACCEPTING {
		fmt.Println("Sequencer currently not accepting new contributions, waiting...")
		time.Sleep(30 * time.Second)
		state = GetSequencerState()
	}

	JoinLobby()
	Bootstrap()
	fmt.Println("New Pubkey: ")
	fmt.Println(bcj.PotPubKey)
	ContributeAndGetVoucher()
}

func PrintLogo() {
	fmt.Println("                                   %#########")
	fmt.Println("                          #############################")
	fmt.Println("                    ########################################&")
	fmt.Println("                 ###############################################")
	fmt.Println("             &#####################%        %######################")
	fmt.Println("           #################                         #################")
	fmt.Println("         ###############                                 ###############")
	fmt.Println("       #############                                        ##############")
	fmt.Println("     #############                                             ############&")
	fmt.Println("    ############                                                 ############")
	fmt.Println("   ###########                     ##########                     &###########")
	fmt.Println("  ###########                    ##############                     ###########")
	fmt.Println(" ###########                     ##############                      ##########&")
	fmt.Println(" ##########                      ##############                       ##########")
	fmt.Println("%##########                        ##########                         ##########")
	fmt.Println("##########&                                                           ##########")
	fmt.Println("##########                                                            &#########")
	fmt.Println("##########&                   #######      #######                    ##########")
	fmt.Println(" ##########                &#########################                 ##########")
	fmt.Println(" ##########              ##############% ##############              &##########")
	fmt.Println(" %##########          &##############      ###############           ##########")
	fmt.Println("  ###########       ###############           ##############%       ###########")
	fmt.Println("   ###########&       ##########                ###############       ########")
	fmt.Println("    ############         #####                     ##############%       ####")
	fmt.Println("      ############                                   ###############")
	fmt.Println("       ##############                                   ##############%")
	fmt.Println("         ###############                                  ###############")
	fmt.Println("           #################&                                ##############%")
	fmt.Println("              #########################&&&#############        ###############")
	fmt.Println("                 ########################################%        ############")
	fmt.Println("                     #######################################        ########")
	fmt.Println("                          #############################                ##")
}

func PrintVersion() {
	fmt.Println(" ")
	fmt.Println("                    Quilibrium Ceremony Client - CLI - v1.0.1")
}
