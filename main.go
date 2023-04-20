package main

import (
	"fmt"
	"os"
	"time"
)

var HOST string = "https://ceremony.quilibrium.com:8443/"

func main() {
	PrintLogo()
	PrintVersion()

	ParseArgs()
}

func ParseArgs() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "verify-transcript":
			VerifyState()
			os.Exit(0)
		case "check-voucher":
			CheckVoucherInclusion(os.Args[2])
			os.Exit(0)
		default:
			break
		}
	}

	WaitForSequencerToBeReady()

	JoinLobby()
	Bootstrap()
	fmt.Println("New PoT Pubkey: ")
	fmt.Println(bcj.PotPubKey)
	fmt.Println()
	fmt.Println("Voucher Pubkey: ")
	fmt.Println(bcj.VoucherPubKey)
	ContributeAndGetVoucher()
}

func WaitForSequencerToBeReady() {
	spinnerChars := []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}
	spinnerIndex := 0
	attempts := 0
	removeLine := "\u001B[A\u001B[2K"
	state := GetSequencerState()
	for state != SEQUENCER_ACCEPTING {
		message := "Sequencer currently not accepting new contributions, waiting..."
		status := fmt.Sprintf("[Attempt %d - Last Checked: %s]", attempts, time.Now().String())

		fmt.Printf("\r%s", removeLine)
		fmt.Printf("%s\n", message+spinnerChars[spinnerIndex])
		fmt.Printf("  |- %s", status)

		spinnerIndex = (spinnerIndex + 1) % len(spinnerChars)
		attempts += 1

		time.Sleep(5 * time.Second)
		state = GetSequencerState()
	}

	fmt.Println()
	fmt.Println("Sequencer is ready for contributions!")
}

func PrintLogo() {
	fmt.Println()
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
	fmt.Println("                    Quilibrium Ceremony Client - CLI - v1.0.2")
	fmt.Println()
	fmt.Println()
}
