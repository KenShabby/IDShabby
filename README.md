*Project for Boot.dev's 2025 Hackathon*

**Plan from the start that's bound to change: Go based intrusion detection system.**

You will most likely need to run this as root to have monitoring access to your
network devices in promiscuous mode.

So far, I have the interface up and receiving packets. Output is being logged.
Nothing really interesting is happening until I work on the alerting system. As
the packet analysis is beyond my current level of knowledge, I'll probably have
to settle for just logging packets for this weekend project and expand on the
statistical analysis later.

Installation and running:
  - [Install go](https://go.dev/doc/install)
  - Clone this repo
  - `go run cmd/IDShabby/main.go` or if you need additional permissions:
  - `sudo go run cmd/IDShabby/main.go`

So far, output will go by default to STDOUT and logs/ids.json.

Next Steps:
  - Allow user to manually choose their interface from the command line or an 
    in app menu selection.
  - UI options to allow for logging/stdout for user chosen types. Default is ports
    22, 80, and 443.
