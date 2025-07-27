*Project for Boot.dev's 2025 Hackathon*

**Plan from the start that's bound to change: Go based intrusion detection system.**

You will most likely need to run this as root to have monitoring access to your
network devices in promiscuous mode.

So far, I have the interface up and receiving packets. Output is being logged.
Nothing really interesting is happening until I work on the alerting system.

Next Steps:
  - Allow user to manually choose their interface from the command line or an 
    in app menu selection.
  - UI options to allow for logging/stdout for user chosen types. Default is ports
    22, 80, and 443.
