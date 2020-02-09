![python status | Luiggy/shodan-seeker](https://github.com/Luiggy/shodan-seeker/workflows/Python%20application/badge.svg)

Shodan-Seeker
-------------

Command-line tool using Shodan API. Generates and downloads CSV results, diffing of historic scanning results, alerts and monitoring of specific ports/IPs, etc.


Wiki pages of tool documentation.

```
EXAMPLES:
  ./shodanseeker --si 'X.X.X.X X.X.X.X/24'                                   # Scan IPs/netblocks
  ./shodanseeker --sf 'pathfilename'                                         # Scan IPs/netblocks from a file
  ./shodanseeker -l                                                          # List previously submitted scans
  ./shodanseeker -i 'X.X.X.X X.X.X.X/24 Y.Y.Y.Y'                             # Get all information of IP/netblocks
  ./shodanseeker -f 'pathfilename'                                           # Get all information from a file of IPs/netblocks
  ./shodanseeker -i 'X.X.X.X' --history                                      # Get all historical banners
  ./shodanseeker -i 'X.X.X.X' --diff                                         # Detect new services published 
  ./shodanseeker -f 'pathfilename' [--history|--diff] --output csv           # Output results in csv format
  ./shodanseeker -i 'X.X.X.X' --diff --output csv --mail toaddr -a           # Send email with csv results attached
  ./shodanseeker --ca Name 'X.X.X.X X.X.X.X/24'                              # Create network alerts for the IP/netblock 
  ./shodanseeker --cf Name 'pathfilename'                                    # Create network alerts from file
  ./shodanseeker --la                                                        # List of all the network alerts activated on the account
  ./shodanseeker --da [alertid|all]                                          # Remove the specified network alert
  ./shodanseeker --subs [alertid|all] --monport '3389 22' [--mail toaddr]    # Subscribe to the Streaming and monitoring for high risk services
  ./shodanseeker --subs [alertid|all] --mondiff [--mail toaddr]              # Subscribe to the Streaming and monitoring for new services published
  ./shodanseeker --subs [alertid|all] --montag 'compromised' [--mail toaddr] # Subscribe to the Streaming and monitoring for tags (ex: compromised, doublepulsar, self-signed)
  ./shodanseeker --get [protocols|services|ports|tags]                       # List of (protocols,services,ports,tags) supported
```
