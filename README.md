# ErroxNetwork

ErroxNetwork is a work in progress collection of scripts that work to scan, monitor, intercept, and scan devices on networks. It is a whole revamp of Errox_8 and Errox_9. Below are comparisons of each script and changes in ErroxNetwork.

## Errox_9 (version 1.3) to network_scanner

While Errox_9 (Errox_9.sh version 1.3) was a decent script for being an intro to the world outside of being another skid on the internet, it had limitations. Below are the issues I found with Errox_9:

  0) Opens several instances of the same bash script running scans with no regard for system resources
  1) Heigh overhead for other flavors of Linux or Unix based systems due to certain commands being needed
  2) Very noisy on a network and will get flagged instantly
  3) Requires user input and monitoring
  4) No network monitoring
  5) Requires a temporary file for values to be saved
  6) Tries to connect to each host instead of using networking protocols

See, lots of issues. And most of those issues are due to the language that it was written in was Bash, a great shell scripting language but horrible for anything else. Below is how network_scanner.py fixed these issues:

  0) Does not rely on parallelism to have fast scans
  1) Uses one package that is not avaliable in base Python
  2) Tries to mask scans as normal trafic from an end device
  3) Has a custom API for scans and monitoring
  4) Has network monitoring (in development)
  5) Saves all results inside of the program's memory, no external file for storage needed
  6) Uses network protocols to efficiently scan for hosts

Well, that all sounds good. But what does it really mean? Well, first the language has swapped from Bash to Python, one of the main issues and limitations of Errox_9 was that it was programmed inside of Bash instead of a decent language (I still love bash). Also, instead of trying to find hosts by pinging them or arpinging them, network_scanner instead will use ARP and ICMP crafted packets to scan for devices.

## Errox_8 (version 2) to host_scanner

Now, I know that with the release of Errox_8_V2.py (Errox_8) two months ago, it was assumed that my grubby little hands wouldn't touch it for another five at least! But that is where both you and I are wrong. There are several flaws with Errox_8, those are listed below:

  0) Only one method of scanning ports
  1) Attempts to fully complete a TCP handshake to connect to a port
  2) Can only scan for TCP ports and connections
  3) No API or ability to be used in other scripts / projects
  4) Needs input from the user to execute correctly
  5) No fingerprinting

Wow, that's alot wrong. Like, really. That is alot. Even the first version of Errox_8 could do some basic fingerprinting. But now, here is how host_scanner surpasses Errox_8:

  0) Has three methods of scanning, two for TCP and one for UDP
  1) When doing a TCP scan can either do a SYN or ACK scan to try and get a response from the server without fully connecting
  2) Has the ability to scan for UDP ports
  3) Has a built in API that allows it to be used in other scripts or projects
  4) Has an API for user input, rather than having the user inside of a terminal watching the screen flicker, the API is to be called inside of a script
  5) Can do pasive OS detection (in development)

So, id say that both scripts have beaten their predecessors.

## Usage

The scripts 'host_scanner' and 'network_scanner' are very easy to use and were developed with users in mind! Simply import them into a project to then have access to their API! An example is below:

    import network_scanner

    network = network_scanner.ErroxNetwork()
    network.get_default_gateway()
    network.get_network_subnetmask()
    network.get_network_address()
The API will handle all network interactions for you! If you want to know more information about each method inside of the API, I would highly suggest reading the comments I left for users to read.
