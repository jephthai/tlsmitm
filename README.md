tlsmitm
=======

TLS relay / proxy for analyzing contents of TLS-protected network communications.  This isn't intended to supersede other excellent tools, such as Burp Suite.  All tools have their place, but sometimes you want complete control.  For example, Burp Suite is just for HTTPS, so if you are looking at something that uses another protocol over TLS, then it won't be so helpful.

This is a generic TLS relay.  It has the following main features:

  1. Output all traffic to a file
  2. Multiple relayed sessions supported at the same time
  3. Pretty small code base so it can be adapted in the wild as needed
  4. "render.js" gives you the essentials for exploring the data
  5. Ultimately, you can read it as a hex dump if you prefer

Running it
==========

To run the relay, just do the following:

    $ node tlsmitm.js <lport> <rhost> <rport>

This will bind to the LPORT parameter, and send any inbound connections off to the RHOST parameter on port RPORT.  The listening service on LPORT will negotiate TLS and the outbound connections to RHOST:RPORT will do the same.  The output will appear in "output.dat" (for now -- it's not too sophisticated at this time).

Viewing Results
===============

The program stores the processed data in "output.dat" in a binary format.  It's pretty simple, reminiscent of a PCAP.  A simple binary header precedes each message that came in on layer 7 either from the client or the server.  You can use the "render.js" program to view the output:

    $ node render.js
    
      usage: render.js <filename> <cmd> [args]
    
        stats            Show summary stats for input file
        session S        Show list of messages in session S
        message S M      Show message M in session S as UTF-8
        conversation S   Show both sides as UTF-8 from session S
