# parse-beacon-logs

Python script to process Cobalt Strike beacon logs for execution of specifica commands, then aggregate logged output across multiple days on a per-callback-IP/host basis. Script must be run in a directory containing a 'logs' subdir from a Cobalt Strike Team Server. No input parameters.

In English: Gives a consolidated log of every time specific commands were run on a given host throughout an engagement. Helpful for conversations with Blue Teams!

## Functionality
- provides a timestamped list of all initial beacons extracted from events.log files
- prompts user to provide a comma-delimited list of hostnames of interest
- identifies all callback IP addresses associated with the specified hostnames and their corresponding beacon_dddddddddd.log files
- outputs two files:
  1. extracted events of specified type (currently configured for: run, execute-assembly, socks, upload, mkdir) sorted chronologically since these lines are all timestamped.
  2. all log files for a given host concatenated so context can be gleaned around a given command. The full output list is NOT chronologically sorted.
