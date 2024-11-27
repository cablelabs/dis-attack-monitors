# DDoS Information Sharing (DIS) Attack Monitors

This repository contains the source code for the CableLabs Distributed Denial of Service Information Sharing project's attack monitors and associated tools.

There are currently two monitors - both of which are intended to run within a network operations center.

1) The DIS Arbor Monitor - which currently supports the upload of DDoS attack source IPs and metadata to the DIS backend to inform the owners of the attack source IPs for the purposes of source-based mitigation.
2) The DIS HIVE Monitor - which currently supports the cross-referencing of forged attack metadata with local netflow using either the NetScout/Arbor forensics API or NetFlow stored in an SQL DB using the nfacctdb SQL schema.

Details on each of these can be found in the subdirectory README files.