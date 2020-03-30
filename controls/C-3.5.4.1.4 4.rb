# encoding: UTF-8

control "C-3.5.4.1.4" do
  title "Ensure firewall rules exist for all open ports"
  desc  "Any ports that have been opened on non-loopback addresses need
firewall rules to govern traffic."
  desc  "rationale", "Without a firewall rule configured for open ports default
firewall policy will drop all packets to these ports."
  desc  "check", "
    Run the following command to determine open ports:

    ```
    # ss -4tuln

    Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
    udp UNCONN 0 0 *:68 *:*
    udp UNCONN 0 0 *:123 *:*
    tcp LISTEN 0 128 *:22 *:*
    ```

    Run the following command to determine firewall rules:

    ```
    # iptables -L INPUT -v -n
    Chain INPUT (policy DROP 0 packets, 0 bytes)
     pkts bytes target prot opt in out source destination
     0 0 ACCEPT all -- lo * 0.0.0.0/0 0.0.0.0/0
     0 0 DROP all -- * * 127.0.0.0/8 0.0.0.0/0
     0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22 state NEW

    ```

    Verify all open ports listening on non-localhost addresses have at least
one firewall rule.

    The last line identified by the \"tcp dpt:22 state NEW\" identifies it as a
firewall rule for new connections on tcp port 22.
  "
  desc  "fix", "
    For each port identified in the audit which does not have a firewall rule
establish a proper rule for accepting inbound connections:

    ```
    # iptables -A INPUT -p

    \t --dport

    \t -m state --state NEW -j ACCEPT
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-7 (1)", "SC-7(5)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.2", "9.4", "Rev_7"]
  tag cis_rid: "3.5.4.1.4"
end
