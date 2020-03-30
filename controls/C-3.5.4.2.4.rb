# encoding: UTF-8

control "C-3.5.4.2.4" do
  title "Ensure IPv6 firewall rules exist for all open ports"
  desc  "Any ports that have been opened on non-loopback addresses need
firewall rules to govern traffic."
  desc  "rationale", "Without a firewall rule configured for open ports default
firewall policy will drop all packets to these ports."
  desc  "check", "
    Run the following command to determine open ports:

    ```
    # ss -6tuln

    Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
    udp UNCONN 0 0 ::1:123 :::*
    udp UNCONN 0 0 :::123 :::*
    tcp LISTEN 0 128 :::22 :::*
    tcp LISTEN 0 20 ::1:25 :::*
    ```

    Run the following command to determine firewall rules:

    ```
    # ip6tables -L INPUT -v -n

    Chain INPUT (policy DROP 0 packets, 0 bytes)
     pkts bytes target prot opt in out source destination
     0 0 ACCEPT all lo * ::/0 ::/0
     0 0 DROP all * * ::1 ::/0
     0 0 ACCEPT tcp * * ::/0 ::/0 tcp dpt:22 state NEW
    ```

    Verify all open ports listening on non-localhost addresses have at least
one firewall rule.

    The last line identified by the \"tcp dpt:22 state NEW\" identifies it as a
firewall rule for new connections on tcp port 22.

    OR

    If IPv6 is disabled:

    Run the following command and verify that no lines are returned.

    ```
    # grep \"^\\s*linux\" /boot/grub2/grub.cfg | grep -v ipv6.disable=1
    ```

    OR

    ```
    # grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v ipv6.disable=1
    ```
  "
  desc  "fix", "
    For each port identified in the audit which does not have a firewall rule
establish a proper rule for accepting inbound connections:

    ```
    # ip6tables -A INPUT -p

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
  tag nist: ["SC-7(5)", "CM-8", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.4", "9.1", "Rev_7"]
  tag cis_rid: "3.5.4.2.4"
end
