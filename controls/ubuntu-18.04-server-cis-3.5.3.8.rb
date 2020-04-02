# encoding: UTF-8

control "C-3.5.3.8" do
  title "Ensure nftables rules are permanent"
  desc  "nftables is a subsystem of the Linux kernel providing filtering and
classification of network packets/datagrams/frames.

    The nftables service reads the `/etc/sysconfig/nftables.conf` file for a
nftables file or files to include in the nftables ruleset.

    A nftables ruleset containing the input, forward, and output base chains
allow network traffic to be filtered.
  "
  desc  "rationale", "Changes made to nftables ruleset only affect the live
system, you will also need to configure the nftables ruleset to apply on boot"
  desc  "check", "
    Run the following commands to verify that input, forward, and output base
chains are configured to be applied to a nftables ruleset on boot:

    Run the following command to verify the input base chain:

    ```
    # awk '/hook input/,/}/' $(awk '$1 ~ /^\\s*include/ {
gsub(\"\\\"\",\"\",$2);print $2 }' /etc/sysconfig/nftables.conf)
    ```

    Output should be similar to:

    ```
     type filter hook input priority 0; policy drop;

     # Ensure loopback traffic is configured
     iif \"lo\" accept
     ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop
     ip6 saddr ::1 counter packets 0 bytes 0 drop

     # Ensure established connections are configured
     ip protocol tcp ct state established accept
     ip protocol udp ct state established accept
     ip protocol icmp ct state established accept

     # Accept port 22(SSH) traffic from anywhere
     tcp dport ssh accept

     # Accept ICMP and IGMP from anywhere
     icmpv6 type { destination-unreachable, packet-too-big, time-exceeded,
parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done,
nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert,
ind-neighbor-solicit, ind-neighbor-advert, mld2-listener-report } accept
    ```

    Note: Review the input base chain to ensure that it follows local site
policy

    Run the following command to verify the forward base chain:

    ```
    # awk '/hook forward/,/}/' $(awk '$1 ~ /^\\s*include/ {
gsub(\"\\\"\",\"\",$2);print $2 }' /etc/sysconfig/nftables.conf)
    ```

    Output should be similar to:

    ```
     # Base chain for hook forward named forward (Filters forwarded network
packets)
     chain forward {
     type filter hook forward priority 0; policy drop;
     }
    ```

    Note: Review the forward base chain to ensure that it follows local site
policy.

    Run the following command to verify the forward base chain:

    ```
    # awk '/hook output/,/}/' $(awk '$1 ~ /^\\s*include/ {
gsub(\"\\\"\",\"\",$2);print $2 }' /etc/sysconfig/nftables.conf)
    ```

    Output should be similar to:

    ```
     # Base chain for hook output named output (Filters outbound network
packets)
     chain output {
     type filter hook output priority 0; policy drop;
     # Ensure outbound and established connections are configured
     ip protocol tcp ct state established,related,new accept
     ip protocol tcp ct state established,related,new accept
     ip protocol udp ct state established,related,new accept
     ip protocol icmp ct state established,related,new accept
     }
    ```

    Note: Review the output base chain to ensure that it follows local site
policy.
  "
  desc "fix", "
    Edit the `/etc/sysconfig/nftables.conf` file and un-comment or add a line
with `include ` for each nftables file you want included in the nftables
ruleset on boot

    example:

    ```
    # vi /etc/sysconfig/nftables.conf
    ```

    Add the line:

    ```
    include \"/etc/nftables/nftables.rules\"
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
  tag nist: ["SC-7(5)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.4", "Rev_7"]
  tag cis_rid: "3.5.3.8"
end
