# encoding: UTF-8

control "C-3.5.4.1.2" do
  title "Ensure loopback traffic is configured"
  desc  "Configure the loopback interface to accept traffic. Configure all
other interfaces to deny traffic to the loopback network (127.0.0.0/8)."
  desc  "rationale", "Loopback traffic is generated between processes on
machine and is typically critical to operation of the system. The loopback
interface is the only place that loopback network (127.0.0.0/8) traffic should
be seen, all other interfaces should ignore traffic on this network as an
anti-spoofing measure."
  desc  "check", "
    Run the following commands and verify output includes the listed rules in
order (packet and byte counts may differ):

    ```
    # iptables -L INPUT -v -n
    Chain INPUT (policy DROP 0 packets, 0 bytes)
     pkts bytes target prot opt in out source destination
     0 0 ACCEPT all -- lo * 0.0.0.0/0 0.0.0.0/0
     0 0 DROP all -- * * 127.0.0.0/8 0.0.0.0/0

     # iptables -L OUTPUT -v -n
    Chain OUTPUT (policy DROP 0 packets, 0 bytes)
     pkts bytes target prot opt in out source destination
     0 0 ACCEPT all -- * lo 0.0.0.0/0 0.0.0.0/0
    ```
  "
  desc  "fix", "
    Run the following commands to implement the loopback rules:

    ```
    # iptables -A INPUT -i lo -j ACCEPT
    # iptables -A OUTPUT -o lo -j ACCEPT
    # iptables -A INPUT -s 127.0.0.0/8 -j DROP
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
  tag cis_rid: "3.5.4.1.2"
end
