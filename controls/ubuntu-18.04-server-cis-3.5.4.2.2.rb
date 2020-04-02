# encoding: UTF-8

control "C-3.5.4.2.2" do
  title "Ensure IPv6 loopback traffic is configured"
  desc  "Configure the loopback interface to accept traffic. Configure all
other interfaces to deny traffic to the loopback network (::1)."
  desc  "rationale", "Loopback traffic is generated between processes on
machine and is typically critical to operation of the system. The loopback
interface is the only place that loopback network (::1) traffic should be seen,
all other interfaces should ignore traffic on this network as an anti-spoofing
measure."
  desc  "check", "
    Run the following commands and verify output includes the listed rules in
order (packet and byte counts may differ):

    ```
    # ip6tables -L INPUT -v -n
    Chain INPUT (policy DROP 0 packets, 0 bytes)
    pkts bytes target prot opt in out source destination
     0 0 ACCEPT all lo * ::/0 ::/0
     0 0 DROP all * * ::1 ::/0

    # ip6tables -L OUTPUT -v -n
    Chain OUTPUT (policy DROP 0 packets, 0 bytes)
    pkts bytes target prot opt in out source destination
     0 0 ACCEPT all * lo ::/0 ::/0
    ```

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
    Run the following commands to implement the loopback rules:

    ```
    # ip6tables -A INPUT -i lo -j ACCEPT
    # ip6tables -A OUTPUT -o lo -j ACCEPT
    # ip6tables -A INPUT -s ::1 -j DROP
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
  tag cis_rid: "3.5.4.2.2"
end
