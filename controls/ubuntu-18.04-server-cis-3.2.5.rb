# encoding: UTF-8

control "C-3.2.5" do
  title "Ensure broadcast ICMP requests are ignored"
  desc  "Setting `net.ipv4.icmp_echo_ignore_broadcasts` to 1 will cause the
system to ignore all ICMP echo and timestamp requests to broadcast and
multicast addresses."
  desc  "rationale", "Accepting ICMP echo and timestamp requests with broadcast
or multicast destinations for your network could be used to trick your host
into starting (or participating) in a Smurf attack. A Smurf attack relies on an
attacker sending large amounts of ICMP broadcast messages with a spoofed source
address. All hosts receiving this message and responding would send echo-reply
messages back to the spoofed address, which is probably not routable. If many
hosts respond to the packets, the amount of traffic on the network could be
significantly multiplied."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.icmp_echo_ignore_broadcasts

    net.ipv4.icmp_echo_ignore_broadcasts = 1
    ```

    ```
    # grep \"net\\.ipv4\\.icmp_echo_ignore_broadcasts\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.icmp_echo_ignore_broadcasts = 1
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.icmp_echo_ignore_broadcasts = 1
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
    ```

    ```
    # sysctl -w net.ipv4.route.flush=1
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
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "3.2.5"

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should cmp '1' }
  end

end
