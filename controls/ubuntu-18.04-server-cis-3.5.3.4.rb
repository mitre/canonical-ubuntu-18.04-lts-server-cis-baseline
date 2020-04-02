# encoding: UTF-8

control "C-3.5.3.4" do
  title "Ensure loopback traffic is configured"
  desc  "Configure the loopback interface to accept traffic. Configure all
other interfaces to deny traffic to the loopback network"
  desc  "rationale", "Loopback traffic is generated between processes on
machine and is typically critical to operation of the system. The loopback
interface is the only place that loopback network traffic should be seen, all
other interfaces should ignore traffic on this network as an anti-spoofing
measure."
  desc  "check", "
    Run the following commands to verify that the loopback interface is
configured:

    ```
    # nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept'

    iif \"lo\" accept
    ```

    ```
    # nft list ruleset | awk '/hook input/,/}/' | grep 'ip sddr'

    ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop
    ```

    ```
    # nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'

    ip6 saddr ::1 counter packets 0 bytes 0 drop
    ```
  "
  desc  "fix", "
    Run the following commands to implement the loopback rules:

    ```
    # nft add rule inet filter input iif lo accept
    ```

    ```
    # nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop
    ```

    ```
    # nft add rule inet filter input ip6 saddr ::1 counter drop
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
  tag cis_rid: "3.5.3.4"
end
