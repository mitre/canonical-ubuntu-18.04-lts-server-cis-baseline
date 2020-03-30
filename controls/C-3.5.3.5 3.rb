# encoding: UTF-8

control "C-3.5.3.5" do
  title "Ensure outbound and established connections are configured"
  desc  "Configure the firewall rules for new outbound, and established
connections"
  desc  "rationale", "If rules are not in place for new outbound, and
established connections all packets will be dropped by the default policy
preventing network usage."
  desc  "check", "
    Run the following commands and verify all rules for established incoming
connections match site policy: site policy:

    ```
    # nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol
(tcp|udp|icmp) ct state'
    ```

    Output should be similar to:

    ```
    ip protocol tcp ct state established accept
    ip protocol udp ct state established accept
    ip protocol icmp ct state established accept
    ```

    Run the folllowing command and verify all rules for new and established
outbound connections match site policy

    ```
    # nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol
(tcp|udp|icmp) ct state'
    ```

    Output should be similar to:

    ```
    ip protocol tcp ct state established,related,new accept
    ip protocol udp ct state established,related,new accept
    ip protocol icmp ct state established,related,new accept
    ```
  "
  desc "fix", "
    Configure nftables in accordance with site policy. The following commands
will implement a policy to allow all outbound connections and all established
connections:

    ```
    # nft add rule inet filter input ip protocol tcp ct state established accept

    # nft add rule inet filter input ip protocol udp ct state established accept

    # nft add rule inet filter input ip protocol icmp ct state established
accept

    # nft add rule inet filter output ip protocol tcp ct state
new,related,established accept

    # nft add rule inet filter output ip protocol udp ct state
new,related,established accept

    # nft add rule inet filter output ip protocol icmp ct state
new,related,established accept
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
  tag cis_rid: "3.5.3.5"
end
