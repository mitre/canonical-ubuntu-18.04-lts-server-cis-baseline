# encoding: UTF-8

control "C-3.5.4.1.3" do
  title "Ensure outbound and established connections are configured"
  desc  "Configure the firewall rules for new outbound, and established
connections."
  desc  "rationale", "If rules are not in place for new outbound, and
established connections all packets will be dropped by the default policy
preventing network usage."
  desc  "check", "
    Run the following command and verify all rules for new outbound, and
established connections match site policy:

    ```
    # iptables -L -v -n
    ```
  "
  desc "fix", "
    Configure iptables in accordance with site policy. The following commands
will implement a policy to allow all outbound connections and all established
connections:

    ```
    # iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
    # iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
    # iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
    # iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
    # iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
    # iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
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
  tag cis_rid: "3.5.4.1.3"
end
