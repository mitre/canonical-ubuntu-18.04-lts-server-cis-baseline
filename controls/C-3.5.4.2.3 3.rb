# encoding: UTF-8

control "C-3.5.4.2.3" do
  title "Ensure IPv6 outbound and established connections are configured"
  desc  "Configure the firewall rules for new outbound, and established IPv6
connections."
  desc  "rationale", "If rules are not in place for new outbound, and
established connections all packets will be dropped by the default policy
preventing network usage."
  desc  "check", "
    Run the following command and verify all rules for new outbound, and
established connections match site policy:

    ```
    # ip6tables -L -v -n
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
  desc "fix", "
    Configure iptables in accordance with site policy. The following commands
will implement a policy to allow all outbound connections and all established
connections:

    ```
    # ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
    # ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
    # ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
    # ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
    # ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
    # ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
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
  tag cis_rid: "3.5.4.2.3"
end
