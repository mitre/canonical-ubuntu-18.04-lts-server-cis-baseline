# encoding: UTF-8

control "C-3.5.3.1" do
  title "Ensure iptables are flushed"
  desc  "nftables is a replacement for iptables, ip6tables, ebtables and
arptables"
  desc  "rationale", "It is possible to mix iptables and nftables. However,
this increases complexity and also the chance to introduce errors. For
simplicity flush out all iptables rules, and ensure it is not loaded"
  desc  "check", "
    Run the following commands to ensure no iptables rules exist

    For iptables:

    ```
    # iptables -L
    ```

    No rules shoulb be returned

    For ip6tables:

    ```
    # ip6tables -L
    ```

    No rules should be returned
  "
  desc  "fix", "
    Run the following commands to flush iptables:

    For iptables:

    ```
    # iptables -F
    ```

    For ip6tables

    ```
    # ip6tables -F
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
  tag cis_rid: "3.5.3.1"
end
