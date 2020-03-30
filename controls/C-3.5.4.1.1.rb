# encoding: UTF-8

control "C-3.5.4.1.1" do
  title "Ensure default deny firewall policy"
  desc  "A default deny all policy on connections ensures that any unconfigured
network usage will be rejected."
  desc  "rationale", "With a default accept policy the firewall will accept any
packet that is not configured to be denied. It is easier to white list
acceptable usage than to black list unacceptable usage."
  desc  "check", "
    Run the following command and verify that the policy for the `INPUT` ,
`OUTPUT` , and `FORWARD` chains is `DROP` or `REJECT` :

    ```
    # iptables -L
    Chain INPUT (policy DROP)
    Chain FORWARD (policy DROP)
    Chain OUTPUT (policy DROP)
    ```
  "
  desc  "fix", "
    Run the following commands to implement a default DROP policy:

    ```
    # iptables -P INPUT DROP
    # iptables -P OUTPUT DROP
    # iptables -P FORWARD DROP
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
  tag cis_rid: "3.5.4.1.1"
end
