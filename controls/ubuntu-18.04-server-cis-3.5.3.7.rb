# encoding: UTF-8

control "C-3.5.3.7" do
  title "Ensure nftables service is enabled"
  desc  "The nftables service allows for the loading of nftables rulesets
during boot, or starting on the nftables service"
  desc  "rationale", "The nftables service restores the nftables rules from the
rules files referenced in the `/etc/sysconfig/nftables.conf` file durring boot
or the starting of the nftables service"
  desc  "check", "
    Run the following command and verify that the nftables service is enabled:

    ```
    # systemctl is-enabled nftables

    enabled
    ```
  "
  desc  "fix", "
    Run the following command to enable the nftables service:

    ```
    # systemctl enable nftables
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
  tag cis_rid: "3.5.3.7"
end
