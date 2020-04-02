# encoding: UTF-8

control "C-3.6" do
  title "Ensure wireless interfaces are disabled"
  desc  "Wireless networking is used when wired networks are unavailable.
Ubuntu contains a wireless tool kit to allow system administrators to configure
and use wireless networks."
  desc  "rationale", "If wireless is not to be used, wireless devices can be
disabled to reduce the potential attack surface."
  desc  "check", "
    Run the following command to verify no wireless interfaces are active on
the system:

    ```
    # nmcli radio all
    ```

    Output should be similar to:

    ```
    WIFI-HW WIFI WWAN-HW WWAN
    enabled disabled enabled disabled
    ```
  "
  desc  "fix", "
    Run the following command to disable any wireless interfaces:

    ```
    # nmcli radio all off
    ```

    Disable any wireless interfaces in your network configuration.less
interfaces in your network configuration.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-7", "CM-7", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["15.4", "15.5", "Rev_7"]
  tag cis_rid: "3.6"
end
