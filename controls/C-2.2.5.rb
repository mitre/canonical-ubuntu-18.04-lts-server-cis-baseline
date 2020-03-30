# encoding: UTF-8

control "C-2.2.5" do
  title "Ensure DHCP Server is not enabled"
  desc  "The Dynamic Host Configuration Protocol (DHCP) is a service that
allows machines to be dynamically assigned IP addresses."
  desc  "rationale", "Unless a system is specifically set up to act as a DHCP
server, it is recommended that this service be deleted to reduce the potential
attack surface."
  desc  "check", "
    Run the following commands to verify `dhcpd` is not enabled:

    ```
    # systemctl is-enabled isc-dhcp-server

    disabled
    ```

    ```
    # systemctl is-enabled isc-dhcp-server6

    disabled
    ```

    Verify results are not `enabled`.
  "
  desc  "fix", "
    Run one of the following commands to disable `dhcpd`:

    ```
    # systemctl --now disable isc-dhcp-server
    ```

    ```
    # systemctl --now disable isc-dhcp-server6
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
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "2.2.5"
end
