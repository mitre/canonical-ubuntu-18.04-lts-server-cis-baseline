# encoding: UTF-8

control "C-3.2.9" do
  title "Ensure IPv6 router advertisements are not accepted"
  desc  "This setting disables the system's ability to accept IPv6 router
advertisements."
  desc  "rationale", "It is recommended that systems do not accept router
advertisements as they could be tricked into routing traffic to compromised
machines. Setting hard routes within the system (usually a single default route
to a trusted router) protects the system from bad routes."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv6.conf.all.accept_ra

    net.ipv6.conf.all.accept_ra = 0
    ```

    ```
    # sysctl net.ipv6.conf.default.accept_ra

    net.ipv6.conf.default.accept_ra = 0
    ```

    ```
    # grep \"net\\.ipv6\\.conf\\.all\\.accept_ra\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv6.conf.all.accept_ra = 0
    ```

    ```
    # grep \"net\\.ipv6\\.conf\\.default\\.accept_ra\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv6.conf.default.accept_ra = 0
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv6.conf.all.accept_ra = 0
    net.ipv6.conf.default.accept_ra = 0
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv6.conf.all.accept_ra=0
    ```

    ```
    # sysctl -w net.ipv6.conf.default.accept_ra=0
    ```

    ```
    # sysctl -w net.ipv6.route.flush=1
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
  tag cis_rid: "3.2.9"

  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
    its('value') { should cmp '0' }
  end

end

