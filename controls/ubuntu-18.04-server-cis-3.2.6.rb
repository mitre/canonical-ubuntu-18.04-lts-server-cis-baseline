# encoding: UTF-8

control "C-3.2.6" do
  title "Ensure bogus ICMP responses are ignored"
  desc  "Setting `icmp_ignore_bogus_error_responses` to 1 prevents the kernel
from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes,
keeping file systems from filling up with useless log messages."
  desc  "rationale", "Some routers (and some attackers) will send responses
that violate RFC-1122 and attempt to fill up a log file system with many
useless error messages."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.icmp_ignore_bogus_error_responses

    net.ipv4.icmp_ignore_bogus_error_responses = 1
    ```

    ```
    # grep \"net.ipv4.icmp_ignore_bogus_error_responses\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.icmp_ignore_bogus_error_responses = 1
    ```
  "
  desc  "fix", "
    Set the following parameter in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.icmp_ignore_bogus_error_responses = 1
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    ```

    ```
    # sysctl -w net.ipv4.route.flush=1
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
  tag cis_rid: "3.2.6"

  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should cmp '1' }
  end

end
