# encoding: UTF-8

control "C-3.2.3" do
  title "Ensure secure ICMP redirects are not accepted"
  desc  "Secure ICMP redirects are the same as ICMP redirects, except they come
from gateways listed on the default gateway list. It is assumed that these
gateways are known to your system, and that they are likely to be secure."
  desc  "rationale", "It is still possible for even known gateways to be
compromised. Setting `net.ipv4.conf.all.secure_redirects` to 0 protects the
system from routing table updates by possibly compromised known gateways."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.conf.all.secure_redirects

    net.ipv4.conf.all.secure_redirects = 0
    ```

    ```
    # sysctl net.ipv4.conf.default.secure_redirects

    net.ipv4.conf.default.secure_redirects = 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.all\\.secure_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.all.secure_redirects= 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.default\\.secure_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.default.secure_redirects= 0
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.conf.all.secure_redirects = 0
    net.ipv4.conf.default.secure_redirects = 0
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.conf.all.secure_redirects=0
    # sysctl -w net.ipv4.conf.default.secure_redirects=0
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
  tag cis_rid: "3.2.3"

  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should cmp '0' }
  end

end
