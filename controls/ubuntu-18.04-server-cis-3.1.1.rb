# encoding: UTF-8

control "C-3.1.1" do
  title "Ensure packet redirect sending is disabled"
  desc  "ICMP Redirects are used to send routing information to other hosts. As
a host itself does not act as a router (in a host only configuration), there is
no need to send redirects."
  desc  "rationale", "An attacker could use a compromised host to send invalid
ICMP redirects to other router devices in an attempt to corrupt routing and
have users access a system set up by the attacker as opposed to a valid system."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.conf.all.send_redirects
    net.ipv4.conf.all.send_redirects = 0
    ```

    ```
    # sysctl net.ipv4.conf.default.send_redirects
    net.ipv4.conf.default.send_redirects = 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.all\\.send_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*
    net.ipv4.conf.all.send_redirects = 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.default\\.send_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*
    net.ipv4.conf.default.send_redirects= 0
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.conf.all.send_redirects=0
    # sysctl -w net.ipv4.conf.default.send_redirects=0
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
  tag cis_rid: "3.1.1"


  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should cmp '0' }
  end

end
