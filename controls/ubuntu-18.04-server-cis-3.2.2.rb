# encoding: UTF-8

control "C-3.2.2" do
  title "Ensure ICMP redirects are not accepted"
  desc  "ICMP redirect messages are packets that convey routing information and
tell your host (acting as a router) to send packets via an alternate path. It
is a way of allowing an outside routing device to update your system routing
tables. By setting `net.ipv4.conf.all.accept_redirects` and
`net.ipv6.conf.all.accept_redirects` to 0, the system will not accept any ICMP
redirect messages, and therefore, won't allow outsiders to update the system's
routing tables."
  desc  "rationale", "Attackers could use bogus ICMP redirect messages to
maliciously alter the system routing tables and get them to send packets to
incorrect networks and allow your system packets to be captured."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.conf.all.accept_redirects

    net.ipv4.conf.all.accept_redirects = 0
    ```

    ```
    # sysctl net.ipv4.conf.default.accept_redirects

    net.ipv4.conf.default.accept_redirects = 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.all\\.accept_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.all.accept_redirects= 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.default\\.accept_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.default.accept_redirects= 0
    ```

    ```
    # sysctl net.ipv6.conf.all.accept_redirects

    net.ipv6.conf.all.accept_redirects = 0
    ```

    ```
    # sysctl net.ipv6.conf.default.accept_redirects

    net.ipv6.conf.default.accept_redirects = 0
    ```

    ```
    # grep \"net\\.ipv6\\.conf\\.all\\.accept_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv6.conf.all.accept_redirects= 0
    ```

    ```
    # grep \"net\\.ipv6\\.conf\\.default\\.accept_redirects\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv6.conf.default.accept_redirects= 0
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.conf.all.accept_redirects = 0
    net.ipv4.conf.default.accept_redirects = 0
    net.ipv6.conf.all.accept_redirects = 0
    net.ipv6.conf.default.accept_redirects = 0
    ```
    Run the following commands to set the active kernel parameters:
    ```
    # sysctl -w net.ipv4.conf.all.accept_redirects=0
    # sysctl -w net.ipv4.conf.default.accept_redirects=0
    # sysctl -w net.ipv6.conf.all.accept_redirects=0
    # sysctl -w net.ipv6.conf.default.accept_redirects=0
    # sysctl -w net.ipv4.route.flush=1
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
  tag cis_rid: "3.2.2"

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv6.conf.all.accept_redirects') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
    its('value') { should cmp '0' }
  end

end
