# encoding: UTF-8

control "C-3.2.7" do
  title "Ensure Reverse Path Filtering is enabled"
  desc  "Setting `net.ipv4.conf.all.rp_filter` and
`net.ipv4.conf.default.rp_filter` to 1 forces the Linux kernel to utilize
reverse path filtering on a received packet to determine if the packet was
valid. Essentially, with reverse path filtering, if the return packet does not
go out the same interface that the corresponding source packet came from, the
packet is dropped (and logged if `log_martians` is set)."
  desc  "rationale", "Setting these flags is a good way to deter attackers from
sending your system bogus packets that cannot be responded to. One instance
where this feature breaks down is if asymmetrical routing is employed. This
would occur when using dynamic routing protocols (bgp, ospf, etc) on your
system. If you are using asymmetrical routing on your system, you will not be
able to enable this feature without breaking the routing."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.conf.all.rp_filter

    net.ipv4.conf.all.rp_filter = 1
    ```

    ```
    # sysctl net.ipv4.conf.default.rp_filter

    net.ipv4.conf.default.rp_filter = 1
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.all\\.rp_filter\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.all.rp_filter = 1
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.default\\.rp_filter\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.default.rp_filter = 1
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.conf.all.rp_filter=1
    ```

    ```
    # sysctl -w net.ipv4.conf.default.rp_filter=1
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
  tag cis_rid: "3.2.7"

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should cmp '1' }
  end

  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should cmp '1' }
  end

end
