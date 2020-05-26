# encoding: UTF-8

control "C-3.2.1" do
  title "Ensure source routed packets are not accepted"
  desc  "In networking, source routing allows a sender to partially or fully
specify the route packets take through a network. In contrast, non-source
routed packets travel a path determined by routers in the network. In some
cases, systems may not be routable or reachable from some locations (e.g.
private addresses vs. Internet routable), and so source routed packets would
need to be used."
  desc  "rationale", "Setting `net.ipv4.conf.all.accept_source_route,
net.ipv4.conf.default.accept_source_route,
net.ipv6.conf.all.accept_source_route and
net.ipv6.conf.default.accept_source_route` to 0 disables the system from
accepting source routed packets. Assume this system was capable of routing
packets to Internet routable addresses on one interface and private addresses
on another interface. Assume that the private addresses were not routable to
the Internet routable addresses and vice versa. Under normal routing
circumstances, an attacker from the Internet routable addresses could not use
the system as a way to reach the private address systems. If, however, source
routed packets were allowed, they could be used to gain access to the private
address systems as the route could be specified, rather than rely on routing
protocols that did not allow this routing."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.conf.all.accept_source_route

    net.ipv4.conf.all.accept_source_route = 0
    ```

    ```
    # sysctl net.ipv4.conf.default.accept_source_route

    net.ipv4.conf.default.accept_source_route = 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.all\\.accept_source_route\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.all.accept_source_route= 0
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.default\\.accept_source_route\"
/etc/sysctl.conf /etc/sysctl.d/*

    net.ipv4.conf.default.accept_source_route= 0
    ```

    ```
    # sysctl net.ipv6.conf.all.accept_source_route

    net.ipv6.conf.all.accept_source_route = 0
    ```

    ```
    # sysctl net.ipv6.conf.default.accept_source_route

    net.ipv6.conf.default.accept_source_route = 0
    ```

    ```
    # grep \"net\\.ipv6\\.conf\\.all\\.accept_source_route\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.all.accept_source_route= 0
    ```

    ```
    # grep \"net\\.ipv6\\.conf\\.default\\.accept_source_route\"
/etc/sysctl.conf /etc/sysctl.d/*

    net.ipv6.conf.default.accept_source_route= 0
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    net.ipv6.conf.all.accept_source_route = 0
    net.ipv6.conf.default.accept_source_route = 0
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.conf.all.accept_source_route=0
    # sysctl -w net.ipv4.conf.default.accept_source_route=0
    # sysctl -w net.ipv6.conf.all.accept_source_route=0
    # sysctl -w net.ipv6.conf.default.accept_source_route=0
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
  tag cis_rid: "3.2.1"

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_source_route') do
    its('value') { should cmp '0' }
  end

end
