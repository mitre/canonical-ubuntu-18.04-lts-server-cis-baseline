# encoding: UTF-8

control "C-3.1.2" do
  title "Ensure IP forwarding is disabled"
  desc  "The `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding` flags are
used to tell the system whether it can forward packets or not."
  desc  "rationale", "Setting the flags to 0 ensures that a system with
multiple interfaces (for example, a hard proxy), will never be able to forward
packets, and therefore, never serve as a router."
  desc  "check", "
    Run the following command and verify output matches:

    ```
    # sysctl net.ipv4.ip_forward

    net.ipv4.ip_forward = 0
    ```

    ```
    # grep -E -s \"^\\s*net\\.ipv4\\.ip_forward\\s*=\\s*1\" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf

    No value should be returned
    ```

    ```
    # sysctl net.ipv6.conf.all.forwarding

    net.ipv6.conf.all.forwarding = 0
    ```

    ```
    # grep -E -s \"^\\s*net\\.ipv6\\.conf\\.all\\.forwarding\\s*=\\s*1\"
/etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf
/run/sysctl.d/*.conf

    No value should be returned
    ```
  "
  desc  "fix", "
    Run the following commands to restore the default parameters and set the
active kernel parameters:

    ```
    # grep -Els \"^\\s*net\\.ipv4\\.ip_forward\\s*=\\s*1\" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read
filename; do sed -ri
\"s/^\\s*(net\\.ipv4\\.ip_forward\\s*)(=)(\\s*\\S+\\b).*$/# *REMOVED* \\1/\"
$filename; done; sysctl -w net.ipv4.ip_forward=0; sysctl -w
net.ipv4.route.flush=1
    ```

    ```
    # grep -Els \"^\\s*net\\.ipv6\\.conf\\.all\\.forwarding\\s*=\\s*1\"
/etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf
/run/sysctl.d/*.conf | while read filename; do sed -ri
\"s/^\\s*(net\\.ipv6\\.conf\\.all\\.forwarding\\s*)(=)(\\s*\\S+\\b).*$/#
*REMOVED* \\1/\" $filename; done; sysctl -w net.ipv6.conf.all.forwarding=0;
sysctl -w net.ipv6.route.flush=1
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
  tag cis_rid: "3.1.2"

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should cmp '0' }
  end

  describe kernel_parameter('net.ipv6.conf.all.forwarding') do
    its('value') { should cmp '0' }
  end

end

