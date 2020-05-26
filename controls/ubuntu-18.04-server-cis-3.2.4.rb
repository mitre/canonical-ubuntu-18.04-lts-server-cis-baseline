# encoding: UTF-8

control "C-3.2.4" do
  title "Ensure suspicious packets are logged"
  desc  "When enabled, this feature logs packets with un-routable source
addresses to the kernel log."
  desc  "rationale", "Enabling this feature and logging these packets allows an
administrator to investigate the possibility that an attacker is sending
spoofed packets to their system."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl net.ipv4.conf.all.log_martians

    net.ipv4.conf.all.log_martians = 1
    ```

    ```
    # sysctl net.ipv4.conf.default.log_martians

    net.ipv4.conf.default.log_martians = 1
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.all\\.log_martians\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.all.log_martians = 1
    ```

    ```
    # grep \"net\\.ipv4\\.conf\\.default\\.log_martians\" /etc/sysctl.conf
/etc/sysctl.d/*

    net.ipv4.conf.default.log_martians = 1
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1
    ```

    Run the following commands to set the active kernel parameters:

    ```
    # sysctl -w net.ipv4.conf.all.log_martians=1
    # sysctl -w net.ipv4.conf.default.log_martians=1
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
  tag nist: ["AU-12", "AU-3", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.2", "6.3", "Rev_7"]
  tag cis_rid: "3.2.4"

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should cmp '1' }
  end

  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should cmp '1' }
  end

end
