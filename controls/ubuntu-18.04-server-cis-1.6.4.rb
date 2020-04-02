# encoding: UTF-8

control "C-1.6.4" do
  title "Ensure core dumps are restricted"
  desc  "A core dump is the memory of an executable program. It is generally
used to determine why a program aborted. It can also be used to glean
confidential information from a core file. The system provides the ability to
set a soft limit for core dumps, but this can be overridden by the user."
  desc  "rationale", "Setting a hard limit on core dumps prevents users from
overriding the soft variable. If core dumps are required, consider setting
limits for user groups (see `limits.conf(5)` ). In addition, setting the
`fs.suid_dumpable` variable to 0 will prevent setuid programs from dumping
core."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # grep \"hard core\" /etc/security/limits.conf /etc/security/limits.d/*

    * hard core 0
    ```

    ```
    # sysctl fs.suid_dumpable

    fs.suid_dumpable = 0
    ```

    ```
    # grep \"fs\\.suid_dumpable\" /etc/sysctl.conf /etc/sysctl.d/*

    fs.suid_dumpable = 0
    ```

    Run the following command to check if systemd-coredump is installed:

    ```
    # systemctl is-enabled coredump.service
    ```

    if `enabled` or `disabled` is returned systemd-coredump is installed
  "
  desc  "fix", "
    Add the following line to `/etc/security/limits.conf` or a
`/etc/security/limits.d/*` file:

    ```
    * hard core 0
    ```

    Set the following parameter in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    fs.suid_dumpable = 0
    ```

    Run the following command to set the active kernel parameter:

    ```
    # sysctl -w fs.suid_dumpable=0
    ```

    If systemd-coredump is installed:

    edit `/etc/systemd/coredump.conf` and add/modify the following lines:

    ```
    Storage=none
    ProcessSizeMax=0
    ```

    Run the command:

    ```
    systemctl daemon-reload
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
  tag cis_rid: "1.6.4"


  describe package('systemd-coredump') do
    it { should_not be_installed }
  end

  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should cmp 0 }
  end

end
