# encoding: UTF-8

control "C-4.2.1.6" do
  title "Ensure remote rsyslog messages are only accepted on designated log
hosts."
  desc  "By default, `rsyslog` does not listen for log messages coming in from
remote systems. The `ModLoad` tells `rsyslog` to load the `imtcp.so` module so
it can listen over a network via TCP. The `InputTCPServerRun` option instructs
`rsyslogd` to listen on the specified TCP port."
  desc  "rationale", "The guidance in the section ensures that remote log hosts
are configured to only accept `rsyslog` data from hosts within the specified
domain and that those systems that are not designed to be log hosts do not
accept any remote `rsyslog` messages. This provides protection from spoofed log
data and ensures that system administrators are reviewing reasonably complete
syslog data in a central location."
  desc  "check", "
    Run the following commands and verify the resulting lines are uncommented
on designated log hosts and commented or removed on all others:

    ```
    # grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

    $ModLoad imtcp
    ```

    ```
    # grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

    $InputTCPServerRun 514
    ```
  "
  desc  "fix", "
    For hosts that are designated as log hosts, edit the `/etc/rsyslog.conf`
file and un-comment or add the following lines:

    ```
    $ModLoad imtcp

    $InputTCPServerRun 514
    ```

    For hosts that are not designated as log hosts, edit the
`/etc/rsyslog.conf` file and comment or remove the following lines:

    ```
    # $ModLoad imtcp

    # $InputTCPServerRun 514
    ```

    Run the following command to reload the `rsyslogd` configuration:

    ```
    # systemctl restart rsyslog
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
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "4.2.1.6"
end
