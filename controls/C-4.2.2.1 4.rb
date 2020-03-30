# encoding: UTF-8

control "C-4.2.2.1" do
  title "Ensure journald is configured to send logs to rsyslog"
  desc  "Data from journald may be stored in volatile memory or persisted
locally on the server. Utilities exist to accept remote export of journald
logs, however, use of the rsyslog service provides a consistent means of log
collection and export."
  desc  "rationale", "Storing log data on a remote host protects log integrity
from local attacks. If an attacker gains root access on the local system, they
could tamper with or remove log data that is stored on the local system."
  desc  "check", "
    Review `/etc/systemd/journald.conf` and verify that logs are forwarded to
syslog

    ```
    # grep -E -i \"^\\s*ForwardToSyslog\" /etc/systemd/journald.conf

    ForwardToSyslog=yes
    ```
  "
  desc "fix", "
    Edit the `/etc/systemd/journald.conf` file and add the following line:

    ```
    ForwardToSyslog=yes
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
  tag nist: ["SI-4 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.5", "Rev_7"]
  tag cis_rid: "4.2.2.1"
end
