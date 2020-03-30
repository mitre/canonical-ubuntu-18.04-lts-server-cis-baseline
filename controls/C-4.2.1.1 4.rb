# encoding: UTF-8

control "C-4.2.1.1" do
  title "Ensure rsyslog is installed"
  desc  "The `rsyslog` software is a recommended replacement to the original
`syslogd` daemon which provide improvements over `syslogd`, such as
connection-oriented (i.e. TCP) transmission of logs, the option to log to
database formats, and the encryption of log data en route to a central logging
server."
  desc  "rationale", "The security enhancements of `rsyslog` such as
connection-oriented (i.e. TCP) transmission of logs, the option to log to
database formats, and the encryption of log data en route to a central logging
server) justify installing and configuring the package."
  desc  "check", "
    Verify either rsyslog or syslog-ng is installed. Use the following command
to provide the needed information:

    ```
    # dpkg -s rsyslog
    ```
  "
  desc "fix", "
    Install rsyslog:

    ```
    # apt install rsyslog
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
  tag cis_rid: "4.2.1.1"
end
