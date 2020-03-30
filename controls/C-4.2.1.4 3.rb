# encoding: UTF-8

control "C-4.2.1.4" do
  title "Ensure rsyslog default file permissions configured"
  desc  "rsyslog will create logfiles that do not already exist on the system.
This setting controls what permissions will be applied to these newly created
files."
  desc  "rationale", "It is important to ensure that log files have the correct
permissions to ensure that sensitive data is archived and protected."
  desc  "check", "
    Run the following command and verify that `$FileCreateMode` is `0640` or
more restrictive:

    ```
    # grep ^\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    ```
  "
  desc "fix", "
    Edit the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files and set
`$FileCreateMode` to `0640` or more restrictive:

    ```
    $FileCreateMode 0640
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
  tag cis_rid: "4.2.1.4"
end
