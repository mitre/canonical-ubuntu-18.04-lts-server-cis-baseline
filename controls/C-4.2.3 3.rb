# encoding: UTF-8

control "C-4.2.3" do
  title "Ensure permissions on all logfiles are configured"
  desc  "Log files stored in /var/log/ contain logged information from many
services on the system, or on log hosts others as well."
  desc  "rationale", "It is important to ensure that log files have the correct
permissions to ensure that sensitive data is archived and protected."
  desc  "check", "
    Run the following command and verify that other has no permissions on any
files and group does not have write or execute permissions on any files:

    ```
    # find /var/log -type f -ls
    ```
  "
  desc  "fix", "
    Run the following commands to set permissions on all existing log files:

    ```
    find /var/log -type f -exec chmod g-wx,o-rwx \"{}\" + -o -type d -exec
chmod g-w,o-rwx \"{}\" +
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
  tag nist: ["SC-1", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["13", "Rev_7"]
  tag cis_rid: "4.2.3"
end
