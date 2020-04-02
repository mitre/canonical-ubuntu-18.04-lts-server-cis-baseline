# encoding: UTF-8

control "C-4.2.2.3" do
  title "Ensure journald is configured to write logfiles to persistent disk"
  desc  "Data from journald may be stored in volatile memory or persisted
locally on the server. Logs in memory will be lost upon a system reboot. By
persisting logs to local disk on the server they are protected from loss."
  desc  "rationale", "Writing log data to disk will provide the ability to
forensically reconstruct events which may have impacted the operations or
security of a system even after a system crash or reboot."
  desc  "check", "
    Review `/etc/systemd/journald.conf` and verify that logs are persisted to
disk:

    ```
    # grep -E -i \"^\\s*Storage\" /etc/systemd/journald.conf
    # Storage=persistent
    ```
  "
  desc "fix", "
    Edit the `/etc/systemd/journald.conf` file and add the following line:

    ```
    Storage=persistent
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
  tag cis_rid: "4.2.2.3"
end
