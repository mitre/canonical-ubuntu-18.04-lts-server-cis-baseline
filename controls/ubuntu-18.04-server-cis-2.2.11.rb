# encoding: UTF-8

control "C-2.2.11" do
  title "Ensure email services are not enabled"
  desc  "`dovecot` is an open source mail submission and transport server for
Linux based systems."
  desc  "rationale", "Unless mail transport services are to be provided by this
system, it is recommended that the service be disabled or deleted to reduce the
potential attack surface."
  desc  "check", "
    Run one of the following commands to verify `dovecot` is not enabled:

    ```
    # systemctl is-enabled dovecot

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run one of the following commands to disable `dovecot` :

    ```
    # systemctl --now disable dovecot
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
  tag cis_rid: "2.2.11"
end
