# encoding: UTF-8

control "C-5.1.1" do
  title "Ensure cron daemon is enabled"
  desc  "The `cron` daemon is used to execute batch jobs on the system."
  desc  "rationale", "While there may not be user jobs that need to be run on
the system, the system does have maintenance jobs that may include security
monitoring that have to run, and `cron` is used to execute them."
  desc  "check", "
    Based on your system configuration, run the appropriate one of the
following commands to verify `cron` is enabled:

    ```
    # systemctl is-enabled cron

    enabled
    ```

    Verify result is \"enabled\".
  "
  desc "fix", "
    Based on your system configuration, run the appropriate one of the
following commands to enable `cron`:

    ```
    # systemctl --now enable cron
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
  tag nist: ["AU-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6", "Rev_7"]
  tag cis_rid: "5.1.1"
end
