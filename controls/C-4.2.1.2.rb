# encoding: UTF-8

control "C-4.2.1.2" do
  title "Ensure rsyslog Service is enabled"
  desc  "Once the `rsyslog` package is installed it needs to be activated."
  desc  "rationale", "If the `rsyslog` service is not activated the system may
default to the `syslogd` service or lack logging instead."
  desc  "check", "
    Run one of the following commands to verify `rsyslog` is enabled:

    ```
    # systemctl is-enabled rsyslog
    ```

    Verify result is `enabled`.
  "
  desc  "fix", "
    Run the following commands to enable `rsyslog`:

    ```
    # systemctl --now enable rsyslog
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
  tag cis_rid: "4.2.1.2"
end
