# encoding: UTF-8

control "C-4.1.2.1" do
  title "Ensure audit log storage size is configured"
  desc  "Configure the maximum size of the audit log file. Once the log reaches
the maximum size, it will be rotated and a new log file will be started."
  desc  "rationale", "It is important that an appropriate size is determined
for log files so that they do not impact the system and audit data is not lost."
  desc  "check", "
    Run the following command and ensure output is in compliance with site
policy:

    ```
    # grep max_log_file /etc/audit/auditd.conf

    max_log_file =
    ```
  "
  desc  "fix", "
    Set the following parameter in `/etc/audit/auditd.conf` in accordance with
site policy:

    ```
    max_log_file =
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-4"]
  tag cis_level: 2
  tag cis_controls: ["6.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.2.1"
  describe auditd_conf do
    its('max_log_file') { should_not be_empty }
  end
end
