# encoding: UTF-8

control "C-4.1.2.3" do
  title "Ensure system is disabled when audit logs are full"
  desc  "The `auditd` daemon can be configured to halt the system when the
audit logs are full."
  desc  "rationale", "In high security contexts, the risk of detecting
unauthorized access or nonrepudiation exceeds the benefit of the system's
availability."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # grep space_left_action /etc/audit/auditd.conf

    space_left_action = email
    ```

    ```
    # grep action_mail_acct /etc/audit/auditd.conf

    action_mail_acct = root
    ```

    ```
    # grep admin_space_left_action /etc/audit/auditd.conf

    admin_space_left_action = halt
    ```
  "
  desc  "fix", "
    Set the following parameters in `/etc/audit/auditd.conf:`

    ```
    space_left_action = email
    action_mail_acct = root
    admin_space_left_action = halt
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-4"]
  tag cis_level: 2
  tag cis_controls: ["6.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.2.3"

  describe auditd_conf do
    its('space_left_action') { should cmp 'email' }
    its('action_mail_acct') { should cmp 'root' }
    its('admin_space_left_action') { should cmp 'halt' }
  end
end
