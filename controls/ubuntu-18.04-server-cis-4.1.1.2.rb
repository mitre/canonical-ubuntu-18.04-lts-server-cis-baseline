# encoding: UTF-8

control "C-4.1.1.2" do
  title "Ensure auditd service is enabled"
  desc  "Enable and start the `auditd` daemon to record system events."
  desc  "rationale", "The capturing of system events provides system
administrators with information to allow them to determine if unauthorized
access to their system is occurring."
  desc  "check", "
    Run the following command to verify `auditd` is enabled:

    ```
    # systemctl is-enabled auditd

    enabled
    ```

    Verify result is \"enabled\".
  "
  desc  "fix", "
    Run the following command to enable `auditd` :

    ```
    # systemctl --now enable auditd
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-12", "AU-3"]
  tag cis_level: 2
  tag cis_controls: ["6.2", "6.3"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.1.2"

  describe service('auditd') do
    it { should be_enabled }
  end
end
