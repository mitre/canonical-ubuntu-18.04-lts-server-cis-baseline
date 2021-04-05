# encoding: UTF-8

control "C-4.1.17" do
  title "Ensure the audit configuration is immutable"
  desc  "Set system audit so that audit rules cannot be modified with
`auditctl` . Setting the flag \"-e 2\" forces audit to be put in immutable
mode. Audit changes can only be made on system reboot."
  desc  "rationale", "In immutable mode, unauthorized users cannot execute
changes to the audit system to potentially hide malicious activity and then put
the audit rules back. Users would most likely notice a system reboot and that
could alert administrators of an attempt to make unauthorized audit changes."
  desc  "check", "
    Run the following command and verify output matches:

    ```
    # grep \"^\\s*[^#]\" /etc/audit/audit.rules | tail -1

    -e 2
    ```
  "
  desc "fix", "
    Edit or create the file `/etc/audit/rules.d/99-finalize.rules` and add the
line

    ```
    -e 2
    ```

    at the end of the file
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-12", "AU-3"]
  tag cis_level: 2
  tag cis_controls: ["6.2", "6.3"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.17"

  last_line = command("grep \"^\\s*[^#]\" /etc/audit/audit.rules | tail -1")
  describe last_line do
    its('stdout.strip') { should cmp "-e 2" }
  end
end
