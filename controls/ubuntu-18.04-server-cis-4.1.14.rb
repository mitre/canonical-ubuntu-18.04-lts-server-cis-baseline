# encoding: UTF-8

control "C-4.1.14" do
  title "Ensure changes to system administration scope (sudoers) is collected"
  desc  "Monitor scope changes for system administrations. If the system has
been properly configured to force system administrators to log in as themselves
first and then use the `sudo` command to execute privileged commands, it is
possible to monitor changes in scope. The file `/etc/sudoers` will be written
to when the file or its attributes have changed. The audit records will be
tagged with the identifier \"scope.\""
  desc  "rationale", "Changes in the `/etc/sudoers` file can indicate that an
unauthorized change has been made to scope of system administrator activity."
  desc  "check", "
    Run the following commands:

    ```
    # grep scope /etc/audit/rules.d/*.rules

    # auditctl -l | grep scope
    ```

    Verify output of both matches:

    ```
    -w /etc/sudoers -p wa -k scope
    -w /etc/sudoers.d/ -p wa -k scope
    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/audit/rules.d/` directory ending in
`.rules`

    Example: `vi /etc/audit/rules.d/scope.rules`

    and add the following lines:

    ```
    -w /etc/sudoers -p wa -k scope
    -w /etc/sudoers.d/ -p wa -k scope
    ```
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-2 (4)", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["4.8", "Rev_7"]
  tag cis_rid: "4.1.14"
  describe auditd do
    its('lines') { should include "-w /etc/sudoers -p wa -k scope" }
    its('lines') { should include "-w /etc/sudoers.d/ -p wa -k scope" }
  end
end
