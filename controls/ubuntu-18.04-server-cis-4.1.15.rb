# encoding: UTF-8

control "C-4.1.15" do
  title "Ensure system administrator actions (sudolog) are collected"
  desc  "Monitor the `sudo` log file. If the system has been properly
configured to disable the use of the `su` command and force all administrators
to have to log in first and then use `sudo` to execute privileged commands,
then all administrator commands will be logged to `/var/log/sudo.log` . Any
time a command is executed, an audit event will be triggered as the
`/var/log/sudo.log` file will be opened for write and the executed
administration command will be written to the log."
  desc  "rationale", "Changes in `/var/log/sudo.log` indicate that an
administrator has executed a command or the log file itself has been tampered
with. Administrators will want to correlate the events written to the audit
trail with the records written to `/var/log/sudo.log` to verify if unauthorized
commands have been executed."
  desc  "check", "
    Run the following commands:

    ```
    # grep -E \"^\\s*-w\\s+$(grep -r logfile /etc/sudoers* | sed -e
's/.*logfile=//;s/,? .*//')\\s+-p\\s+wa\\s+-k\\s+actions\"
/etc/audit/rules.d/*.rules

    # auditctl -l | grep actions
    ```

    Verify output of both matches the output of the following command, and the
the output includes a file path

    ```
    echo \"-w $(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?
.*//') -p wa -k actions\"
    ```

    **Example Output**

    ```
    -w /var/log/sudo.log -p wa -k actions
    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/audit/rules.d/` directory ending in
`.rules` and add the following line:

    ```
    -w

    \t -p wa -k actions
    ```

    Example: `vi /etc/audit/rules.d/actions.rules`

    and add the following line:

    ```
    -w /var/log/sudo.log -p wa -k actions
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-2"]
  tag cis_level: 2
  tag cis_controls: ["4.9"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.15"
  sudo_log_file = command("grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//;s/\"//g'").stdout
  describe "sudo log file" do
    subject{ sudo_log_file }
    it { should_not be_empty }
  end
  describe auditd.file(sudo_log_file.chomp).where { key == "actions" } do
    its('permissions') { should include ['w', 'a'] }
  end
end
