# encoding: UTF-8

control "C-4.1.8" do
  title "Ensure session initiation information is collected"
  desc  "Monitor session initiation events. The parameters in this section
track changes to the files associated with session events. The file
`/var/run/utmp` tracks all currently logged in users. All audit records will be
tagged with the identifier \"session.\" The `/var/log/wtmp` file tracks logins,
logouts, shutdown, and reboot events. The file `/var/log/btmp` keeps track of
failed login attempts and can be read by entering the command `/usr/bin/last -f
/var/log/btmp` . All audit records will be tagged with the identifier
\"logins.\""
  desc  "rationale", "Monitoring these files for changes could alert a system
administrator to logins occurring at unusual hours, which could indicate
intruder activity (i.e. a user logging in at a time when they do not normally
log in)."
  desc  "check", "
    Run the following commands:

    ```
    # grep -E '(session|logins)' /etc/audit/rules.d/*.rules
    ```

    Verify output includes:

    ```
    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k logins
    -w /var/log/btmp -p wa -k logins
    ```

    ```
    # auditctl -l | grep -E '(session|logins)'
    ```

    Verify output includes:

    ```
    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k logins
    -w /var/log/btmp -p wa -k logins
    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/audit/rules.d/` directory ending in
`.rules`

    Example: `vi /etc/audit/rules.d/session.rules`

    and add the following lines:

    ```
    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k logins
    -w /var/log/btmp -p wa -k logins
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-2", "AC-11", "AC-2(12)"]
  tag cis_level: 2
  tag cis_controls: ["4.9", "16.11", "16.13"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.8"

  files = [
    '/var/log/wtmp',
    '/var/log/btmp'
  ]

  files.each do |file|
    describe auditd.file(file).where { key == "logins" } do
      its('permissions') { should include ['w', 'a'] }
    end
  end


  describe auditd.file('/var/run/utmp').where { key == "session" } do
    its('permissions') { should include ['w', 'a'] }
  end
end
