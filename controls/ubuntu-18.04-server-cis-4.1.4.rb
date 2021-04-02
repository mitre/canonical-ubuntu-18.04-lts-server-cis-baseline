# encoding: UTF-8

control "C-4.1.4" do
  title "Ensure events that modify user/group information are collected"
  desc  "Record events affecting the `group` , `passwd` (user IDs), `shadow`
and `gshadow` (passwords) or `/etc/security/opasswd` (old passwords, based on
remember parameter in the PAM configuration) files. The parameters in this
section will watch the files to see if they have been opened for write or have
had attribute changes (e.g. permissions) and tag them with the identifier
\"identity\" in the audit log file."
  desc  "rationale", "Unexpected changes to these files could be an indication
that the system has been compromised and that an unauthorized user is
attempting to hide their activities or compromise additional accounts."
  desc  "check", "
    Run the following commands:

    ```
    # grep identity /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/security/opasswd -p wa -k identity
    ```

    ```
    # auditctl -l | grep identity
    ```

    Verify the output matches:

    ```
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/security/opasswd -p wa -k identity
    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/audit/rules.d/` directory ending in
`.rules`

    Example: `vi /etc/audit/rules.d/identity.rules`

    and add the following lines:

    ```
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/security/opasswd -p wa -k identity
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AC-2 (4)"]
  tag cis_level: 2
  tag cis_controls: ["4.8"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.4"

  files = [
    '/etc/group',
    '/etc/passwd',
    '/etc/gshadow',
    '/etc/shadow',
    '/etc/security/opasswd'
  ]

  files.each do |file|
    describe auditd.file(file).where { key == "identity" } do
      its('permissions') { should include ['w', 'a'] }
    end
  end
end
