# encoding: UTF-8

control "C-4.1.13" do
  title "Ensure file deletion events by users are collected"
  desc  "Monitor the use of system calls associated with the deletion or
renaming of files and file attributes. This configuration statement sets up
monitoring for the `unlink` (remove a file), `unlinkat` (remove a file
attribute), `rename` (rename a file) and `renameat` (rename a file attribute)
system calls and tags them with the identifier \"delete\".

    **Note:** Systems may have been customized to change the default UID_MIN.
To confirm the UID_MIN for your system, run the following command:

    ```
    # awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs
    ```

    If your systems' UID_MIN is not 1000, replace audit>=1000 with audit>= in
the Audit and Remediation procedures.
  "
  desc  "rationale", "Monitoring these calls from non-privileged users could
provide a system administrator with evidence that inappropriate removal of
files and file attributes associated with protected files is occurring. While
this audit option will look at all events, system administrators will want to
look for specific privileged files that are being deleted or altered."
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep delete /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
    ```

    ```
    # auditctl -l | grep delete
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000
-F auid!=-1 -F key=delete
    ```

    On a 64 bit system run the following commands:

    ```
    # grep delete /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
    -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
    ```

    ```
    # auditctl -l | grep delete
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=5100
-F auid!=-1 -F key=delete
    -a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000
-F auid!=-1 -F key=delete
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/audit.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/delete.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
    -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["SC-1"]
  tag cis_level: 2
  tag cis_controls: ["13"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.13"


  arches = ['b32']
  if os.arch.match?(/64/)
    arches.push('b64')
  end

  syscalls = [
    'unlink',
    'unlinkat',
    'rename',
    'renameat'
  ]

  syscalls.each do |syscall|
    arches.each do |a|
      describe auditd.syscall(syscall).where { arch == a && key == 'delete'  } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
        its('fields.flatten.uniq') {  should include "auid>=#{login_defs.UID_MIN}" }
      end

      # the rule states that `auid!=4294967295` but this comes back as `auid!=-1` when queries via `auditctl -l`
      # this check will allow either.
      describe.one do
        describe auditd.syscall(syscall).where { arch == a && key == 'delete'  } do
          its('fields.flatten.uniq') {  should include "auid!=-1" }
        end
        describe auditd.syscall(syscall).where { arch == a && key == 'delete'  } do
          its('fields.flatten.uniq') {  should include "auid!=4294967295" }
        end
      end
    end
  end
end
