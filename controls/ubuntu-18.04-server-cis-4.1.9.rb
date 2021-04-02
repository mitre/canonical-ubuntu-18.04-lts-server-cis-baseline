# encoding: UTF-8

control "C-4.1.9" do
  title "Ensure discretionary access control permission modification events are
collected"
  desc  "Monitor changes to file permissions, attributes, ownership and group.
The parameters in this section track changes for system calls that affect file
permissions and attributes. The `chmod` , `fchmod` and `fchmodat` system calls
affect the permissions associated with a file. The `chown` , `fchown` ,
`fchownat` and `lchown` system calls affect owner and group attributes on a
file. The `setxattr` , `lsetxattr` , `fsetxattr` (set extended file attributes)
and `removexattr` , `lremovexattr` , `fremovexattr` (remove extended file
attributes) control extended file attributes. In all cases, an audit record
will only be written for non-system user ids (auid >= 1000) and will ignore
Daemon events (auid = 4294967295). All audit records will be tagged with the
identifier \"perm_mod.\"

    **Note:** Systems may have been customized to change the default UID_MIN.
To confirm the UID_MIN for your system, run the following command:

    ```
    awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs
    ```

    If your systems' UID_MIN is not `1000`, replace `audit>=1000` with
`audit>=` in the Audit and Remediation procedures.
  "
  desc  "rationale", "Monitoring for changes in file attributes could alert a
system administrator to activity that could indicate intruder activity or
policy violation."
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep perm_mod /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
    ```

    ```
    # auditctl -l | grep perm_mod
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F
auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F
auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S
setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F
auid>=1000 -F auid!=-1 -F key=perm_mod
    ```

    On a 64 bit system run the following commands:

    ```
    # grep perm_mod /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
    -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
    ```

    ```
    # auditctl -l | grep auditctl -l | grep perm_mod
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F
auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F
auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F
auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F
auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b64 -S
setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F
auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S
setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F
auid>=1000 -F auid!=-1 -F key=perm_mod
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/perm_mod.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/perm_mod.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
    -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["CM-6 (1)"]
  tag cis_level: 2
  tag cis_controls: ["5.5"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.9"

  arches = ['b32']
  if os.arch.match?(/64/)
    arches.push('b64')
  end

  syscalls = [
    'chmod',
    'fchmod',
    'fchmodat',
    'chown',
    'fchown',
    'fchownat',
    'lchown',
    'setxattr',
    'lsetxattr',
    'fsetxattr',
    'removexattr',
    'lremovexattr',
    'fremovexattr',
  ]

  syscalls.each do |syscall|
    arches.each do |a|
      describe auditd.syscall(syscall).where { arch == a && key == 'perm_mod'  } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
        its('fields.flatten.uniq') {  should include "auid>=#{login_defs.UID_MIN}" }
      end

      # the rule states that `auid!=4294967295` but this comes back as `auid!=-1` when queries via `auditctl -l`
      # this check will allow either.
      describe.one do
        describe auditd.syscall(syscall).where { arch == a && key == 'perm_mod'  } do
          its('fields.flatten.uniq') {  should include "auid!=-1" }
        end
        describe auditd.syscall(syscall).where { arch == a && key == 'perm_mod'  } do
          its('fields.flatten.uniq') {  should include "auid!=4294967295" }
        end
      end
    end
  end
end
