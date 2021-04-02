# encoding: UTF-8

control "C-4.1.10" do
  title "Ensure unsuccessful unauthorized file access attempts are collected"
  desc  "Monitor for unsuccessful attempts to access files. The parameters
below are associated with system calls that control creation ( `creat` ),
opening ( `open` , `openat` ) and truncation ( `truncate` , `ftruncate` ) of
files. An audit log record will only be written if the user is a non-privileged
user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the system
call returned EACCES (permission denied to the file) or EPERM (some other
permanent error associated with the specific system call). All audit records
will be tagged with the identifier \"access.\"

    **Note:** Systems may have been customized to change the default UID_MIN.
To confirm the UID_MIN for your system, run the following command:

    ```
    # awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs
    ```

    If your systems' UID_MIN is not 1000, replace audit>=1000 with audit>= in
the Audit and Remediation procedures.
  "
  desc  "rationale", "Failed attempts to open, create or truncate files could
be an indication that an individual or process is trying to gain unauthorized
access to the system."
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep access /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    ```

    ```
    # auditctl -l | grep access
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F
exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F
exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access
    ```

    On a 64 bit system run the following commands:

    ```
    # grep access /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    ```

    ```
    # auditctl -l | grep access
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F
exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F
exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F
exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F
exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/audit.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/access.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-2"]
  tag cis_level: 2
  tag cis_controls: ["14.9"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.10"

  arches = ['b32']
  if os.arch.match?(/64/)
    arches.push('b64')
  end

  syscalls = [
    'creat',
    'open',
    'openat',
    'truncate',
    'ftruncate'
  ]

  syscalls.each do |syscall|
    arches.each do |a|
      describe auditd.syscall(syscall).where { arch == a && key == 'access'  } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
        its('fields.flatten.uniq') {  should include "auid>=#{login_defs.UID_MIN}" }
        its('exit') { should include '-EACCES' }
        its('exit') { should include '-EPERM' }
      end

      # the rule states that `auid!=4294967295` but this comes back as `auid!=-1` when queries via `auditctl -l`
      # this check will allow either.
      describe.one do
        describe auditd.syscall(syscall).where { arch == a && key == 'access'  } do
          its('fields.flatten.uniq') {  should include "auid!=-1" }
        end
        describe auditd.syscall(syscall).where { arch == a && key == 'access'  } do
          its('fields.flatten.uniq') {  should include "auid!=4294967295" }
        end
      end
    end
  end
end
