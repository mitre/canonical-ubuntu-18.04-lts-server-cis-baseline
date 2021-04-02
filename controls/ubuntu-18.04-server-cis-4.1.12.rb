# encoding: UTF-8

control "C-4.1.12" do
  title "Ensure successful file system mounts are collected"
  desc  "Monitor the use of the `mount` system call. The `mount` (and `umount`
) system call controls the mounting and unmounting of file systems. The
parameters below configure the system to create an audit record when the mount
system call is used by a non-privileged user

    **Note:** Systems may have been customized to change the default UID_MIN.
To confirm the UID_MIN for your system, run the following command:

    ```
    # awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs
    ```

    If your systems' UID_MIN is not 1000, replace audit>=1000 with audit>= in
the Audit and Remediation procedures.
  "
  desc  "rationale", "It is highly unusual for a non privileged user to `mount`
file systems to the system. While tracking `mount` commands gives the system
administrator evidence that external media may have been mounted (based on a
review of the source of the mount and confirming it's an external media type),
it does not conclusively indicate that data was exported to the media. System
administrators who wish to determine if data were exported, would also have to
track successful `open` , `creat` and `truncate` system calls requiring write
access to a file under the mount point of the external media file system. This
could give a fair indication that a write occurred. The only way to truly prove
it, would be to track successful writes to the external media. Tracking write
system calls could quickly fill up the audit log and is not recommended.
Recommendations on configuration options to track data export to media is
beyond the scope of this document."
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep mounts /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k
mounts
    ```

    ```
    # auditctl -l | grep mounts
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts
    ```

    On a 64 bit system run the following commands:

    ```
    # grep mounts /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k
mounts
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k
mounts
    ```

    ```
    # auditctl -l | grep mounts
    ```

    Verify output matches:

    ```
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/audit.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k
mounts
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/mounts.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k
mounts
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k
mounts
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["CM-6"]
  tag cis_level: 2
  tag cis_controls: ["5.1"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.12"


  arches = ['b32']
  if os.arch.match?(/64/)
    arches.push('b64')
  end

  syscall = 'mount'
  arches.each do |a|
    describe auditd.syscall(syscall).where { arch == a && key == 'mounts'  } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end

    # the rule states that `auid!=4294967295` but this comes back as `auid!=-1` when queries via `auditctl -l`
    # this check will allow either.
    describe.one do
      describe auditd.syscall(syscall).where { arch == a && key == 'mounts'  } do
        its('fields.flatten.uniq') {  should include "auid!=-1" }
      end
      describe auditd.syscall(syscall).where { arch == a && key == 'mounts'  } do
        its('fields.flatten.uniq') {  should include "auid!=4294967295" }
      end
    end
  end
end
