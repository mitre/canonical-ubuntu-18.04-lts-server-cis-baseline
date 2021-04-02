# encoding: UTF-8

control "C-4.1.16" do
  title "Ensure kernel module loading and unloading is collected"
  desc  "Monitor the loading and unloading of kernel modules. The programs
`insmod` (install a kernel module), `rmmod` (remove a kernel module), and
`modprobe` (a more sophisticated program to load and unload modules, as well as
some other features) control loading and unloading of modules. The
`init_module` (load a module) and `delete_module` (delete a module) system
calls control loading and unloading of modules. Any execution of the loading
and unloading module programs and system calls will trigger an audit record
with an identifier of \"modules\"."
  desc  "rationale", "Monitoring the use of `insmod` , `rmmod` and `modprobe`
could provide system administrators with evidence that an unauthorized user
loaded or unloaded a kernel module, possibly compromising the security of the
system. Monitoring of the `init_module` and `delete_module` system calls would
reflect an unauthorized user attempting to use a different program to load and
unload modules."
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep modules /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b32 -S init_module -S delete_module -k modules
    ```

    ```
    # auditctl -l | grep modules
    ```

    Verify output matches:

    ```
    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b32 -S init_module,delete_module -F key=modules
    ```

    On a 64 bit system run the following commands:

    ```
    # grep modules /etc/audit/rules.d/*.rules
    ```

    Verify output matches:

    ```
    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b64 -S init_module -S delete_module -k modules
    ```

    ```
    # auditctl -l | grep modules
    ```

    Verify output matches:

    ```
    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b64 -S init_module,delete_module -F key=modules
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/modules.rules`

    and add the following lines:
    ```
    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b32 -S init_module -S delete_module -k modules
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/modules.rules`

    and add the following lines:

    ```
    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b64 -S init_module -S delete_module -k modules
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["CM-6"]
  tag cis_level: 2
  tag cis_controls: ["5.1"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.16"

  files = [
    '/sbin/insmod',
    '/sbin/rmmod',
    '/sbin/modprobe'
  ]

  files.each do |file|
    describe auditd.file(file).where { key == "modules" } do
      its('permissions.uniq') { should include ['x'] }
    end
  end


  arches = ['b32']
  if os.arch.match?(/64/)
    arches.push('b64')
  end

  syscalls = [
    'init_module',
    'delete_module'
  ]

  syscalls.each do |syscall|
    arches.each do |a|
      describe auditd.syscall(syscall).where { arch == a && key == 'modules'  } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
  end
end
