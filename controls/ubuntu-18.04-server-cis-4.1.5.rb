# encoding: UTF-8

control "C-4.1.5" do
  title "Ensure events that modify the system's network environment are
collected"
  desc  "Record changes to network environment files or system calls. The below
parameters monitor the sethostname (set the systems host name) or setdomainname
(set the systems domainname) system calls, and write an audit event on system
call exit. The other parameters monitor the `/etc/issue` and `/etc/issue.net`
files (messages displayed pre-login), `/etc/hosts` (file containing host names
and associated IP addresses) and `/etc/network` (directory containing network
interface scripts and configurations) files."
  desc  "rationale", "Monitoring `sethostname` and `setdomainname` will
identify potential unauthorized changes to host and domainname of a system. The
changing of these names could potentially break security parameters that are
set based on those names. The `/etc/hosts` file is monitored for changes in the
file that can indicate an unauthorized intruder is trying to change machine
associations with IP addresses and trick users and processes into connecting to
unintended machines. Monitoring `/etc/issue` and `/etc/issue.net` is important,
as intruders could put disinformation into those files and trick users into
providing information to the intruder. Monitoring `/etc/network` is important
as it can show if network interfaces or scripts are being modified in a way
that can lead to the machine becoming unavailable or compromised. All audit
records will be tagged with the identifier \"system-locale.\""
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep system-locale /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/network -p wa -k system-locale
    ```

    ```
    # auditctl -l | grep system-locale
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/network -p wa -k system-locale
    ```

    On a 64 bit system run the following commands:

    ```
    # grep system-locale /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/network -p wa -k system-locale
    ```

    ```
    # auditctl -l | grep system-locale
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale
    -a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/network -p wa -k system-locale
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/system-locale.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/network -p wa -k system-locale
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/system-locale.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/network -p wa -k system-locale
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["CM-6 (1)"]
  tag cis_level: 2
  tag cis_controls: ["5.5"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.5"

  files = [
    '/etc/issue',
    '/etc/issue.net',
    '/etc/hosts',
    '/etc/network'
  ]

  files.each do |file|
    describe auditd.file(file).where { key == "system-locale" } do
      its('permissions') { should include ['w', 'a'] }
    end
  end

  arches = ['b32']
  if os.arch.match?(/64/)
    arches.push('b64')
  end

  ['sethostname', 'setdomainname'].each do |syscall|
    arches.each do |a|
      describe auditd.syscall(syscall).where { arch == a && key == 'system-locale'  } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
  end
end
