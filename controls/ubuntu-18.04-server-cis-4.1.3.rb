# encoding: UTF-8

control "C-4.1.3" do
  title "Ensure events that modify date and time information are collected"
  desc  "Capture events where the system date and/or time has been modified.
The parameters in this section are set to determine if the `adjtimex` (tune
kernel clock), `settimeofday` (Set time, using timeval and timezone structures)
`stime` (using seconds since 1/1/1970) or `clock_settime` (allows for the
setting of several internal clocks and timers) system calls have been executed
and always write an audit record to the `/var/log/audit.log` file upon exit,
tagging the records with the identifier \"time-change\""
  desc  "rationale", "Unexpected changes in system date and/or time could be a
sign of malicious activity on the system."
  desc  "check", "
    On a 32 bit system run the following commands:

    ```
    # grep time-change /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k
time-change
    -a always,exit -F arch=b32 -S clock_settime -k time-change
    -w /etc/localtime -p wa -k time-change
    ```

    ```
    # auditctl -l | grep time-change
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change
    -a always,exit -F arch=b32 -S clock_settime -F key=time-change
    -w /etc/localtime -p wa -k time-change
    ```

    On a 64 bit system run the following commands:

    ```
    # grep time-change /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
    -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k
time-change
    -a always,exit -F arch=b64 -S clock_settime -k time-change
    -a always,exit -F arch=b32 -S clock_settime -k time-change
    -w /etc/localtime -p wa -k time-change
    ```

    ```
    # auditctl -l | grep time-change
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
    -a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change
    -a always,exit -F arch=b64 -S clock_settime -F key=time-change
    -a always,exit -F arch=b32 -S clock_settime -F key=time-change
    -w /etc/localtime -p wa -k time-change
    ```
  "
  desc  "fix", "
    For 32 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/time-change.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k
time-change
    -a always,exit -F arch=b32 -S clock_settime -k time-change
    -w /etc/localtime -p wa -k time-change
    ```

    For 64 bit systems Edit or create a file in the `/etc/audit/rules.d/`
directory ending in `.rules`

    Example: `vi /etc/audit/rules.d/time-change.rules`

    and add the following lines:

    ```
    -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
    -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k
time-change
    -a always,exit -F arch=b64 -S clock_settime -k time-change
    -a always,exit -F arch=b32 -S clock_settime -k time-change
    -w /etc/localtime -p wa -k time-change
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["CM-6 (1)"]
  tag cis_level: 2
  tag cis_controls: ["5.5"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.3"


  ['adjtimex', 'settimeofday', 'stime', 'clock_settime'].each do |syscall|
    describe auditd.syscall(syscall).where { arch == 'b32' && key == 'time-change'  } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  
  describe auditd.file('/etc/localtime').where { key == "time-change" } do
    its('permissions') { should include ['w', 'a'] }
  end

  if os.arch.match?(/64/)
    ['adjtimex', 'settimeofday', 'clock_settime'].each do |syscall|
      describe auditd.syscall(syscall).where { arch == 'b64' && key == 'time-change'  } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
  end
  
end
