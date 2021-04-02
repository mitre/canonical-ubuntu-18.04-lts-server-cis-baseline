# encoding: UTF-8

control "C-4.1.11" do
  title "Ensure use of privileged commands is collected"
  desc  "Monitor privileged programs (those that have the setuid and/or setgid
bit set on execution) to determine if unprivileged users are running these
commands.

    **Note:** Systems may have been customized to change the default UID_MIN.
To confirm the UID_MIN for your system, run the following command:

    ```
    # awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs
    ```

    If your systems' UID_MIN is not 1000, replace audit>=1000 with audit>= in
the Audit and Remediation procedures.
  "
  desc  "rationale", "Execution of privileged commands by non-privileged users
could be an indication of someone trying to gain unauthorized access to the
system."
  desc  "check", "
    Run the following command replacing `

    \t` with a list of partitions where programs can be executed from on your
system:

    ```
    # find

    \t -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | awk '{print \\
    \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=1000 -F
auid!=4294967295 \\
    -k privileged\" }'
    ```

    Verify all resulting lines are a `.rules` file in `/etc/audit/rules.d/` and
the output of `auditctl -l`.

    NOTE: The `.rules` file output will be `auid!=-1` not `auid!=4294967295`
  "
  desc "fix", "
    To remediate this issue, the system administrator will have to execute a
find command to locate all the privileged programs and then add an audit line
for each one of them. The audit parameters associated with this are as follows:
     `-F path=\" $1 \"` - will populate each file name found through the find
command and processed by awk. `-F perm=x` - will write an audit record if the
file is executed. `-F auid>=1000` - will write a record if the user executing
the command is not a privileged user. `-F auid!= 4294967295` - will ignore
Daemon events

    All audit records should be tagged with the identifier \"privileged\".

    Run the following command replacing _

    \t_ with a list of partitions where programs can be executed from on your
system:

    ```
    # find

    \t -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | awk '{print \\
    \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=1000 -F
auid!=4294967295 \\
    -k privileged\" }'
    ```

    Edit or create a file in the `/etc/audit/rules.d/` directory ending in
`.rules`

    Example: `vi /etc/audit/rules.d/privileged.rules`

    And add all resulting lines to the file.
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["CM-6"]
  tag cis_level: 2
  tag cis_controls: ["5.1"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.11"
  command("mount |grep -v noexec|cut -d' ' -f3").stdout.lines.each do |line|
    command("find #{line.chomp} -xdev \\( -perm -4000 -o -perm -2000 \\) -type f").stdout.lines.each do |executable|
      describe auditd.where { key == 'privileged' && path == executable} do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
        its('permissions') { should include ['x'] }
      end

      # the rule states that `auid!=4294967295` but this comes back as `auid!=-1` when queries via `auditctl -l`
      # this check will allow either.
      describe.one do
        describe auditd.where { key == 'privileged' && path == executable} do
          its('fields.flatten.uniq') {  should include "auid!=-1" }
        end
        describe auditd.where { key == 'privileged' && path == executable} do
          its('fields.flatten.uniq') {  should include "auid!=4294967295" }
        end
      end
    end
  end
end
